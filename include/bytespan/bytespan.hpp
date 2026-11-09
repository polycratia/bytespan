// bytespan — reading and writing binary formats without reaching past the end.
//
// Nearly every memory-safety CVE in a C++ protocol parser is the same mistake
// written a different way: a length field is trusted, a memcpy runs past the
// buffer, and the bug is a remote crash at best. The fix is not cleverness, it
// is refusing to do the unchecked thing at all.
//
// The design decision that makes this usable rather than merely safe: a failed
// read poisons the cursor. Parsing a header is a run of reads, and checking
// every one of them is what people skip. Here they can read the whole header
// and check once, because after the first failure nothing else succeeds. The
// cursor keeps the first refusal — offset, reason, and the two sizes that
// disagreed — so the single check still knows which field went wrong.
//
// Header-only, no allocation, no exceptions, C++20.
#ifndef BYTESPAN_BYTESPAN_HPP
#define BYTESPAN_BYTESPAN_HPP

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <type_traits>

namespace bytespan {

enum class endian { little, big };

/// Why a cursor refused.
enum class reason {
    short_input,     ///< reader: the field needed more bytes than were left
    no_room,         ///< writer: the call needed more room than was left
    trailing_bytes,  ///< reader: expect_end found bytes after the last field
    too_long,        ///< writer: a payload too large to count in its prefix
    overflow,        ///< reader: a varint whose value does not fit the type
    non_canonical,   ///< reader: a varint padded past its shortest encoding
    bad_slot,        ///< writer: a length slot closed out of order, closed
                     ///< twice, or opened on another buffer
};

/// A refusal as it happened: which field, why, and the two sizes that
/// disagreed. Offset is the first byte of the refused field, so it names that
/// field rather than a position inside it.
struct refusal {
    std::size_t offset;
    reason why;
    std::size_t wanted;
    std::size_t available;
};

namespace detail {

/// std::byteswap is C++23. Reversing the bytes by hand keeps this header at
/// C++20, which is where most projects that need it actually are; every
/// compiler recognises the pattern and emits the single instruction.
template <typename T>
[[nodiscard]] constexpr T swap_bytes(T value) noexcept {
    static_assert(std::is_unsigned_v<T>, "byte order applies to unsigned integers");
    T out = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out = static_cast<T>(out << 8) | static_cast<T>((value >> (8 * i)) & 0xFFu);
    }
    return out;
}

/// A declared length can be the largest size_t there is, and a refusal reports
/// the prefix width added to it; saturating keeps the number in the record
/// from wrapping round into a small, misleading one.
[[nodiscard]] constexpr std::size_t saturating_add(std::size_t a, std::size_t b) noexcept {
    const std::size_t limit = std::numeric_limits<std::size_t>::max();
    return a > limit - b ? limit : a + b;
}

/// Seven bits to a byte: ten groups is the most a 64-bit value can need.
inline constexpr std::size_t varint_u64_max_bytes = 10;

}  // namespace detail

/// A cursor over bytes that cannot be moved past its end. Every read is a
/// constant expression, so a parse of a constexpr input is evaluated by the
/// compiler, where reaching past the end is an error rather than behaviour.
class reader {
  public:
    constexpr explicit reader(std::span<const std::byte> data) noexcept : data_(data) {}

    /// True while every read so far has succeeded.
    [[nodiscard]] constexpr bool ok() const noexcept { return !refused_; }

    /// The refusal that poisoned the cursor, nullopt while ok(). It is the
    /// first one: later calls fail as a consequence of it, and recording those
    /// consequences would bury the failure that explains the parse.
    [[nodiscard]] constexpr std::optional<refusal> refused() const noexcept {
        if (!refused_) return std::nullopt;
        return record_;
    }

    /// Bytes not yet consumed. Zero once the cursor is poisoned, so that a
    /// caller looping on remaining() cannot spin.
    [[nodiscard]] constexpr std::size_t remaining() const noexcept {
        return ok() ? data_.size() - offset_ : 0;
    }

    [[nodiscard]] constexpr std::size_t offset() const noexcept { return offset_; }

    /// Consume n bytes. Fails, and poisons the cursor, if fewer remain.
    [[nodiscard]] constexpr std::optional<std::span<const std::byte>> bytes(
        std::size_t n) noexcept {
        if (!take(n)) return std::nullopt;
        return data_.subspan(offset_ - n, n);
    }

    /// Skip n bytes without looking at them.
    constexpr bool skip(std::size_t n) noexcept { return take(n); }

    /// True only when the parse consumed exactly the input: trailing bytes
    /// poison the cursor, and a cursor that already failed stays refused even
    /// though remaining() reports zero, so a poisoned parse cannot read as
    /// complete. Like skip(), it belongs in the run of reads checked by ok().
    constexpr bool expect_end() noexcept {
        if (!ok()) return false;
        if (offset_ != data_.size()) {
            poison({offset_, reason::trailing_bytes, 0, data_.size() - offset_});
            return false;
        }
        return true;
    }

    [[nodiscard]] constexpr std::optional<std::uint8_t> u8() noexcept {
        return read<std::uint8_t>(endian::big);
    }

    [[nodiscard]] constexpr std::optional<std::uint16_t> u16(endian order) noexcept {
        return read<std::uint16_t>(order);
    }

    [[nodiscard]] constexpr std::optional<std::uint32_t> u32(endian order) noexcept {
        return read<std::uint32_t>(order);
    }

    [[nodiscard]] constexpr std::optional<std::uint64_t> u64(endian order) noexcept {
        return read<std::uint64_t>(order);
    }

    /// Unsigned LEB128: seven bits to a byte, low group first, and only the
    /// canonical encoding. A value that can be spelled two ways is a value two
    /// parsers can disagree about, so a padded varint is refused rather than
    /// quietly accepted and there is no lenient mode. Each byte is judged as
    /// it is read, and a refusal names the varint's first byte.
    [[nodiscard]] constexpr std::optional<std::uint64_t> varint_u64() noexcept {
        if (!ok()) return std::nullopt;
        const std::size_t start = offset_;
        std::uint64_t value = 0;
        for (std::size_t index = 0;; ++index) {
            if (offset_ == data_.size()) {
                return refuse_varint(start, reason::short_input, index + 1,
                                     data_.size() - start);
            }
            const auto group = std::to_integer<std::uint8_t>(data_[offset_]);
            ++offset_;
            // Nine groups carry 63 bits, so a tenth may carry one more; above
            // 0x01 it sets bits past the top of the type. An eleventh byte
            // needs a tenth that continued, which is already above 0x01, so
            // this single test covers that too.
            if (index == detail::varint_u64_max_bytes - 1 && group > 0x01) {
                return refuse_varint(start, reason::overflow, 0, offset_ - start);
            }
            // A zero group cannot continue, so it ends the varint; anywhere
            // but first it is padding, and the value had a shorter spelling.
            if (index > 0 && group == 0x00) {
                return refuse_varint(start, reason::non_canonical, 0, offset_ - start);
            }
            value |= static_cast<std::uint64_t>(group & 0x7Fu) << (7 * index);
            if ((group & 0x80u) == 0) return value;
        }
    }

    /// Read a length prefix and then that many bytes — the shape that goes
    /// wrong most often, so it is one call rather than two.
    [[nodiscard]] constexpr std::optional<std::span<const std::byte>> length_prefixed_u16(
        endian order) noexcept {
        return length_prefixed<std::uint16_t>(order);
    }

    [[nodiscard]] constexpr std::optional<std::span<const std::byte>> length_prefixed_u32(
        endian order) noexcept {
        return length_prefixed<std::uint32_t>(order);
    }

  private:
    constexpr void poison(refusal record) noexcept {
        if (!refused_) {
            record_ = record;
            refused_ = true;
        }
    }

    /// A varint is one field however many bytes it spans, so a refusal leaves
    /// the cursor at its first byte the way every other refusal does.
    constexpr std::nullopt_t refuse_varint(std::size_t start, reason why, std::size_t wanted,
                                           std::size_t available) noexcept {
        poison({start, why, wanted, available});
        offset_ = start;
        return std::nullopt;
    }

    constexpr bool take(std::size_t n) noexcept {
        if (!ok()) return false;
        if (n > data_.size() - offset_) {
            poison({offset_, reason::short_input, n, data_.size() - offset_});
            return false;
        }
        offset_ += n;
        return true;
    }

    /// The value is assembled from the bytes in the order that was asked for.
    /// That is both why it works during constant evaluation, where a memcpy
    /// through an object representation does not, and why the reader never
    /// consults the host's byte order at all.
    template <typename T>
    [[nodiscard]] constexpr std::optional<T> read(endian order) noexcept {
        if (!take(sizeof(T))) return std::nullopt;
        const std::size_t start = offset_ - sizeof(T);
        T value{};
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            const std::size_t shift = 8 * (order == endian::big ? sizeof(T) - 1 - i : i);
            const auto group = static_cast<T>(std::to_integer<std::uint8_t>(data_[start + i]));
            value = static_cast<T>(value | static_cast<T>(group << shift));
        }
        return value;
    }

    template <typename T>
    [[nodiscard]] constexpr std::optional<std::span<const std::byte>> length_prefixed(
        endian order) noexcept {
        if (!ok()) return std::nullopt;
        const std::size_t start = offset_;
        const auto length = read<T>(order);
        if (!length) return std::nullopt;  // the record already names the prefix
        // A 32-bit length on a 32-bit size_t could wrap; the comparison is
        // against the real remaining size, so the wrap cannot turn into a read.
        const std::size_t wanted = static_cast<std::size_t>(*length);
        if (wanted > data_.size() - offset_) {
            // The prefix and the payload are one field, so a refusal names that
            // field: the offset of the prefix, and the width of the count
            // folded into what the field as a whole wanted.
            poison({start, reason::short_input, detail::saturating_add(sizeof(T), wanted),
                    data_.size() - start});
            offset_ = start;
            return std::nullopt;
        }
        offset_ += wanted;
        return data_.subspan(offset_ - wanted, wanted);
    }

    std::span<const std::byte> data_;
    std::size_t offset_ = 0;
    // Not a std::optional: assigning to one during constant evaluation only
    // became valid in a defect report against C++20, and the reader should not
    // need a compiler new enough to carry that fix.
    bool refused_ = false;
    refusal record_{};
};

/// A length field reserved by writer::open_u16 or writer::open_u32 and spent
/// by writer::close: the field's offset, its width, the buffer it was reserved
/// in, and the offset of the slot that was innermost when it opened. A plain
/// value, so nesting is a chain of locals rather than a stack the writer owns.
struct length_slot {
    std::size_t offset;
    std::size_t width;
    const std::byte* data;
    std::optional<std::size_t> parent;
};

/// A cursor that writes, with the same discipline: an overrun fails the writer
/// instead of the process.
class writer {
  public:
    constexpr explicit writer(std::span<std::byte> out) noexcept : out_(out) {}

    [[nodiscard]] constexpr bool ok() const noexcept { return !refusal_.has_value(); }

    /// The refusal that poisoned the writer, nullopt while ok(), and the first
    /// one for the same reason as the reader's.
    [[nodiscard]] std::optional<refusal> refused() const noexcept { return refusal_; }

    [[nodiscard]] constexpr std::size_t written() const noexcept { return offset_; }
    [[nodiscard]] constexpr std::size_t remaining() const noexcept {
        return ok() ? out_.size() - offset_ : 0;
    }

    /// What has been written so far, for handing to a socket. Open slots are
    /// not checked: a length field whose close never came is still the zeros
    /// open reserved it with, because the writer cannot tell a caller who is
    /// finished from one who is not.
    [[nodiscard]] constexpr std::span<const std::byte> view() const noexcept {
        return out_.subspan(0, offset_);
    }

    /// memmove, not memcpy: nothing stops a caller passing a span of this
    /// writer's own buffer — of view(), say — and overlapping memcpy is
    /// undefined rather than merely surprising.
    bool bytes(std::span<const std::byte> source) noexcept {
        if (!take(source.size())) return false;
        std::memmove(out_.data() + offset_ - source.size(), source.data(), source.size());
        return true;
    }

    bool u8(std::uint8_t value) noexcept { return put(value, endian::big); }
    bool u16(std::uint16_t value, endian order) noexcept { return put(value, order); }
    bool u32(std::uint32_t value, endian order) noexcept { return put(value, order); }
    bool u64(std::uint64_t value, endian order) noexcept { return put(value, order); }

    /// The minimal encoding the reader accepts, all or nothing: the groups are
    /// built first and written in one call, so a refusal leaves written() where
    /// it stood rather than half a varint for someone to read back.
    bool varint_u64(std::uint64_t value) noexcept {
        std::array<std::byte, detail::varint_u64_max_bytes> groups{};
        std::size_t size = 0;
        do {
            auto group = static_cast<std::uint8_t>(value & 0x7Fu);
            value >>= 7;
            if (value != 0) group = static_cast<std::uint8_t>(group | 0x80u);
            groups[size++] = static_cast<std::byte>(group);
        } while (value != 0);
        return bytes(std::span<const std::byte>(groups).first(size));
    }

    /// Write the payload's size as a prefix and then the payload, mirroring
    /// the reader: one call, because a count written apart from its body is
    /// how the two drift. A payload too large for the prefix poisons the
    /// writer rather than truncating the count.
    bool length_prefixed_u16(std::span<const std::byte> payload, endian order) noexcept {
        return length_prefixed<std::uint16_t>(payload, order);
    }

    bool length_prefixed_u32(std::span<const std::byte> payload, endian order) noexcept {
        return length_prefixed<std::uint32_t>(payload, order);
    }

    /// Reserve a zeroed length field for a body whose size is not known yet —
    /// the shape every nested format has, a block whose count covers a block
    /// that carries its own. Nullopt with the writer poisoned as no_room when
    /// the field does not fit, and nullopt on a writer that already failed.
    [[nodiscard]] std::optional<length_slot> open_u16() noexcept {
        return open<std::uint16_t>();
    }

    [[nodiscard]] std::optional<length_slot> open_u32() noexcept {
        return open<std::uint32_t>();
    }

    /// Write the bytes written since the field as the body's length, and make
    /// the slot's parent the innermost open slot again. Refusals poison the
    /// writer: a body longer than the field can count is too_long and leaves
    /// the field's zeros alone, while a slot that is not the innermost open one
    /// — closed out of order, or closed twice — or that was opened on another
    /// buffer is bad_slot. A bad_slot refusal is recorded at the offset the
    /// writer had reached, since such a slot's own offset may name a position
    /// in someone else's buffer.
    bool close(const length_slot& slot, endian order) noexcept {
        if (!ok()) return false;
        // The innermost offset is enough to identify the slot: offsets only
        // grow, so no two slots of one writer can ever share one.
        if (slot.data != out_.data() || innermost_ != slot.offset) {
            poison({offset_, reason::bad_slot, 0, 0});
            return false;
        }
        const bool narrow = slot.width == sizeof(std::uint16_t);
        const std::size_t body = offset_ - (slot.offset + slot.width);
        const std::size_t limit =
            narrow ? static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())
                   : static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max());
        if (body > limit) {
            poison({slot.offset, reason::too_long, body, limit});
            return false;
        }
        if (narrow) {
            store(slot.offset, static_cast<std::uint16_t>(body), order);
        } else {
            store(slot.offset, static_cast<std::uint32_t>(body), order);
        }
        innermost_ = slot.parent;
        return true;
    }

  private:
    void poison(refusal record) noexcept {
        if (!refusal_) refusal_ = record;
    }

    bool take(std::size_t n) noexcept {
        if (!ok()) return false;
        if (n > out_.size() - offset_) {
            poison({offset_, reason::no_room, n, out_.size() - offset_});
            return false;
        }
        offset_ += n;
        return true;
    }

    template <typename T>
    void store(std::size_t at, T value, endian order) noexcept {
        if constexpr (sizeof(T) > 1) {
            const bool host_is_little = std::endian::native == std::endian::little;
            const bool want_little = order == endian::little;
            if (host_is_little != want_little) value = detail::swap_bytes(value);
        }
        std::memcpy(out_.data() + at, &value, sizeof(T));
    }

    template <typename T>
    bool put(T value, endian order) noexcept {
        if (!take(sizeof(T))) return false;
        store(offset_ - sizeof(T), value, order);
        return true;
    }

    template <typename T>
    std::optional<length_slot> open() noexcept {
        const std::size_t at = offset_;
        if (!take(sizeof(T))) return std::nullopt;
        // The caller's buffer need not have arrived zeroed, and an unclosed
        // field has to read as zero rather than as whatever was there.
        for (std::size_t i = 0; i < sizeof(T); ++i) out_[at + i] = std::byte{0};
        const length_slot slot{at, sizeof(T), out_.data(), innermost_};
        innermost_ = at;
        return slot;
    }

    template <typename T>
    bool length_prefixed(std::span<const std::byte> payload, endian order) noexcept {
        if (!ok()) return false;
        const std::size_t size = payload.size();
        if constexpr (sizeof(std::size_t) > sizeof(T)) {
            if (size > static_cast<std::size_t>(std::numeric_limits<T>::max())) {
                poison({offset_, reason::too_long, size,
                        static_cast<std::size_t>(std::numeric_limits<T>::max())});
                return false;
            }
        }
        // Prefix and body are reserved in one check, so a refusal cannot leave
        // a lone count behind. Subtracting from the room left, rather than
        // adding the two, keeps the sum from wrapping on a 32-bit size_t.
        const std::size_t room = out_.size() - offset_;
        if (size > room || sizeof(T) > room - size) {
            poison({offset_, reason::no_room, detail::saturating_add(sizeof(T), size), room});
            return false;
        }
        put(static_cast<T>(size), order);
        return bytes(payload);
    }

    std::span<std::byte> out_;
    std::size_t offset_ = 0;
    std::optional<refusal> refusal_;
    // Only the innermost open slot, because each slot carries its own parent:
    // nesting needs no allocation and has no fixed depth.
    std::optional<std::size_t> innermost_;
};

}  // namespace bytespan

#endif  // BYTESPAN_BYTESPAN_HPP
