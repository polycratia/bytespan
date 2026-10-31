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

}  // namespace detail

/// A cursor over bytes that cannot be moved past its end.
class reader {
  public:
    constexpr explicit reader(std::span<const std::byte> data) noexcept : data_(data) {}

    /// True while every read so far has succeeded.
    [[nodiscard]] constexpr bool ok() const noexcept { return !refusal_.has_value(); }

    /// The refusal that poisoned the cursor, nullopt while ok(). It is the
    /// first one: later calls fail as a consequence of it, and recording those
    /// consequences would bury the failure that explains the parse.
    [[nodiscard]] std::optional<refusal> refused() const noexcept { return refusal_; }

    /// Bytes not yet consumed. Zero once the cursor is poisoned, so that a
    /// caller looping on remaining() cannot spin.
    [[nodiscard]] constexpr std::size_t remaining() const noexcept {
        return ok() ? data_.size() - offset_ : 0;
    }

    [[nodiscard]] constexpr std::size_t offset() const noexcept { return offset_; }

    /// Consume n bytes. Fails, and poisons the cursor, if fewer remain.
    [[nodiscard]] std::optional<std::span<const std::byte>> bytes(std::size_t n) noexcept {
        if (!take(n)) return std::nullopt;
        return data_.subspan(offset_ - n, n);
    }

    /// Skip n bytes without looking at them.
    bool skip(std::size_t n) noexcept { return take(n); }

    /// True only when the parse consumed exactly the input: trailing bytes
    /// poison the cursor, and a cursor that already failed stays refused even
    /// though remaining() reports zero, so a poisoned parse cannot read as
    /// complete. Like skip(), it belongs in the run of reads checked by ok().
    bool expect_end() noexcept {
        if (!ok()) return false;
        if (offset_ != data_.size()) {
            poison({offset_, reason::trailing_bytes, 0, data_.size() - offset_});
            return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<std::uint8_t> u8() noexcept { return read<std::uint8_t>(endian::big); }

    [[nodiscard]] std::optional<std::uint16_t> u16(endian order) noexcept {
        return read<std::uint16_t>(order);
    }

    [[nodiscard]] std::optional<std::uint32_t> u32(endian order) noexcept {
        return read<std::uint32_t>(order);
    }

    [[nodiscard]] std::optional<std::uint64_t> u64(endian order) noexcept {
        return read<std::uint64_t>(order);
    }

    /// Read a length prefix and then that many bytes — the shape that goes
    /// wrong most often, so it is one call rather than two.
    [[nodiscard]] std::optional<std::span<const std::byte>> length_prefixed_u16(endian order) noexcept {
        return length_prefixed<std::uint16_t>(order);
    }

    [[nodiscard]] std::optional<std::span<const std::byte>> length_prefixed_u32(endian order) noexcept {
        return length_prefixed<std::uint32_t>(order);
    }

  private:
    void poison(refusal record) noexcept {
        if (!refusal_) refusal_ = record;
    }

    bool take(std::size_t n) noexcept {
        if (!ok()) return false;
        if (n > data_.size() - offset_) {
            poison({offset_, reason::short_input, n, data_.size() - offset_});
            return false;
        }
        offset_ += n;
        return true;
    }

    template <typename T>
    [[nodiscard]] std::optional<T> read(endian order) noexcept {
        if (!take(sizeof(T))) return std::nullopt;
        T value{};
        std::memcpy(&value, data_.data() + offset_ - sizeof(T), sizeof(T));
        return fix(value, order);
    }

    template <typename T>
    [[nodiscard]] std::optional<std::span<const std::byte>> length_prefixed(endian order) noexcept {
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

    template <typename T>
    static constexpr T fix(T value, endian order) noexcept {
        if constexpr (sizeof(T) == 1) {
            return value;
        } else {
            const bool host_is_little = std::endian::native == std::endian::little;
            const bool want_little = order == endian::little;
            return host_is_little == want_little ? value : detail::swap_bytes(value);
        }
    }

    std::span<const std::byte> data_;
    std::size_t offset_ = 0;
    std::optional<refusal> refusal_;
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

    /// What has been written so far, for handing to a socket.
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
    bool put(T value, endian order) noexcept {
        if (!take(sizeof(T))) return false;
        if constexpr (sizeof(T) > 1) {
            const bool host_is_little = std::endian::native == std::endian::little;
            const bool want_little = order == endian::little;
            if (host_is_little != want_little) value = detail::swap_bytes(value);
        }
        std::memcpy(out_.data() + offset_ - sizeof(T), &value, sizeof(T));
        return true;
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
};

}  // namespace bytespan

#endif  // BYTESPAN_BYTESPAN_HPP
