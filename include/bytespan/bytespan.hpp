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
// and check once, because after the first failure nothing else succeeds.
//
// Header-only, no allocation, no exceptions, C++20.
#ifndef BYTESPAN_BYTESPAN_HPP
#define BYTESPAN_BYTESPAN_HPP

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <type_traits>

namespace bytespan {

enum class endian { little, big };

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

}  // namespace detail

/// A cursor over bytes that cannot be moved past its end.
class reader {
  public:
    constexpr explicit reader(std::span<const std::byte> data) noexcept : data_(data) {}

    /// True while every read so far has succeeded.
    [[nodiscard]] constexpr bool ok() const noexcept { return ok_; }

    /// Bytes not yet consumed. Zero once the cursor is poisoned, so that a
    /// caller looping on remaining() cannot spin.
    [[nodiscard]] constexpr std::size_t remaining() const noexcept {
        return ok_ ? data_.size() - offset_ : 0;
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
        if (!ok_) return false;
        if (offset_ != data_.size()) {
            ok_ = false;
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
        const auto length = u16(order);
        if (!length) return std::nullopt;
        return bytes(*length);
    }

    [[nodiscard]] std::optional<std::span<const std::byte>> length_prefixed_u32(endian order) noexcept {
        const auto length = u32(order);
        if (!length) return std::nullopt;
        // A 32-bit length on a 32-bit size_t could wrap; bytes() checks against
        // the real remaining size, so the wrap cannot turn into a read.
        return bytes(static_cast<std::size_t>(*length));
    }

  private:
    bool take(std::size_t n) noexcept {
        if (!ok_) return false;
        if (n > data_.size() - offset_) {
            ok_ = false;
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
    bool ok_ = true;
};

/// A cursor that writes, with the same discipline: an overrun fails the writer
/// instead of the process.
class writer {
  public:
    constexpr explicit writer(std::span<std::byte> out) noexcept : out_(out) {}

    [[nodiscard]] constexpr bool ok() const noexcept { return ok_; }
    [[nodiscard]] constexpr std::size_t written() const noexcept { return offset_; }
    [[nodiscard]] constexpr std::size_t remaining() const noexcept {
        return ok_ ? out_.size() - offset_ : 0;
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

  private:
    bool take(std::size_t n) noexcept {
        if (!ok_) return false;
        if (n > out_.size() - offset_) {
            ok_ = false;
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

    std::span<std::byte> out_;
    std::size_t offset_ = 0;
    bool ok_ = true;
};

}  // namespace bytespan

#endif  // BYTESPAN_BYTESPAN_HPP
