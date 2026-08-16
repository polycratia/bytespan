#include "bytespan/bytespan.hpp"

#include <array>
#include <cstddef>
#include <vector>

#include "harness.hpp"

using namespace bytespan;

namespace {

std::vector<std::byte> raw(std::initializer_list<int> values) {
    std::vector<std::byte> out;
    out.reserve(values.size());
    for (int value : values) out.push_back(static_cast<std::byte>(value));
    return out;
}

void reads_integers_in_both_orders() {
    const auto data = raw({0x01, 0x02, 0x03, 0x04});

    reader big{data};
    CHECK(big.u32(endian::big) == 0x01020304u);
    CHECK(big.ok());
    CHECK(big.remaining() == 0);

    reader little{data};
    CHECK(little.u32(endian::little) == 0x04030201u);

    const auto wide = raw({0, 0, 0, 0, 0, 0, 0, 9});
    reader sixty_four{wide};
    CHECK(sixty_four.u64(endian::big) == 9u);
}

// The whole point: the length says more than the buffer holds.
void a_truncated_read_fails_instead_of_reading_past_the_end() {
    const auto data = raw({0x01, 0x02});
    reader r{data};

    CHECK(!r.u32(endian::big).has_value());
    CHECK(!r.ok());
    CHECK(r.remaining() == 0);
    // The cursor did not move past what it could read.
    CHECK(r.offset() == 0);
}

// Parsing a header is a run of reads. Checking every one is what people skip,
// so the first failure has to make the rest fail too.
void failure_is_sticky() {
    const auto data = raw({0x01, 0x02});
    reader r{data};

    CHECK(r.u8() == 1u);
    CHECK(!r.u32(endian::big).has_value());  // fails here
    CHECK(!r.u8().has_value());              // and stays failed, though a byte remains
    CHECK(!r.skip(0));
    CHECK(!r.bytes(0).has_value());
    CHECK(!r.ok());
}

void a_lying_length_prefix_is_refused() {
    // Says 0xFFFF bytes follow; two do.
    const auto data = raw({0xFF, 0xFF, 0xAA, 0xBB});
    reader r{data};

    CHECK(!r.length_prefixed_u16(endian::big).has_value());
    CHECK(!r.ok());
}

void an_honest_length_prefix_is_read() {
    const auto data = raw({0x00, 0x02, 0xAA, 0xBB, 0xCC});
    reader r{data};

    const auto payload = r.length_prefixed_u16(endian::big);
    CHECK(payload.has_value());
    CHECK(payload->size() == 2);
    CHECK((*payload)[0] == std::byte{0xAA});
    CHECK(r.remaining() == 1);
}

// A 32-bit length on a 32-bit size_t is the classic integer-overflow path into
// a huge memcpy. The check is against the real remaining size, so it cannot.
void an_enormous_length_prefix_cannot_wrap_into_a_read() {
    const auto data = raw({0xFF, 0xFF, 0xFF, 0xFF, 0x01});
    reader r{data};

    CHECK(!r.length_prefixed_u32(endian::big).has_value());
    CHECK(!r.ok());
}

void skip_and_bytes_respect_the_end() {
    const auto data = raw({1, 2, 3, 4});
    reader r{data};

    CHECK(r.skip(3));
    CHECK(r.remaining() == 1);
    CHECK(!r.bytes(2).has_value());
    CHECK(!r.ok());
}

void an_empty_buffer_reads_nothing_and_says_so() {
    const std::span<const std::byte> empty;
    reader r{empty};

    CHECK(r.remaining() == 0);
    CHECK(r.ok());
    CHECK(!r.u8().has_value());
    CHECK(!r.ok());
}

void the_writer_round_trips_what_the_reader_reads() {
    std::array<std::byte, 16> buffer{};
    writer w{buffer};

    CHECK(w.u8(0x7F));
    CHECK(w.u16(0xBEEF, endian::big));
    CHECK(w.u32(0xDEADBEEF, endian::little));
    CHECK(w.ok());
    CHECK(w.written() == 7);

    reader r{w.view()};
    CHECK(r.u8() == 0x7Fu);
    CHECK(r.u16(endian::big) == 0xBEEFu);
    CHECK(r.u32(endian::little) == 0xDEADBEEFu);
    CHECK(r.remaining() == 0);
}

void the_writer_refuses_to_overrun_its_buffer() {
    std::array<std::byte, 3> buffer{};
    writer w{buffer};

    CHECK(w.u16(0x0102, endian::big));
    CHECK(!w.u32(0, endian::big));
    CHECK(!w.ok());
    // Sticky here too: nothing more is written after the failure.
    CHECK(!w.u8(0xFF));
    CHECK(w.written() == 2);
    CHECK(w.view().size() == 2);
}

}  // namespace

int main() {
    reads_integers_in_both_orders();
    a_truncated_read_fails_instead_of_reading_past_the_end();
    failure_is_sticky();
    a_lying_length_prefix_is_refused();
    an_honest_length_prefix_is_read();
    an_enormous_length_prefix_cannot_wrap_into_a_read();
    skip_and_bytes_respect_the_end();
    an_empty_buffer_reads_nothing_and_says_so();
    the_writer_round_trips_what_the_reader_reads();
    the_writer_refuses_to_overrun_its_buffer();
    return harness::report("bytespan");
}
