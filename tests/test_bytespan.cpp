#include "bytespan/bytespan.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <span>
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

bool refused_with(const std::optional<refusal>& record, std::size_t offset, reason why,
                  std::size_t wanted, std::size_t available) {
    return record.has_value() && record->offset == offset && record->why == why &&
           record->wanted == wanted && record->available == available;
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

// One check for the whole header is only useful if it can still say which
// field went wrong, and the record has to survive the reads that follow it.
void the_first_refusal_is_kept_with_its_offset_reason_and_sizes() {
    const auto data = raw({0x01, 0x02, 0x03});
    reader r{data};

    CHECK(r.u8() == 1u);
    CHECK(!r.refused().has_value());

    CHECK(!r.u32(endian::big).has_value());
    CHECK(refused_with(r.refused(), 1, reason::short_input, 4, 2));

    // A byte is still there to read, and reading it must not rewrite history.
    CHECK(!r.u8().has_value());
    CHECK(!r.skip(1));
    CHECK(!r.bytes(1).has_value());
    CHECK(!r.expect_end());
    CHECK(refused_with(r.refused(), 1, reason::short_input, 4, 2));
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
    CHECK(!r.refused().has_value());
}

// A refusal has to name the field it refused, the way it does for every other
// read — the prefix is part of that field, not progress through it.
void a_refused_length_prefixed_read_leaves_the_offset_at_the_prefix() {
    const auto lying = raw({0x01, 0xFF, 0xFF, 0xAA, 0xBB});
    reader r{lying};
    CHECK(r.u8() == 1u);
    CHECK(!r.length_prefixed_u16(endian::big).has_value());
    CHECK(r.offset() == 1);
    CHECK(!r.ok());
    CHECK(r.remaining() == 0);

    const auto wide = raw({0x01, 0x00, 0x00, 0x00, 0x05, 0xAA});
    reader thirty_two{wide};
    CHECK(thirty_two.u8() == 1u);
    CHECK(!thirty_two.length_prefixed_u32(endian::big).has_value());
    CHECK(thirty_two.offset() == 1);
    CHECK(!thirty_two.ok());
    CHECK(thirty_two.remaining() == 0);

    // The prefix itself cut short is refused at the same place.
    const auto cut = raw({0x01, 0xFF});
    reader short_prefix{cut};
    CHECK(short_prefix.u8() == 1u);
    CHECK(!short_prefix.length_prefixed_u16(endian::big).has_value());
    CHECK(short_prefix.offset() == 1);
    CHECK(!short_prefix.ok());
}

// The count and the body are one field, so the sizes in the record are the
// field's: the prefix width plus the length it declared.
void a_refused_length_prefixed_read_records_the_whole_field() {
    const auto lying = raw({0x01, 0xFF, 0xFF, 0xAA, 0xBB});
    reader r{lying};
    CHECK(r.u8() == 1u);
    CHECK(!r.length_prefixed_u16(endian::big).has_value());
    CHECK(refused_with(r.refused(), 1, reason::short_input, 2 + 0xFFFF, 4));

    const auto cut = raw({0x01, 0xFF});
    reader short_prefix{cut};
    CHECK(short_prefix.u8() == 1u);
    CHECK(!short_prefix.length_prefixed_u16(endian::big).has_value());
    CHECK(refused_with(short_prefix.refused(), 1, reason::short_input, 2, 1));
}

// A 32-bit length on a 32-bit size_t is the classic integer-overflow path into
// a huge memcpy. The check is against the real remaining size, so it cannot.
void an_enormous_length_prefix_cannot_wrap_into_a_read() {
    const auto data = raw({0xFF, 0xFF, 0xFF, 0xFF, 0x01});
    reader r{data};

    CHECK(!r.length_prefixed_u32(endian::big).has_value());
    CHECK(!r.ok());
    CHECK(r.refused()->offset == 0);
    CHECK(r.refused()->why == reason::short_input);
    CHECK(r.refused()->available == 5);
}

void skip_and_bytes_respect_the_end() {
    const auto data = raw({1, 2, 3, 4});
    reader r{data};

    CHECK(r.skip(3));
    CHECK(r.remaining() == 1);
    CHECK(!r.bytes(2).has_value());
    CHECK(!r.ok());
    CHECK(refused_with(r.refused(), 3, reason::short_input, 2, 1));
}

void an_empty_buffer_reads_nothing_and_says_so() {
    const std::span<const std::byte> empty;
    reader r{empty};

    CHECK(r.remaining() == 0);
    CHECK(r.ok());
    CHECK(!r.u8().has_value());
    CHECK(!r.ok());
    CHECK(refused_with(r.refused(), 0, reason::short_input, 1, 0));
}

// A record that ends where the input ends.
void expect_end_accepts_a_parse_that_consumed_everything() {
    const auto data = raw({0x01, 0x02, 0x03});
    reader r{data};

    CHECK(r.u8() == 1u);
    CHECK(r.u16(endian::big) == 0x0203u);
    CHECK(r.expect_end());
    CHECK(r.ok());
    CHECK(!r.refused().has_value());

    const std::span<const std::byte> empty;
    reader nothing{empty};
    CHECK(nothing.expect_end());
    CHECK(nothing.ok());
}

// Bytes after the last field mean the input was not the record it claimed to
// be, and a cursor that already failed must not look finished either — its
// remaining() is zero for a different reason.
void expect_end_refuses_trailing_bytes_and_a_failed_cursor() {
    const auto data = raw({0x01, 0x02, 0x03, 0x04});
    reader trailing{data};

    CHECK(trailing.u8() == 1u);
    CHECK(trailing.u16(endian::big) == 0x0203u);
    CHECK(!trailing.expect_end());
    CHECK(!trailing.ok());
    CHECK(trailing.offset() == 3);

    const auto truncated = raw({0x01, 0x02});
    reader poisoned{truncated};
    CHECK(!poisoned.u32(endian::big).has_value());
    CHECK(poisoned.remaining() == 0);
    CHECK(!poisoned.expect_end());
    CHECK(!poisoned.ok());
    // Refused for being short, not for what came after it.
    CHECK(refused_with(poisoned.refused(), 0, reason::short_input, 4, 2));
}

// Nothing was wanted, and bytes were there anyway: the count of them is the
// useful half of the record.
void trailing_bytes_are_recorded_with_their_count() {
    const auto data = raw({0x01, 0x02, 0x03, 0x04, 0x05});
    reader r{data};

    CHECK(r.u8() == 1u);
    CHECK(r.u16(endian::big) == 0x0203u);
    CHECK(!r.expect_end());
    CHECK(refused_with(r.refused(), 3, reason::trailing_bytes, 0, 2));
}

void the_writer_round_trips_what_the_reader_reads() {
    std::array<std::byte, 16> buffer{};
    writer w{buffer};

    CHECK(w.u8(0x7F));
    CHECK(w.u16(0xBEEF, endian::big));
    CHECK(w.u32(0xDEADBEEF, endian::little));
    CHECK(w.ok());
    CHECK(!w.refused().has_value());
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

// An overrun says where the writer stood, what the call needed, and what was
// left — and the smaller call that fails next does not take its place.
void the_writer_records_an_overrun_as_no_room() {
    std::array<std::byte, 3> buffer{};
    writer w{buffer};

    CHECK(w.u16(0x0102, endian::big));
    CHECK(!w.refused().has_value());

    CHECK(!w.u32(0, endian::big));
    CHECK(refused_with(w.refused(), 2, reason::no_room, 4, 1));

    CHECK(!w.u8(0xFF));
    CHECK(!w.bytes(std::span<const std::byte>{}));
    CHECK(refused_with(w.refused(), 2, reason::no_room, 4, 1));
}

// Nothing stops a caller handing the writer a span of the buffer it is writing
// into — of view(), or of the array itself. Shifting a region one byte along is
// the overlap memcpy leaves undefined, so this must come out right under ASan.
void the_writer_copies_a_source_that_aliases_its_own_buffer() {
    std::array<std::byte, 8> buffer{};
    for (std::size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<std::byte>(i + 1);
    }

    writer w{buffer};
    CHECK(w.u8(1));
    CHECK(w.bytes(std::span(buffer).first(4)));
    CHECK(w.ok());
    CHECK(w.written() == 5);

    const auto expected = raw({1, 1, 2, 3, 4, 6, 7, 8});
    CHECK(std::equal(buffer.begin(), buffer.end(), expected.begin()));
}

// The buffer is big enough for the bytes; the prefix is not big enough for the
// count. Truncating it would write a record that lies about its own length.
void a_payload_too_large_for_its_prefix_is_refused() {
    std::vector<std::byte> buffer(80000);
    const std::vector<std::byte> payload(70000, std::byte{0xAB});

    writer w{buffer};
    CHECK(!w.length_prefixed_u16(payload, endian::big));
    CHECK(!w.ok());
    CHECK(w.written() == 0);
    CHECK(w.view().empty());
    // Room was never the problem: the record says so by naming the prefix's
    // maximum as what was available.
    CHECK(refused_with(w.refused(), 0, reason::too_long, 70000, 0xFFFF));
}

// Room for the count but not the body: all or nothing, so no lone prefix is
// left for a reader to trust.
void a_prefix_without_room_for_its_body_writes_nothing() {
    std::array<std::byte, 4> buffer{};
    const auto payload = raw({0xAA, 0xBB, 0xCC});

    writer w{buffer};
    CHECK(!w.length_prefixed_u16(payload, endian::big));
    CHECK(!w.ok());
    CHECK(w.written() == 0);
    CHECK(buffer[0] == std::byte{0});
    CHECK(buffer[1] == std::byte{0});
    // Prefix and body are one call, so what it wanted is both of them.
    CHECK(refused_with(w.refused(), 0, reason::no_room, 5, 4));
}

void an_honest_length_prefixed_write_round_trips() {
    const auto payload = raw({0xAA, 0xBB, 0xCC});

    for (const endian order : {endian::big, endian::little}) {
        std::array<std::byte, 16> buffer{};
        writer w{buffer};
        CHECK(w.length_prefixed_u16(payload, order));
        CHECK(w.length_prefixed_u32(payload, order));
        CHECK(w.ok());
        CHECK(w.written() == 12);

        reader r{w.view()};
        const auto first = r.length_prefixed_u16(order);
        const auto second = r.length_prefixed_u32(order);
        CHECK(first.has_value());
        CHECK(second.has_value());
        CHECK(first->size() == 3);
        CHECK(second->size() == 3);
        CHECK(std::equal(first->begin(), first->end(), payload.begin()));
        CHECK(std::equal(second->begin(), second->end(), payload.begin()));
        CHECK(r.expect_end());
    }
}

}  // namespace

int main() {
    reads_integers_in_both_orders();
    a_truncated_read_fails_instead_of_reading_past_the_end();
    failure_is_sticky();
    the_first_refusal_is_kept_with_its_offset_reason_and_sizes();
    a_lying_length_prefix_is_refused();
    an_honest_length_prefix_is_read();
    a_refused_length_prefixed_read_leaves_the_offset_at_the_prefix();
    a_refused_length_prefixed_read_records_the_whole_field();
    an_enormous_length_prefix_cannot_wrap_into_a_read();
    skip_and_bytes_respect_the_end();
    an_empty_buffer_reads_nothing_and_says_so();
    expect_end_accepts_a_parse_that_consumed_everything();
    expect_end_refuses_trailing_bytes_and_a_failed_cursor();
    trailing_bytes_are_recorded_with_their_count();
    the_writer_round_trips_what_the_reader_reads();
    the_writer_refuses_to_overrun_its_buffer();
    the_writer_records_an_overrun_as_no_room();
    the_writer_copies_a_source_that_aliases_its_own_buffer();
    a_payload_too_large_for_its_prefix_is_refused();
    a_prefix_without_room_for_its_body_writes_nothing();
    an_honest_length_prefixed_write_round_trips();
    return harness::report("bytespan");
}
