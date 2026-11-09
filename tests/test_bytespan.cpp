#include "bytespan/bytespan.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "harness.hpp"

using namespace bytespan;

// Constant evaluation is where core-language undefined behaviour cannot be
// reached: a read past the end of the span makes this block fail to compile,
// on every compiler, with or without sanitizers. It covers the inputs written
// here and no others, which is why the runtime tests below still run under
// AddressSanitizer and UndefinedBehaviorSanitizer.
namespace compile_time {

constexpr bool a_truncated_u32_is_refused_at_offset_zero() {
    constexpr std::array<std::byte, 2> input{std::byte{0x01}, std::byte{0x02}};
    reader r{input};

    if (r.u32(endian::big).has_value()) return false;
    if (r.ok() || r.offset() != 0 || r.remaining() != 0) return false;

    const auto why = r.refused();
    return why.has_value() && why->offset == 0 && why->why == reason::short_input &&
           why->wanted == 4 && why->available == 2;
}

constexpr bool a_lying_u16_prefix_is_refused_at_offset_zero() {
    constexpr std::array<std::byte, 4> input{std::byte{0xFF}, std::byte{0xFF},
                                             std::byte{0xAA}, std::byte{0xBB}};
    reader r{input};

    if (r.length_prefixed_u16(endian::big).has_value()) return false;
    if (r.ok() || r.offset() != 0) return false;

    const auto why = r.refused();
    return why.has_value() && why->offset == 0 && why->why == reason::short_input &&
           why->wanted == 2 + 0xFFFF && why->available == 4;
}

constexpr bool an_honest_u16_prefix_yields_its_payload() {
    constexpr std::array<std::byte, 4> input{std::byte{0x00}, std::byte{0x02},
                                             std::byte{0xAA}, std::byte{0xBB}};
    reader r{input};

    const auto payload = r.length_prefixed_u16(endian::big);
    if (!payload.has_value() || payload->size() != 2) return false;
    if ((*payload)[0] != std::byte{0xAA} || (*payload)[1] != std::byte{0xBB}) return false;

    return r.expect_end() && r.ok();
}

constexpr bool a_trailing_byte_fails_expect_end() {
    constexpr std::array<std::byte, 3> input{std::byte{0x01}, std::byte{0x02},
                                             std::byte{0x03}};
    reader r{input};

    if (r.u16(endian::big) != 0x0102u) return false;
    if (r.expect_end()) return false;

    const auto why = r.refused();
    return !r.ok() && why.has_value() && why->offset == 2 &&
           why->why == reason::trailing_bytes && why->wanted == 0 && why->available == 1;
}

constexpr bool a_padded_varint_is_non_canonical() {
    constexpr std::array<std::byte, 2> input{std::byte{0x80}, std::byte{0x00}};
    reader r{input};

    if (r.varint_u64().has_value()) return false;
    if (r.ok() || r.offset() != 0) return false;

    const auto why = r.refused();
    return why.has_value() && why->offset == 0 && why->why == reason::non_canonical &&
           why->wanted == 0 && why->available == 2;
}

static_assert(a_truncated_u32_is_refused_at_offset_zero());
static_assert(a_lying_u16_prefix_is_refused_at_offset_zero());
static_assert(an_honest_u16_prefix_yields_its_payload());
static_assert(a_trailing_byte_fails_expect_end());
static_assert(a_padded_varint_is_non_canonical());

}  // namespace compile_time

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
    CHECK(!r.varint_u64().has_value());
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

// A canonical LEB128 value has exactly one spelling, so the bytes are checked
// against the published encoding rather than against whatever comes out.
void varints_round_trip_through_their_exact_bytes() {
    const struct {
        std::uint64_t value;
        std::vector<std::byte> encoded;
    } cases[] = {
        {0, raw({0x00})},
        {127, raw({0x7F})},
        {128, raw({0x80, 0x01})},
        {300, raw({0xAC, 0x02})},
        {UINT64_MAX, raw({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01})},
    };

    for (const auto& one : cases) {
        std::array<std::byte, 16> buffer{};
        writer w{buffer};
        CHECK(w.varint_u64(one.value));
        CHECK(w.ok());
        CHECK(w.written() == one.encoded.size());
        CHECK(std::equal(w.view().begin(), w.view().end(), one.encoded.begin()));

        reader round_trip{w.view()};
        CHECK(round_trip.varint_u64() == one.value);
        CHECK(round_trip.expect_end());
        CHECK(round_trip.ok());

        reader published{one.encoded};
        CHECK(published.varint_u64() == one.value);
        CHECK(published.expect_end());
    }
}

// 0x80 0x00 is zero written the long way. Accepting it would give the same
// value two spellings, which is a difference two parsers can be played off.
void a_padded_varint_is_refused_as_non_canonical() {
    const auto padded = raw({0x80, 0x00});
    reader r{padded};

    CHECK(!r.varint_u64().has_value());
    CHECK(!r.ok());
    CHECK(r.offset() == 0);
    CHECK(r.remaining() == 0);
    CHECK(refused_with(r.refused(), 0, reason::non_canonical, 0, 2));
}

// Ten groups hold 64 bits only if the tenth holds a single one. Past that the
// value would wrap, which is how a length check gets walked around.
void a_varint_past_sixty_four_bits_is_refused() {
    const auto wrapping =
        raw({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02});
    reader r{wrapping};
    CHECK(!r.varint_u64().has_value());
    CHECK(!r.ok());
    CHECK(r.offset() == 0);
    CHECK(refused_with(r.refused(), 0, reason::overflow, 0, 10));

    // Eleven bytes are refused at the tenth, which already continued.
    const auto endless = raw({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                              0x01});
    reader eleven{endless};
    CHECK(!eleven.varint_u64().has_value());
    CHECK(eleven.offset() == 0);
    CHECK(refused_with(eleven.refused(), 0, reason::overflow, 0, 10));
}

// The input ran out mid-varint: a continuation byte promised more and there
// was no more.
void a_varint_that_ends_inside_itself_is_short_input() {
    const auto lone = raw({0x80});
    reader r{lone};
    CHECK(!r.varint_u64().has_value());
    CHECK(!r.ok());
    CHECK(r.offset() == 0);
    CHECK(refused_with(r.refused(), 0, reason::short_input, 2, 1));

    const std::span<const std::byte> empty;
    reader nothing{empty};
    CHECK(!nothing.varint_u64().has_value());
    CHECK(refused_with(nothing.refused(), 0, reason::short_input, 1, 0));
}

// A varint is one field however many bytes it spans, so the refusal names its
// first byte rather than the byte that proved it wrong.
void a_refused_varint_names_its_own_first_byte() {
    const auto data = raw({0x01, 0x80, 0x00});
    reader r{data};

    CHECK(r.u8() == 1u);
    CHECK(!r.varint_u64().has_value());
    CHECK(r.offset() == 1);
    CHECK(refused_with(r.refused(), 1, reason::non_canonical, 0, 2));
}

// All or nothing: a varint that does not fit leaves the writer where it was,
// not with a prefix of itself in the buffer.
void a_varint_without_room_writes_nothing() {
    std::array<std::byte, 9> buffer{};
    writer w{buffer};

    CHECK(!w.varint_u64(UINT64_MAX));
    CHECK(!w.ok());
    CHECK(w.written() == 0);
    CHECK(w.view().empty());
    CHECK(buffer[0] == std::byte{0});
    CHECK(refused_with(w.refused(), 0, reason::no_room, 10, 9));

    std::array<std::byte, 2> tight{};
    writer exact{tight};
    CHECK(exact.varint_u64(128));
    CHECK(exact.written() == 2);
    CHECK(!exact.varint_u64(128));
    CHECK(exact.written() == 2);
    CHECK(refused_with(exact.refused(), 2, reason::no_room, 2, 0));
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

// Formats nest: an extension block whose length covers a TLV carrying its own.
// Neither count is known when it has to be written, so both are reserved and
// patched afterwards, and the reader reads them back as ordinary prefixes.
void nested_length_slots_round_trip_through_the_reader() {
    const auto payload = raw({0xAA, 0xBB, 0xCC});
    std::array<std::byte, 32> buffer{};
    writer w{buffer};

    const auto block = w.open_u16();
    CHECK(block.has_value());
    CHECK(w.u8(0x0A));
    const auto body = w.open_u16();
    CHECK(body.has_value());
    CHECK(w.bytes(payload));
    CHECK(w.close(*body, endian::big));
    CHECK(w.close(*block, endian::big));
    CHECK(w.ok());
    CHECK(w.written() == 8);

    const auto expected = raw({0x00, 0x06, 0x0A, 0x00, 0x03, 0xAA, 0xBB, 0xCC});
    CHECK(std::equal(w.view().begin(), w.view().end(), expected.begin()));

    reader r{w.view()};
    const auto block_bytes = r.length_prefixed_u16(endian::big);
    CHECK(block_bytes.has_value());
    CHECK(block_bytes->size() == 6);
    CHECK(r.expect_end());

    reader inner{*block_bytes};
    CHECK(inner.u8() == 0x0Au);
    const auto body_bytes = inner.length_prefixed_u16(endian::big);
    CHECK(body_bytes.has_value());
    CHECK(body_bytes->size() == 3);
    CHECK(std::equal(body_bytes->begin(), body_bytes->end(), payload.begin()));
    CHECK(inner.expect_end());
}

void a_u32_slot_is_patched_in_either_order() {
    const auto payload = raw({0xAA, 0xBB, 0xCC});

    for (const endian order : {endian::big, endian::little}) {
        std::array<std::byte, 16> buffer{};
        writer w{buffer};

        const auto slot = w.open_u32();
        CHECK(slot.has_value());
        CHECK(w.bytes(payload));
        CHECK(w.close(*slot, order));
        CHECK(w.ok());
        CHECK(w.written() == 7);

        reader r{w.view()};
        const auto body = r.length_prefixed_u32(order);
        CHECK(body.has_value());
        CHECK(body->size() == 3);
        CHECK(std::equal(body->begin(), body->end(), payload.begin()));
        CHECK(r.expect_end());
    }
}

// The field cannot hold the count the body turned out to need. Truncating it
// would write a block that lies about its own length.
void a_body_too_long_for_its_slot_is_refused() {
    std::vector<std::byte> buffer(80000);
    const std::vector<std::byte> body(70000, std::byte{0xAB});

    writer w{buffer};
    const auto slot = w.open_u16();
    CHECK(slot.has_value());
    CHECK(w.bytes(body));
    CHECK(!w.close(*slot, endian::big));
    CHECK(!w.ok());
    CHECK(refused_with(w.refused(), 0, reason::too_long, 70000, 0xFFFF));
    // The field keeps the zeros it was reserved with.
    CHECK(buffer[0] == std::byte{0});
    CHECK(buffer[1] == std::byte{0});
}

// Closing the outer block first would patch it with a length that stops short
// of the inner one, which is a record no reader can make sense of.
void closing_a_slot_out_of_order_is_refused() {
    std::array<std::byte, 16> buffer{};
    writer w{buffer};

    const auto outer = w.open_u16();
    const auto inner = w.open_u16();
    CHECK(outer.has_value());
    CHECK(inner.has_value());
    CHECK(w.u8(0xAA));

    CHECK(!w.close(*outer, endian::big));
    CHECK(!w.ok());
    CHECK(refused_with(w.refused(), 5, reason::bad_slot, 0, 0));
    // Sticky: the inner one cannot be closed afterwards either.
    CHECK(!w.close(*inner, endian::big));
    CHECK(refused_with(w.refused(), 5, reason::bad_slot, 0, 0));
}

// A slot is spent by its close. Closing it again would patch a field with a
// count of bytes written after the block it belonged to.
void closing_a_slot_twice_is_refused() {
    std::array<std::byte, 16> buffer{};
    writer w{buffer};

    const auto slot = w.open_u16();
    CHECK(slot.has_value());
    CHECK(w.u16(0xBEEF, endian::big));
    CHECK(w.close(*slot, endian::big));
    CHECK(w.ok());

    CHECK(!w.close(*slot, endian::big));
    CHECK(!w.ok());
    CHECK(refused_with(w.refused(), 4, reason::bad_slot, 0, 0));
    // The length patched the first time survived the refusal.
    CHECK(buffer[0] == std::byte{0x00});
    CHECK(buffer[1] == std::byte{0x02});
}

// Two writers, two buffers: a slot carries the data pointer it was opened on,
// so it cannot be closed over someone else's bytes.
void a_slot_from_another_buffer_is_refused() {
    std::array<std::byte, 16> first{};
    std::array<std::byte, 16> second{};
    writer a{first};
    writer b{second};

    const auto slot = a.open_u16();
    CHECK(slot.has_value());
    CHECK(b.u8(0x01));

    CHECK(!b.close(*slot, endian::big));
    CHECK(!b.ok());
    CHECK(refused_with(b.refused(), 1, reason::bad_slot, 0, 0));
    CHECK(a.ok());
    CHECK(second[0] == std::byte{0x01});
}

void a_slot_that_does_not_fit_is_refused_as_no_room() {
    std::array<std::byte, 1> buffer{};
    writer w{buffer};

    CHECK(!w.open_u16().has_value());
    CHECK(!w.ok());
    CHECK(w.written() == 0);
    CHECK(refused_with(w.refused(), 0, reason::no_room, 2, 1));
    // And a poisoned writer hands out no slots at all.
    CHECK(!w.open_u32().has_value());
    CHECK(refused_with(w.refused(), 0, reason::no_room, 2, 1));
}

// view() makes no promise about open slots: a field whose close never came is
// still the zeros open reserved, even over a buffer that arrived dirty.
void an_unclosed_slot_stays_zero_in_the_view() {
    std::array<std::byte, 8> buffer{};
    buffer.fill(std::byte{0xFF});

    writer w{buffer};
    const auto slot = w.open_u16();
    CHECK(slot.has_value());
    CHECK(w.u8(0xAA));
    CHECK(w.ok());

    const auto expected = raw({0x00, 0x00, 0xAA});
    CHECK(w.view().size() == 3);
    CHECK(std::equal(w.view().begin(), w.view().end(), expected.begin()));
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
    varints_round_trip_through_their_exact_bytes();
    a_padded_varint_is_refused_as_non_canonical();
    a_varint_past_sixty_four_bits_is_refused();
    a_varint_that_ends_inside_itself_is_short_input();
    a_refused_varint_names_its_own_first_byte();
    a_varint_without_room_writes_nothing();
    the_writer_round_trips_what_the_reader_reads();
    the_writer_refuses_to_overrun_its_buffer();
    the_writer_records_an_overrun_as_no_room();
    the_writer_copies_a_source_that_aliases_its_own_buffer();
    a_payload_too_large_for_its_prefix_is_refused();
    a_prefix_without_room_for_its_body_writes_nothing();
    an_honest_length_prefixed_write_round_trips();
    nested_length_slots_round_trip_through_the_reader();
    a_u32_slot_is_patched_in_either_order();
    a_body_too_long_for_its_slot_is_refused();
    closing_a_slot_out_of_order_is_refused();
    closing_a_slot_twice_is_refused();
    a_slot_from_another_buffer_is_refused();
    a_slot_that_does_not_fit_is_refused_as_no_room();
    an_unclosed_slot_stays_zero_in_the_view();
    return harness::report("bytespan");
}
