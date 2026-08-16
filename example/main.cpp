// Parsing a record header the way a protocol actually arrives: some of it
// truncated, one length field lying about what follows.
//
//   make demo
#include "bytespan/bytespan.hpp"

#include <cstdio>
#include <span>
#include <vector>

namespace {

struct record {
    std::uint8_t type;
    std::uint16_t version;
    std::span<const std::byte> payload;
};

// The whole parse is a run of reads with one check at the end, which is the
// only version of this anyone writes in practice.
std::optional<record> parse(std::span<const std::byte> input) {
    bytespan::reader r{input};

    record out{};
    const auto type = r.u8();
    const auto version = r.u16(bytespan::endian::big);
    const auto payload = r.length_prefixed_u16(bytespan::endian::big);

    if (!r.ok()) return std::nullopt;
    out.type = *type;
    out.version = *version;
    out.payload = *payload;
    return out;
}

std::vector<std::byte> raw(std::initializer_list<int> values) {
    std::vector<std::byte> out;
    for (int value : values) out.push_back(static_cast<std::byte>(value));
    return out;
}

void show(const char* label, std::span<const std::byte> input) {
    const auto parsed = parse(input);
    if (!parsed) {
        std::printf("%-28s refused\n", label);
        return;
    }
    std::printf("%-28s type=0x%02X version=0x%04X payload=%zu bytes\n", label,
                parsed->type, parsed->version, parsed->payload.size());
}

}  // namespace

int main() {
    show("well formed", raw({0x16, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC}));
    show("header cut short", raw({0x16, 0x03}));
    show("length field lies", raw({0x16, 0x03, 0x03, 0xFF, 0xFF, 0xAA}));
    show("empty input", {});
    return 0;
}
