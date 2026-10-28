# bytespan

Reading and writing binary formats without reaching past the end.

Nearly every memory-safety bug in a C++ protocol parser is the same mistake
written a different way: a length field is trusted, a `memcpy` runs past the
buffer, and the result is a remote crash at best. The fix is not cleverness. It
is refusing to do the unchecked thing at all.

```console
$ make demo
well formed                  type=0x16 version=0x0303 payload=3 bytes
header cut short             refused
length field lies            refused
empty input                  refused
```

## The decision that makes it usable

A failed read **poisons the cursor**. Parsing a header is a run of reads, and
checking every single one is exactly what people skip — so here you read the
whole header and check once:

```cpp
bytespan::reader r{input};

const auto type    = r.u8();
const auto version = r.u16(bytespan::endian::big);
const auto payload = r.length_prefixed_u16(bytespan::endian::big);

if (!r.ok()) return std::nullopt;   // one check for the whole header
```

After the first failure nothing else succeeds, `remaining()` reports zero so a
loop cannot spin, and the cursor never moves past what it could actually read.

## What it refuses

**A length prefix that lies.** `length_prefixed_u16` and `length_prefixed_u32`
read the count and the payload in one call, because splitting them is where the
check gets forgotten. A refusal leaves `offset()` at the start of the prefix, so
it names the field that was refused rather than a position inside it.

**A count that does not match the bytes.** The writer has the same pair, taking
the payload and writing its size ahead of it. A payload too large for the prefix
fails the writer instead of truncating the count, and prefix and body are
reserved in one bounds check — a refusal never leaves a lone length behind for
someone to trust.

**An integer overflow turning into a read.** A 32-bit length on a 32-bit
`size_t` can wrap; the bounds check is against the real remaining size, so a
wrapped length cannot become a huge `memcpy`.

**Bytes nobody asked for.** `expect_end()` is true only when the cursor is
still `ok()` and sits exactly at the end of the input. Trailing bytes poison it
like any other failure, and a cursor that already failed is refused too — its
`remaining()` is zero for the opposite reason. It joins the run of reads and is
covered by the same single `ok()`:

```cpp
const auto type    = r.u8();
const auto version = r.u16(bytespan::endian::big);
r.expect_end();

if (!r.ok()) return std::nullopt;   // short, long, or mangled — all one check
```

**Silent endianness.** Byte order is a parameter, never a default. A parser that
happens to work on this machine is not a parser.

## Use

Header-only, C++20, no dependencies, no allocation, no exceptions. Copy
`include/` or point your include path at it.

```cpp
#include "bytespan/bytespan.hpp"

std::array<std::byte, 64> buffer{};
bytespan::writer w{buffer};
w.u8(0x16);
w.u16(0x0303, bytespan::endian::big);
w.length_prefixed_u16(payload, bytespan::endian::big);
if (!w.ok()) { /* the buffer was too small; nothing overran */ }
send(w.view());
```

The writer has the same discipline as the reader: an overrun fails the writer
instead of the process, and stays failed.

## What it is not

**Not a serialisation framework.** No schemas, no code generation, no field
descriptors. It is a cursor with bounds checks, and it stops there.

**Not a substitute for the sanitizers.** The tests run under
`-fsanitize=address,undefined`, because a bounds-checking library that is only
checked by its own assertions has proved nothing.

**Not `std::byteswap`.** That is C++23; this reverses the bytes by hand to stay
at C++20, where most projects that need this actually are. Every compiler
recognises the pattern.

## Status

Early, and small on purpose.

| | |
|---|---|
| Reading | `u8`/`u16`/`u32`/`u64` in either byte order, raw spans, skip, length-prefixed payloads, `expect_end` |
| Writing | the same set, bounds-checked, with a view of what was written |
| Not yet | signed integers, varints, floating point, bit-level fields, `std::expected` return type for C++23 users |

## Development

```bash
make test   # under AddressSanitizer and UndefinedBehaviorSanitizer
make demo
```

## License

MIT

Maintained by [polycratia](https://polycratia.com).
