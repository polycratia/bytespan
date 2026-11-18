# bytespan

Reading and writing binary formats without reaching past the end.

Nearly every memory-safety bug in a C++ protocol parser is the same mistake
written a different way: a length field is trusted, a `memcpy` runs past the
buffer, and the result is a remote crash at best. The fix is not cleverness. It
is refusing to do the unchecked thing at all.

```console
$ make demo
well formed                  type=0x16 version=0x0303 payload=3 bytes
header cut short             refused at 1: short input (wanted 2, had 1)
length field lies            refused at 3: short input (wanted 65537, had 3)
empty input                  refused at 0: short input (wanted 1, had 0)
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

**A length field closed out of order.** When the size is not known until the
body has been written — the shape every nested format has, a block whose count
covers a block that carries its own — `open_u16` and `open_u32` reserve a
zeroed field and hand back a `length_slot`, and `close` back-patches it with
the bytes written since:

```cpp
const auto block = w.open_u16();          // nullopt, writer poisoned, if it does not fit
w.u8(0x0A);
const auto body = w.open_u16();
w.bytes(payload);
w.close(*body, bytespan::endian::big);    // innermost first
w.close(*block, bytespan::endian::big);
```

A slot is a plain value — the field's offset, its width, the buffer it was
reserved in, and the slot that was innermost when it opened — so nesting is a
chain of locals and needs no allocation and has no fixed depth. The writer
remembers only the innermost offset, which is enough to identify a slot because
offsets only grow and no two slots of one writer can share one. A close that
does not name that slot is `bad_slot`: an outer block closed before the inner
one, the same slot closed twice, or a slot opened on another buffer. A body too
large for the field to count is `too_long` and leaves the field's zeros alone.
`view()` makes no promise about open slots — a field whose close never came is
still the zeros `open` reserved it with, because the writer cannot tell a caller
who is finished from one who is not.

**An integer overflow turning into a read.** A 32-bit length on a 32-bit
`size_t` can wrap; the bounds check is against the real remaining size, so a
wrapped length cannot become a huge `memcpy`.

**A varint with more than one spelling.** `varint_u64` reads unsigned LEB128 —
seven bits a byte, low group first — and accepts only the canonical encoding,
because a value that can be written two ways is a value two parsers can
disagree about. A tenth byte above `0x01` would set bits past the top of the
type and is `overflow`, and an eleventh byte needs a tenth that continued, so
it is caught by the same test; a padded tail, `0x80 0x00` for zero, is
`non_canonical`. Each byte is judged as it is read, there is no lenient mode,
and a refusal leaves the cursor at the varint's first byte. Neither reason
reports two sizes, because no size was the problem: `wanted` is zero and
`available` counts the bytes examined. A varint the input ends inside is
ordinary `short_input`, wanting one group more than it had seen. The writer
emits the minimal encoding all or nothing, so a buffer too small leaves
`written()` where it stood rather than half a varint for someone to read back.

**Bytes nobody asked for.** `expect_end()` is true only when the cursor is
still `ok()` and sits exactly at the end of the input. Trailing bytes poison it
like any other failure — `trailing_bytes`, with the count of what was left over
as `available` — and a cursor that already failed is refused too, keeping its
own earlier refusal, because its `remaining()` is zero for the opposite reason.
It joins the run of reads and is covered by the same single `ok()`:

```cpp
const auto type    = r.u8();
const auto version = r.u16(bytespan::endian::big);
r.expect_end();

if (!r.ok()) return std::nullopt;   // short, long, or mangled — all one check
```

**Silent endianness.** Byte order is a parameter, never a default. A parser that
happens to work on this machine is not a parser.

## What it says when it refused

`ok()` is enough to decide what to do; it is not enough to write the log line.
So the cursor keeps the refusal — which field, why, and the two sizes that
disagreed:

```cpp
if (const auto why = r.refused()) {        // nullopt while ok()
    why->offset;     // first byte of the field that was refused
    why->why;        // short_input, trailing_bytes, overflow or non_canonical
                     // when reading; no_room, too_long or bad_slot when writing
    why->wanted;     // bytes the field needed
    why->available;  // bytes actually left from that offset
}
```

The **first** refusal, never the last. Once the cursor is poisoned every later
call fails as a consequence, and letting those consequences overwrite the record
would bury the one failure that explains the parse — a header that died on a
truncated `u32` should not end up reporting the `u8` that followed it.

The sizes belong to the field, not to the call that happened to notice. A
refused length-prefixed read reports the offset of the prefix and `prefix width
+ declared length`, so a header claiming 65535 bytes of payload in a 4-byte
input says it wanted 65537 and had 4. On the writer, an overrun is `no_room`
with the room that was left, while a payload too big to count in its prefix is
`too_long` with the prefix maximum — 65535 or 4294967295 — as what was
available, because room was never the problem. A `bad_slot` refusal reports no
sizes at all and names the offset the writer had reached, since the slot's own
offset may name a position in someone else's buffer.

## Where the cursor stops

A refusal is a position as much as a reason. `offset()` and `refused()->offset`
agree, and both name the **first byte of the field that was refused**: the
prefix for a length-prefixed read, the first group for a varint, the first byte
of the integer for a plain `u32`. Never a position inside the field. A
length-prefixed read that got its count and then found the payload short rewinds
to the prefix, so the offset names the field rather than the point at which the
lie became visible — `expect_end` is the one refusal with no field of its own,
and it reports the first byte nobody asked for.

```cpp
const auto input = raw({0x16, 0x03, 0x03, 0xFF, 0xFF, 0xAA});
bytespan::reader r{input};

const auto type    = r.u8();                                       // 0x16
const auto version = r.u16(bytespan::endian::big);                  // 0x0303
const auto payload = r.length_prefixed_u16(bytespan::endian::big);  // refused

const auto why = *r.refused();
std::printf("refused at %zu: wanted %zu, had %zu\n", why.offset, why.wanted,
            why.available);
// refused at 3: wanted 65537, had 3

r.offset();     // 3 — the prefix, not the two bytes of it that were read
r.remaining();  // 0
```

And it stays there. The cursor is poisoned for good: every later call fails,
`remaining()` is zero, the record keeps that first refusal, and `offset()` never
moves again. A refused parse has one position and one explanation for as long as
the reader exists.

**Why it never resumes.** There is no `retry()` and no way to feed the reader
more bytes. A parser that receives the rest of the record builds a new reader
over the whole record and parses it from the start. That is deliberate: resuming
on partial input is precisely where length checks get skipped, because a cursor
that remembers it was halfway through a field has to trust the half it already
read — the declared length, the groups of a varint — against bytes that had not
arrived when it was checked. Reassembling a stream into records is the caller's
job, and framing is outside this library's scope; a reader is a cursor over a
buffer that is all there.

## What the compiler checks

The reader is `constexpr` throughout, so a parse of a `constexpr` input is
evaluated while the file is being compiled. Core-language undefined behaviour
cannot be reached during constant evaluation: a read that walked off the end of
the span would be a compile error instead, on every compiler, with or without
sanitizers. The `static_assert` block at the top of `tests/test_bytespan.cpp`
uses that — a truncated `u32`, a length prefix that lies, an honest one, a
trailing byte, a padded varint — and it covers exactly those inputs, not all
inputs. The runtime tests still do the rest.

An integer is assembled from its bytes in the order that was asked for, rather
than copied in and swapped, so the reader never consults the host's byte order
at all.

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

**Not a streaming parser.** A reader is given the bytes it will ever have. A
refusal is final rather than a request for more, and deframing a socket into
records happens above this library, not inside it.

**Not a substitute for the sanitizers.** The tests run under
`-fsanitize=address,undefined`, because a bounds-checking library that is only
checked by its own assertions has proved nothing.

**Not `std::byteswap`.** That is C++23; the writer reverses the bytes by hand to
stay at C++20, where most projects that need this actually are. Every compiler
recognises the pattern.

## Status

Early, and small on purpose.

| | |
|---|---|
| Reading | `u8`/`u16`/`u32`/`u64` in either byte order, raw spans, `skip`, length-prefixed payloads, canonical `varint_u64`, `expect_end` — all `constexpr` |
| Writing | the same set, bounds-checked, with a prefix and its payload written in one call, plus length slots reserved and back-patched for bodies whose size is not known yet, and a view of what was written |
| Refusing | reading: short input, trailing bytes, varints that are non-canonical or overflow 64 bits. Writing: no room, a payload too long to count in its prefix or slot, a slot closed out of order, twice, or on another buffer |
| Reporting | `refused()`: the first refusal, with the offset of the field it refused, the reason, and the sizes that disagreed |
| Resuming | not a feature — a refused cursor stays refused, and more bytes mean a new reader over the whole record |
| Checking | runtime tests under ASan and UBSan, a sweep over every three-call sequence of reader calls, and a `static_assert` block the compiler evaluates |
| Not yet | signed integers, floating point, bit-level fields, a `constexpr` writer, `std::expected` return type for C++23 users |

## Development

```bash
make test   # under AddressSanitizer and UndefinedBehaviorSanitizer
make demo
```

## License

MIT

Maintained by [polycratia](https://polycratia.com).
