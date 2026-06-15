/*
 * Reproducer for the misaligned-uint32 access in ring_pedersen's (de)serializer.
 * ring_pedersen_public_(de)serialize_internal (ring_pedersen.c) read/write their
 * 4-byte length fields with `*(uint32_t*)p` after variable-length BN payloads, so
 * the cursor is misaligned whenever a preceding bignum length isn't a multiple of
 * 4 — UB, and SIGBUS on strict-alignment targets.
 *
 * Each SECTION hand-builds a wire buffer whose byte counts force the next length
 * field off alignment, then round-trips it (deserialize -> serialize) via the
 * public API. Build under UBSan (-fsanitize=undefined): expect "misaligned
 * address ... 'uint32_t'" reports at ring_pedersen.c (a read in deserialize, a
 * write in serialize). The Catch assertions only check the round-trip; UBSan is
 * the signal. Fix: access the length fields with memcpy.
 */
#include "crypto/commitments/ring_pedersen.h"

#include <openssl/rand.h>

#include <tests/catch.hpp>

#include <cstdint>
#include <vector>

namespace {

// little-endian uint32 at off
void put_u32_le(std::vector<uint8_t> &buf, size_t off, uint32_t v) {
    buf[off + 0] = static_cast<uint8_t>( v        & 0xff);
    buf[off + 1] = static_cast<uint8_t>((v >>  8) & 0xff);
    buf[off + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
    buf[off + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

// random payload, top byte forced so the deserializer's s<=n / t<=n check passes
void fill_bn(std::vector<uint8_t> &buf, size_t off, uint32_t len, uint8_t top) {
    RAND_bytes(buf.data() + off, static_cast<int>(len));
    buf[off] = top;
}

// Build a wire buffer with all three bignums bn_bytes long, then round-trip it.
// When bn_bytes is not a multiple of 4, the s/t length fields land off-alignment.
void exercise(uint32_t bn_bytes) {
    const size_t total = 3 * (sizeof(uint32_t) + bn_bytes);
    std::vector<uint8_t> wire(total);

    size_t off = 0;
    put_u32_le(wire, off, bn_bytes);            off += sizeof(uint32_t);
    fill_bn(wire, off, bn_bytes, /*top=*/0x7F); off += bn_bytes;   // n: large
    put_u32_le(wire, off, bn_bytes);            off += sizeof(uint32_t);
    fill_bn(wire, off, bn_bytes, /*top=*/0x10); off += bn_bytes;   // s < n
    put_u32_le(wire, off, bn_bytes);            off += sizeof(uint32_t);
    fill_bn(wire, off, bn_bytes, /*top=*/0x10); off += bn_bytes;   // t < n
    REQUIRE(off == total);

    ring_pedersen_public_t *pub =
        ring_pedersen_public_deserialize(wire.data(), static_cast<uint32_t>(wire.size()));
    REQUIRE(pub != nullptr);

    std::vector<uint8_t> out(total);
    uint32_t written = 0;
    REQUIRE(ring_pedersen_public_serialize(pub, out.data(),
                                           static_cast<uint32_t>(out.size()), &written) != nullptr);
    REQUIRE(written == total);

    ring_pedersen_free_public(pub);
}

} // namespace

// Different byte counts misalign different length fields, re-arming UBSan's
// per-source-line dedup so both the read and write sites report.
TEST_CASE("ring_pedersen (de)serialize: misaligned uint32 after non-4-aligned BN payload") {
    SECTION("bn_bytes = 255") { exercise(255); }
    SECTION("bn_bytes = 257") { exercise(257); }
    SECTION("bn_bytes = 254") { exercise(254); }
}
