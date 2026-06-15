/*
 * Reproducer for the misaligned-uint32 read in damgard_fujisaki's deserializer.
 * damgard_fujisaki_public_deserialize_internal (damgard_fujisaki.c:691) reads the
 * dimension field with `*(const uint32_t*)pos` at offset 4 + n_len, and n_len is
 * taken straight off the wire with no multiple-of-4 check (only n_len > 8192 is
 * rejected). A crafted n_len % 4 != 0 lands the read off alignment — UB, and
 * SIGBUS on strict-alignment targets, reachable through the public API with
 * attacker-controlled input. (The serializer at line 631 has the same shape for
 * a modulus whose byte length isn't a multiple of 4.)
 *
 * Build under UBSan (-fsanitize=undefined): expect "misaligned address ...
 * 'uint32_t'" at damgard_fujisaki.c:691. The assertion only checks that the
 * crafted buffer is rejected; UBSan is the signal. Fix: read the field via memcpy.
 */
#include "crypto/commitments/damgard_fujisaki.h"

#include <tests/catch.hpp>

#include <cstdint>
#include <vector>

namespace {

void put_u32_le(std::vector<uint8_t> &buf, size_t off, uint32_t v) {
    buf[off + 0] = static_cast<uint8_t>( v        & 0xff);
    buf[off + 1] = static_cast<uint8_t>((v >>  8) & 0xff);
    buf[off + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
    buf[off + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

} // namespace

// Wire: [u32 n_len][n_len-byte n][u32 dimension]. deserialize advances pos by
// 4 + n_len before reading dimension, so a non-4-aligned n_len misaligns that read.
TEST_CASE("damgard_fujisaki deserialize: misaligned uint32 read after non-4-aligned modulus") {
    const uint32_t n_len = 255;   // dimension read lands at offset 4 + 255 = 259 (mod 4 == 3)
    std::vector<uint8_t> wire(sizeof(uint32_t) + n_len + sizeof(uint32_t), 0);
    put_u32_le(wire, 0, n_len);
    wire[sizeof(uint32_t)] = 0x7F;                      // n: top byte nonzero
    put_u32_le(wire, sizeof(uint32_t) + n_len, 1);      // dimension = 1

    // Too short for the full object, so deserialize returns NULL — but only after
    // the misaligned dimension read at damgard_fujisaki.c:691.
    damgard_fujisaki_public_t *pub =
        damgard_fujisaki_public_deserialize(wire.data(), static_cast<uint32_t>(wire.size()));
    REQUIRE(pub == nullptr);
}
