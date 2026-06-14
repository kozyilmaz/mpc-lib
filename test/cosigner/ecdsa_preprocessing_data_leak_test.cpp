/* Proves the leak / UB in
 * fireblocks::common::cosigner::ecdsa_preprocessing_data::~ecdsa_preprocessing_data()
 * (include/cosigner/cmp_ecdsa_signing_service.h).
 *
 * The destructor runs:  OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data))
 * `k` is the first member and elliptic_curve_scalar is just { data } at offset 0
 * (no vtable), so k.data == this. The cleanse therefore zeroes the WHOLE struct
 * — including the std::vector (mta_request) and the two std::map members — in the
 * destructor body, which runs *before* those members' own destructors. Each
 * container destructor then reads a zeroed control block and frees nothing, so
 * the heap buffers leak (reading a zeroed control block is UB besides). The
 * cleanse is also pointless: the secret scalars already self-wipe via
 * elliptic_curve_scalar's own destructor.
 *
 * No sanitizer needed: a global operator new / operator delete counts live heap
 * allocations. std::vector and std::map allocate through operator new, so a
 * correct destructor returns the count to zero; the buggy one leaves it positive
 * and the REQUIRE below fails. Replacing the global allocator is why this is its
 * own binary — the counter must not perturb the other cosigner tests. The fix
 * (drop the destructor; the scalars self-wipe) turns this green.
 */
#include <tests/catch.hpp>

#include "cosigner/cmp_ecdsa_signing_service.h"   // ecdsa_preprocessing_data, byte_vector_t

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

using namespace fireblocks::common::cosigner;

namespace {
std::atomic<long> g_live{0};
std::atomic<bool> g_tracking{false};
}

void *operator new(std::size_t n) {
    void *p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    if (g_tracking.load(std::memory_order_relaxed))
        g_live.fetch_add(1, std::memory_order_relaxed);
    return p;
}
void operator delete(void *p) noexcept {
    if (!p) return;
    if (g_tracking.load(std::memory_order_relaxed))
        g_live.fetch_sub(1, std::memory_order_relaxed);
    std::free(p);
}
void operator delete(void *p, std::size_t) noexcept { ::operator delete(p); }

TEST_CASE("ecdsa_preprocessing_data destructor leaks its std::vector/std::map members",
          "[cosigner][ecdsa_preproc_leak][leak]") {
    g_live.store(0, std::memory_order_relaxed);
    g_tracking.store(true, std::memory_order_relaxed);
    {
        ecdsa_preprocessing_data d;
        d.mta_request.assign(64, 0xAB);             // vector member -> 1 heap buffer
        d.G_proofs[1] = byte_vector_t(48, 0xCD);    // map node + inner buffer
        d.G_proofs[2] = byte_vector_t(48, 0xEF);    // map node + inner buffer
    }   // ~ecdsa_preprocessing_data zeroes the control blocks before the members'
        // destructors run -> nothing is freed -> the buffers leak.
    const long live = g_live.load(std::memory_order_relaxed);
    g_tracking.store(false, std::memory_order_relaxed);

    INFO("heap allocations still live after destruction: " << live
         << " (a correct destructor frees them all, leaving 0)");
    REQUIRE(live == 0);
}
