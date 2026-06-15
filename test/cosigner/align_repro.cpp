/*
 * align_repro.cpp — hit the ring_pedersen misaligned-uint32 bug through the real
 * cosigner setup API, single-threaded.
 *
 * ring_pedersen_public_(de)serialize_internal (ring_pedersen.c) access their
 * 4-byte length fields with `*(uint32_t*)p` after variable-length BN_bn2bin()
 * payloads. BN_bn2bin strips leading zeros, so the cursor is misaligned whenever
 * a preceding bignum length isn't a multiple of 4 — UB, SIGBUS on strict-align
 * targets, purely data-dependent (no threads needed).
 *
 * generate_setup_commitments serializes a fresh ring_pedersen key per call, and
 * the misalignment needs a non-4-aligned bignum length (~1 in a few hundred), so
 * we loop (count via argv[1]). Run under UBSan; expect a report at
 * ring_pedersen.c:248 via serialize_auxiliary_keys. The deterministic gate is
 * the unit test test/crypto/ring_pedersen_alignment.
 */
#include "cosigner/cmp_setup_service.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "cosigner/types.h"

#include <openssl/rand.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace fireblocks::common::cosigner;

namespace {

constexpr const char *kTenant = "repro-tenant";
constexpr uint64_t    kSelfId = 1;
constexpr uint64_t    kPeerId = 2;
constexpr int         kDefaultIterations = 512;

/* Minimal platform_service: just enough for generate_setup_commitments to reach
 * the serializer. Encryption is identity; randomness comes from OpenSSL. */
class repro_platform : public platform_service {
public:
    void gen_random(size_t len, uint8_t *out) const override { RAND_bytes(out, static_cast<int>(len)); }
    const std::string get_current_tenantid() const override { return kTenant; }
    uint64_t get_id_from_keyid(const std::string &) const override { return kSelfId; }

    void derive_initial_share(const share_derivation_args &, cosigner_sign_algorithm,
                              elliptic_curve256_scalar_t *key) const override {
        RAND_bytes(*key, sizeof(elliptic_curve256_scalar_t));
    }

    byte_vector_t encrypt_for_player(uint64_t, const byte_vector_t &data,
                                     const std::optional<std::string> & = std::nullopt) const override { return data; }
    byte_vector_t decrypt_message(const byte_vector_t &data) const override { return data; }

    bool backup_key(const std::string &, cosigner_sign_algorithm, const elliptic_curve256_scalar_t &,
                    const cmp_key_metadata &, const auxiliary_keys &) override { return true; }

    bool is_client_id(uint64_t id) const override { return id == kPeerId; }

    uint64_t now_msec() const override {
        using namespace std::chrono;
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }

    /* Required overrides, not reached on the setup path. */
    void on_start_signing(const std::string &, const std::string &, const signing_data &,
                          const std::string &, const std::set<std::string> &, signing_type) override {}
    void prepare_for_signing(const std::string &, const std::string) override {}
    void fill_signing_info_from_metadata(const std::string &, std::vector<uint32_t> &) const override {}
    void fill_eddsa_signing_info_from_metadata(std::vector<eddsa_signature_data> &, const std::string &) const override {}
    void fill_bam_signing_info_from_metadata(std::vector<bam_signing_properties> &, const std::string &) const override {}
    void mark_key_setup_in_progress(const std::string &) const override {}
    void clear_key_setup_in_progress(const std::string &) const override {}
};

/* Minimal in-memory key store. Single-threaded, so no locking. */
class repro_persistency : public cmp_setup_service::setup_key_persistency {
public:
    bool key_exist(const std::string &id) const override { return _keys.count(id) != 0; }

    void load_key(const std::string &id, cosigner_sign_algorithm &algo,
                  elliptic_curve256_scalar_t &key) const override {
        auto it = _keys.find(id);
        if (it == _keys.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
        algo = it->second.algo;
        std::memcpy(key, it->second.key, sizeof(elliptic_curve256_scalar_t));
    }

    const std::string get_tenantid_from_keyid(const std::string &) const override { return kTenant; }

    void load_key_metadata(const std::string &id, cmp_key_metadata &md, bool /*full_load*/) const override {
        auto it = _meta.find(id);
        if (it == _meta.end() || !it->second.metadata) throw cosigner_exception(cosigner_exception::BAD_KEY);
        md = *it->second.metadata;
    }

    void load_auxiliary_keys(const std::string &id, auxiliary_keys &aux) const override {
        auto it = _meta.find(id);
        if (it == _meta.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
        aux = it->second.aux;
    }

    void store_key(const std::string &id, cosigner_sign_algorithm algo,
                   const elliptic_curve256_scalar_t &key, uint64_t /*ttl*/) override {
        auto &info = _keys[id];
        info.algo = algo;
        std::memcpy(info.key, key, sizeof(elliptic_curve256_scalar_t));
    }

    void store_key_metadata(const std::string &id, const cmp_key_metadata &md, bool allow_override) override {
        auto &slot = _meta[id];
        if (slot.metadata && !allow_override) throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        slot.metadata = md;
    }

    void store_auxiliary_keys(const std::string &id, const auxiliary_keys &aux) override { _meta[id].aux = aux; }

    void store_keyid_tenant_id(const std::string &, const std::string &) override {}

    void store_setup_data(const std::string &id, const setup_data &sd, bool override_flag) override {
        if (_setup_data.count(id) && !override_flag) throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        _setup_data[id] = sd;
    }

    void load_setup_data(const std::string &id, setup_data &sd) override {
        auto it = _setup_data.find(id);
        if (it == _setup_data.end()) throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        sd = it->second;
    }

    void store_setup_commitments(const std::string &id, const std::map<uint64_t, commitment> &c) override {
        if (_commits.count(id)) throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        _commits[id] = c;
    }

    void load_setup_commitments(const std::string &id, std::map<uint64_t, commitment> &c) override { c = _commits[id]; }

    void delete_temporary_key_data(const std::string &id, bool delete_key) override {
        _setup_data.erase(id);
        _commits.erase(id);
        if (delete_key) { _meta.erase(id); _keys.erase(id); }
    }

private:
    struct key_info  { cosigner_sign_algorithm algo; uint8_t key[sizeof(elliptic_curve256_scalar_t)]; };
    struct meta_info { std::optional<cmp_key_metadata> metadata; auxiliary_keys aux; };
    std::map<std::string, key_info>                       _keys;
    std::map<std::string, meta_info>                      _meta;
    std::map<std::string, setup_data>                     _setup_data;
    std::map<std::string, std::map<uint64_t, commitment>> _commits;
};

} // namespace

int main(int argc, char **argv)
{
    const int iterations = (argc > 1) ? std::atoi(argv[1]) : kDefaultIterations;
    std::fprintf(stderr,
        "align_repro: %d iterations of generate_setup_commitments(EDDSA_ED25519); "
        "under UBSan watch for a misaligned-uint32 report at ring_pedersen.c\n", iterations);

    repro_platform    platform;
    repro_persistency persistency;
    cmp_setup_service service(platform, persistency);

    try {
        for (int i = 0; i < iterations; ++i) {
            std::vector<uint64_t> players{ kSelfId, kPeerId };
            commitment commit;
            service.generate_setup_commitments(
                "key-" + std::to_string(i), kTenant, EDDSA_ED25519,
                players, static_cast<uint8_t>(players.size()), /*ttl=*/0, /*derive=*/{}, commit);
        }
    } catch (const std::exception &e) {
        std::fprintf(stderr, "align_repro: setup threw: %s\n", e.what());
        return 2;
    }

    std::fprintf(stderr, "align_repro: completed %d iterations\n", iterations);
    return 0;
}
