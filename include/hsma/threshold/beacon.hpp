// HSMA :: threshold/beacon.hpp — epoch beacon (Step 9, DEC-192).
// HSM_BEACON_V1 || epoch || prev -> h2g1 -> threshold-sign (t-of-n) ->
// SHA-256(affine sigma) -> consensus::Digest. SAME (epoch, prev)->Digest
// interface as sim_beacon (types, not values). sim_beacon remains in force;
// its retirement is an explicit swap decision with golden regeneration.
// Phase-0 API models the harness: the Committee carries the t-subset shares;
// production splits into per-member partials + permissionless aggregation.
#pragma once
#include <hsma/consensus.hpp>
#include <hsma/threshold/h2g1.hpp>
#include <hsma/threshold/sig.hpp>
#include <hsma/threshold/poly.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace hsma::threshold::beacon {

struct Committee {
    std::vector<std::uint64_t> ids;    // participating t-subset
    std::vector<Fr> shares;            // S_j aligned with ids
};

inline bool serialize(const g1::Pt& P, std::uint8_t out[96]) {
    std::uint64_t x[6], y[6];
    if (!g1::to_affine(P, x, y)) return false;
    for (int k = 0; k < 6; ++k)
        for (int b = 0; b < 8; ++b) {
            out[k * 8 + b]    = std::uint8_t(x[k] >> (8 * b));
            out[48 + k * 8 + b] = std::uint8_t(y[k] >> (8 * b));
        }
    return true;
}

inline consensus::Digest epoch_beacon(const Committee& c, std::uint64_t epoch,
                                      const consensus::Digest& prev) {
    static constexpr char TAG[] = "HSM_BEACON_V1";   // 13 chars (sizeof-1, never hand-counted: CA-R43)
    std::uint8_t pre[13 + 8 + 32];                   // exact 53
    std::memcpy(pre, TAG, sizeof(TAG) - 1);          // NUL excluded
    for (int i = 0; i < 8; ++i) pre[13 + i] = std::uint8_t(epoch >> (8 * i));
    prev.to_bytes(pre + 21);

    const g1::Pt H = hash_to_g1(pre, sizeof pre);
    std::vector<Fr> xs(c.ids.size());
    for (std::size_t i = 0; i < c.ids.size(); ++i)
        if (!fr_from_u64(xs[i], c.ids[i])) {
            std::fprintf(stderr, "FATAL: beacon id >= r\n"); std::abort();
        }
    std::vector<Fr> lam;
    if (!lagrange_zero(lam, xs)) {
        std::fprintf(stderr, "FATAL: beacon ids not distinct\n"); std::abort();
    }
    std::vector<g1::Pt> parts;
    parts.reserve(c.ids.size());
    for (std::size_t i = 0; i < c.ids.size(); ++i)
        parts.push_back(sig::partial(c.shares[i], H));
    const g1::Pt s = sig::aggregate(lam, parts);

    std::uint8_t ser[96];
    if (!serialize(s, ser)) {
        std::fprintf(stderr, "FATAL: beacon sigma at infinity\n"); std::abort();
    }
    std::uint8_t d[32];
    digest::Sha256 h;
    h.update(ser, 96);
    h.finish(d);
    return consensus::Digest::from_bytes(d);
}

inline consensus::Digest genesis(std::uint64_t epoch, const Committee& c) {
    const std::uint8_t z[32] = {};
    return epoch_beacon(c, epoch, consensus::Digest::from_bytes(z));
}

} // namespace hsma::threshold::beacon
