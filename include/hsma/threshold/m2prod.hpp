// HSMA :: threshold/m2prod.hpp — M2 production hardening (Step 13, DEC-204..206).
// sigma_user: the sender's envelope authorization (BLS-style: G1 sig 48B / G2 pk,
// verification = the 10-B law). Partials: per-member signing + permissionless
// id-driven aggregation — the harness Committee retires to golden generation.
// Tags derived via sizeof-1 (CA-R43); DEC-127; DEC-090.
#pragma once
#include <hsma/threshold/m2.hpp>
#include <hsma/threshold/h2g1.hpp>
#include <hsma/threshold/sig.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/pairing.hpp>
#include <hsma/threshold/beacon.hpp>
#include <vector>
#include <cstring>

namespace hsma::threshold::m2prod {

static constexpr char TAG_SU[] = "HSM_SIG_USER_V1";   // 16 chars

// preimage: TAG(15, sizeof-derived) | header(56) | ser(R)(192) = 263 B
// CA-R64: "HSM_SIG_USER_V1" is 15 chars; ALL offsets derived, never hand-counted.
inline bool user_preimage(std::uint8_t out[263], std::uint64_t epoch,
                          const std::uint8_t sender[32], std::uint64_t nonce,
                          std::uint64_t fee, const g2::G2Pt& R) {
    constexpr std::size_t TAGL = sizeof(TAG_SU) - 1;   // 15, derived
    std::memcpy(out, TAG_SU, TAGL);
    m2::ser_hdr(out + TAGL, epoch, sender, nonce, fee);
    return m2::ser_g2(R, out + TAGL + 56);
}

inline g1::Pt user_attest(const Fr& sk_u, std::uint64_t epoch,
                          const std::uint8_t sender[32], std::uint64_t nonce,
                          std::uint64_t fee, const g2::G2Pt& R) {
    std::uint8_t pre[263];
    if (!user_preimage(pre, epoch, sender, nonce, fee, R)) return g1::Pt{};
    return sig::partial(sk_u, hash_to_g1(pre, sizeof pre));
}

// e(sigma_user, G2gen) == e(H(pre), PK_u)  — the 10-B law, verbatim reuse
inline bool user_verify(const g1::Pt& sig, const g2::G2Pt& PK_u,
                        std::uint64_t epoch, const std::uint8_t sender[32],
                        std::uint64_t nonce, std::uint64_t fee, const g2::G2Pt& R) {
    std::uint8_t pre[263];
    if (!user_preimage(pre, epoch, sender, nonce, fee, R)) return false;
    const g1::Pt H = hash_to_g1(pre, sizeof pre);
    std::uint64_t sx[6], sy[6], hx[6], hy[6];
    if (!g1::to_affine(sig, sx, sy)) return false;
    if (!g1::to_affine(H, hx, hy)) return false;
    return bls_verify_aff(sx, sy, hx, hy, PK_u);
}

// ── per-member partials + permissionless aggregation (DEC-205) ──
struct PartialSig {
    std::uint64_t id;   // the member's validator id (the Lagrange x-coordinate)
    g1::Pt sig;         // the member's partial: [S_j]H(m) — computed alone
};

inline PartialSig member_partial(const Fr& sk_j, std::uint64_t id, const g1::Pt& H) {
    return PartialSig{id, sig::partial(sk_j, H)};
}

// The aggregator computes lambda from the SUBMITTED ids — no committee struct,
// no co-located shares. Duplicate ids rejected by lagrange_zero.
inline g1::Pt aggregate_partials(const std::vector<PartialSig>& ps) {
    std::vector<Fr> xs(ps.size());
    for (std::size_t i = 0; i < ps.size(); ++i)
        if (!fr_from_u64(xs[i], ps[i].id)) return g1::Pt{};
    std::vector<Fr> lam;
    if (!lagrange_zero(lam, xs)) return g1::Pt{};
    std::vector<g1::Pt> sigs;
    sigs.reserve(ps.size());
    for (const auto& p : ps) sigs.push_back(p.sig);
    return sig::aggregate(lam, sigs);
}

// the production beacon: the members' partials over H(beacon-pre), aggregated
// by anyone, serialized, hashed — the beacon.hpp harness path's sibling.
inline consensus::Digest beacon_from_partials(const std::vector<PartialSig>& ps,
                                              std::uint64_t epoch,
                                              const consensus::Digest& prev) {
    const g1::Pt s = aggregate_partials(ps);
    std::uint8_t ser[96];
    if (!beacon::serialize(s, ser)) return consensus::Digest{};
    std::uint8_t d[32];
    digest::Sha256 h;
    h.update(ser, 96);
    h.finish(d);
    return consensus::Digest::from_bytes(d);
}

} // namespace hsma::threshold::m2prod
