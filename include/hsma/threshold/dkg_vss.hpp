#pragma once
// HSMA :: threshold/dkg_vss.hpp — P5-A: beacon-seeded Feldman VSS + per-epoch rotation.
// Parameters become CODE CHECKS (config_ok) — the committee-collusion waiver closes
// mechanically when n=224,t=112 flips on at the capstone.
// Share verification needs NO pairing: [f(j)]G2 == Prod_k C_k^(j^k), Horner in the exponent.
// Seed chain conforms to threshold/beacon.hpp (DEC-192): epoch 0 = H("HSM_DKG_V1"||LE64(0));
// epoch E>0 = sim_beacon(E, prev) once the threshold beacon signs rotation (P5-C).
#include <hsma/consensus.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <cstdio>
#include <cstring>
#include <vector>

namespace hsma::threshold::vss {

struct Transcript {
    std::uint64_t n = 0, t = 0, epoch = 0;
    Poly f{};                       // degree t-1; f(0) = epoch secret
    std::vector<g2::G2Pt> C;        // Feldman commitments C_k = [c_k]G2gen
    std::vector<g2::G2Pt> Y;        // member publics Y_j = [f(j)]G2gen, j = 1..n
};

// The parameter law, in code: honest threshold t > n/2, t >= 2, production ceiling 224.
inline bool config_ok(std::uint64_t n, std::uint64_t t) {
    return t >= 2 && n >= t && (2 * t) > n && n <= 224;
}

static_assert(sizeof(consensus::Digest) == 32, "P5-A conform: Digest expected 32 bytes");
inline void digest_to_bytes(const consensus::Digest& d, std::uint8_t out[32]) {
    std::memcpy(out, &d, 32);          // opaque conform: struct is 32B standard layout
}

// Deterministic epoch seed. prev == nullptr for genesis epoch.
inline void epoch_seed(std::uint8_t out[32], std::uint64_t epoch,
                       const consensus::Digest* prev) {
    std::uint8_t buf[10 + 8 + 32];
    std::memcpy(buf, "HSM_DKG_V1", 10);
    for (int i = 0; i < 8; ++i) buf[10 + i] = std::uint8_t(epoch >> (8 * i));
    std::size_t len = 18;
    if (prev) { std::memcpy(buf + 18, prev, 32); len = 50; }   // prev is Digest*
    consensus::Digest d = consensus::sha256d(buf, len);
    digest_to_bytes(d, out);
}

inline bool deal(Transcript& T, std::uint64_t epoch, std::uint64_t n, std::uint64_t t,
                 const consensus::Digest* prev = nullptr) {
    if (!config_ok(n, t)) {
        std::fprintf(stderr, "[dkg] config REJECTED n=%llu t=%llu (law: t>=2, t>n/2, n<=224)\n",
                     (unsigned long long)n, (unsigned long long)t);
        return false;
    }
    T.n = n; T.t = t; T.epoch = epoch;
    T.f.c.assign(t, Fr{});
    std::uint8_t seed[32];
    epoch_seed(seed, epoch, prev);
    for (std::uint64_t k = 0; k < t; ++k) {           // c_k = LE64(H(seed || k)[0..8])
        std::uint8_t buf[33];
        std::memcpy(buf, seed, 32);
        buf[32] = std::uint8_t(k);
        consensus::Digest d = consensus::sha256d(buf, sizeof buf);
        std::uint8_t db[32];
        digest_to_bytes(d, db);
        std::uint64_t w = 0;
        for (int i = 0; i < 8; ++i) w |= std::uint64_t(db[i]) << (8 * i);
        if (!fr_from_u64(T.f.c[k], w)) return false;
    }
    T.C.assign(t, g2::G2Pt{});
    for (std::uint64_t k = 0; k < t; ++k) {
        mont::fe6 kk{};
        fr_to_fe6(T.f.c[k], kk);
        T.C[k] = g2::Pmul(g2::gen(), kk);
    }
    T.Y.assign(n + 1, g2::gen());
    for (std::uint64_t j = 1; j <= n; ++j) {
        Fr sj = dkg::share_for(T.f, j);
        mont::fe6 k{};
        fr_to_fe6(sj, k);
        T.Y[j] = g2::Pmul(g2::gen(), k);
    }
    return true;
}

// G2 equality via affine coordinates (g2.hpp exposes to_affine, no Peq — DEC conform).
// to_affine returns false for infinity; both-infinity == equal.
inline bool pt_eq(const g2::G2Pt& A, const g2::G2Pt& B) {
    std::uint64_t ax0[6], ax1[6], ay0[6], ay1[6];
    std::uint64_t bx0[6], bx1[6], by0[6], by1[6];
    const bool aok = g2::to_affine(A, ax0, ax1, ay0, ay1);
    const bool bok = g2::to_affine(B, bx0, bx1, by0, by1);
    if (!aok && !bok) return true;
    if (aok != bok)   return false;
    return std::memcmp(ax0, bx0, sizeof ax0) == 0
        && std::memcmp(ax1, bx1, sizeof ax1) == 0
        && std::memcmp(ay0, by0, sizeof ay0) == 0
        && std::memcmp(ay1, by1, sizeof ay1) == 0;
}

// G2-only Feldman check, Horner: rhs = C_{t-1}; for k = t-2..0: rhs = [j]rhs + C_k.
// rhs == Y_j  iff  the share for member j is the committed polynomial's evaluation.
inline bool verify_share(const Transcript& T, std::uint64_t j, const g2::G2Pt& Yj) {
    if (j == 0 || j > T.n) return false;
    Fr jf{};
    if (!fr_from_u64(jf, j)) return false;
    mont::fe6 js{};
    fr_to_fe6(jf, js);
    g2::G2Pt rhs = T.C[T.t - 1];
    for (std::int64_t k = std::int64_t(T.t) - 2; k >= 0; --k)
        rhs = g2::Padd(g2::Pmul(rhs, js), T.C[k]);
    return pt_eq(rhs, Yj);          // affine-compare shim (no Peq in g2.hpp)
}

// A member proves its OWN share is the committed one (no trusted-dealer trust).
inline bool verify_own(const Transcript& T, std::uint64_t j, const mont::fe6& s_scalar) {
    return verify_share(T, j, g2::Pmul(g2::gen(), s_scalar));
}


// ---- P5-C: threshold decryption aggregation (t-of-n, Lagrange at x=0) ----
// D_j = [f(j)]R  (each member's contribution, computed via threshold::m2::dec_share)
// Aggregate: D = Sum_j lambda_j * D_j = [f(0)]R   — WITHOUT any member learning f(0).
// lambda_j = prod_{m != j} x_m / (x_m - x_j) over Fr, for the participating x-set.
// Requires exactly t participants (n=3, t=2 testnet: any 2 of 3).

// Lagrange coefficient for participant x_j over the full participating x-set.
inline Fr lagrange_at_zero(const std::vector<std::uint64_t>& xs, std::uint64_t xj) {
    Fr num{}, den{}, t{};
    fr_from_u64(num, 1); fr_from_u64(den, 1);
    for (std::uint64_t xm : xs) {
        if (xm == xj) continue;
        Fr fxm{}; fr_from_u64(fxm, xm);
        Fr fxj{}; fr_from_u64(fxj, xj);
        num = fr_mul(num, fxm);                 // num *= x_m
        t = fr_sub(fxm, fxj);                   // den *= (x_m - x_j)
        den = fr_mul(den, t);
    }
    Fr dinv{}; fr_inv(dinv, den);               // scalar_r.hpp API: bool fr_inv(Fr& out, const Fr& a)
    return fr_mul(num, dinv);                   // lambda_j = num * den^{-1}
}

// Aggregate t decryption-share POINTS into [f(0)]R (G2 points).
// shares: pairs of (member_id, D_j). Must contain exactly t entries.
inline bool agg_dec_share(g2::G2Pt& D_out,
                          const std::vector<std::pair<std::uint64_t, g2::G2Pt>>& shares) {
    if (shares.empty()) return false;
    std::vector<std::uint64_t> xs;
    for (const auto& [j, D] : shares) xs.push_back(j);
    if ((std::uint64_t)xs.size() != shares.size()) return false;
    bool first = true;
    for (const auto& [j, Dj] : shares) {
        Fr lam = lagrange_at_zero(xs, j);
        mont::fe6 lk{}; fr_to_fe6(lam, lk);
        g2::G2Pt term = g2::Pmul(Dj, lk);
        D_out = first ? term : g2::Padd(D_out, term);
        first = false;
    }
    return true;
}

} // namespace hsma::threshold::vss
