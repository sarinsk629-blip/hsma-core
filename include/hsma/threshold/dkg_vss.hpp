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

inline void digest_to_bytes(const consensus::Digest& d, std::uint8_t out[32]) {
    for (int w = 0; w < 4; ++w)
        for (int b = 0; b < 8; ++b)
            out[(w << 3) | b] = std::uint8_t(d[w] >> (8 * b));   // conform: Digest indexable
}

// Deterministic epoch seed. prev == nullptr for genesis epoch.
inline void epoch_seed(std::uint8_t out[32], std::uint64_t epoch,
                       const consensus::Digest* prev) {
    std::uint8_t buf[10 + 8 + 32];
    std::memcpy(buf, "HSM_DKG_V1", 10);
    for (int i = 0; i < 8; ++i) buf[10 + i] = std::uint8_t(epoch >> (8 * i));
    std::size_t len = 18;
    if (prev) { std::memcpy(buf + 18, *prev, 32); len = 50; }  // conform: Digest contiguous
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
    return g2::peq(rhs, Yj);        // ← CONFORM POINT: round-2 grep names the real equality
}

// A member proves its OWN share is the committed one (no trusted-dealer trust).
inline bool verify_own(const Transcript& T, std::uint64_t j, const mont::fe6& s_scalar) {
    return verify_share(T, j, g2::Pmul(g2::gen(), s_scalar));
}

} // namespace hsma::threshold::vss
