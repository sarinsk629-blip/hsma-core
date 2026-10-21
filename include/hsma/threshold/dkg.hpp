// HSMA :: threshold/dkg.hpp — Feldman DKG in G1 (Step 9, DEC-190).
// Commitments C_k = [a_k]G; share verification [s_j]G == sum_k [j^k]C_k —
// a pure G1 point equation, pairing-free (DEC-181). Dealer-side poly
// machinery is the Step 7 kernel (Poly/Horner/lagrange_zero).
#pragma once
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/g1.hpp>
#include <hsma/threshold/interop.hpp>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace hsma::threshold::dkg {

inline std::vector<g1::Pt> commit(const Poly& p) {
    std::vector<g1::Pt> cs;
    cs.reserve(p.c.size());
    for (const Fr& a : p.c) {
        mont::fe6 k{}; fr_to_fe6(a, k);
        cs.push_back(g1::Pmul(g1::gen(), k));
    }
    return cs;
}

inline Fr share_for(const Poly& p, std::uint64_t j) {
    Fr x{};
    if (!fr_from_u64(x, j)) { std::fprintf(stderr, "FATAL: id >= r\n"); std::abort(); }
    return poly_eval(p, x);
}

inline bool verify_share(std::uint64_t j, const Fr& s_j,
                         const std::vector<g1::Pt>& C) {
    Fr jx{};
    if (!fr_from_u64(jx, j)) return false;
    mont::fe6 sj{}; fr_to_fe6(s_j, sj);
    g1::Pt lhs = g1::Pmul(g1::gen(), sj);
    g1::Pt rhs{};                                   // infinity
    Fr jk; fr_from_u64(jk, 1);
    for (std::size_t k = 0; k < C.size(); ++k) {
        if (k > 0) jk = fr_mul(jk, jx);             // j^k mod r
        mont::fe6 kk{}; fr_to_fe6(jk, kk);
        rhs = g1::Padd(rhs, g1::Pmul(C[k], kk));
    }
    std::uint64_t xa[6], ya[6], xb[6], yb[6];
    if (!g1::to_affine(lhs, xa, ya)) return false;
    if (!g1::to_affine(rhs, xb, yb)) return false;
    return mont::bn_cmp(xa, xb, 6) == 0 && mont::bn_cmp(ya, yb, 6) == 0;
}

// Aggregate public key: Y = sum_i C_{i,0} = [sum_i a_{i,0}]G = [S]G.
inline g1::Pt aggregate_pk(const std::vector<std::vector<g1::Pt>>& all) {
    g1::Pt y{};
    for (const auto& c : all) if (!c.empty()) y = g1::Padd(y, c[0]);
    return y;
}

} // namespace hsma::threshold::dkg
