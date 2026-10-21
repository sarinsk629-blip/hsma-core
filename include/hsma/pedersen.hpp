// HSMA :: pedersen.hpp - P1-09 (GAP-05 Layer 1, DEC-227).
// Dual-layer PCS, Layer 1: homomorphic Pedersen accumulators over the Pasta cycle.
// PedP: Pallas points (g1p); scalars = F_q canonical limbs (Pallas order = q).
// PedV: Vesta points (g2v);  scalars = F_p canonical limbs (Vesta order  = p).
// The 2-cycle property makes the scalar domains EXACT: no reduction, no
// cross-field collision risk (CA-R117 honored by construction).
// Base derivation (transparent, no new Poseidon domain, no trusted setup):
//   h_i = SHA256("HSMA_PEDERSEN_<CURVE>_H<i>") as little-endian u256,
//         reduced mod the group order (at most 2 conditional subtracts);
//         H_i = [h_i] * G.  Golden-pinned: scalar parity + point parity.
// Homomorphism: C(a,r1) + C(b,r2) = C(a+b, r1+r2)  (scalars mod the order).
// HONEST BOUNDARY: the opening proof is the WHIR-class wrap (P1-10, Layer 2);
// this layer supplies binding (DLP) + hiding (blinding) + homomorphism -
// exactly what HyperNova's commitment folding consumes.
#pragma once
#include <hsma/g1p.hpp>
#include <hsma/g2v.hpp>
#include <hsma/sha256.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace hsma::pedutil {
// 32 LE bytes -> scalar < ORDER. digest < 2^256, ORDER > 2^254.9, so at most
// 2 conditional subtracts; the loop is bounded at 4 with a trip-check.
inline bool scalar_from_digest(const std::uint8_t dg[32],
                               const std::uint64_t ORDER[4],
                               std::uint64_t out[4]) noexcept {
    for (int i = 0; i < 4; ++i) {
        out[i] = 0;
        for (int j = 0; j < 8; ++j) out[i] |= (std::uint64_t)dg[8*i + j] << (8*j);
    }
    for (int t = 0; t < 4; ++t) {
        bool geq = true;
        for (int i = 3; i >= 0; --i)
            if (out[i] != ORDER[i]) { geq = out[i] > ORDER[i]; break; }
        if (!geq) return true;
        std::uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            std::uint64_t bi = ORDER[i] + borrow;
            if (out[i] >= bi) { out[i] -= bi; borrow = 0; }
            else { out[i] -= bi; borrow = 1; }
        }
        if (t == 3) return false;   // would need a 5th pass: malformed input
    }
    return true;
}
} // namespace hsma::pedutil

namespace hsma::pedp {
using g1p::PtP;
inline PtP base_h(unsigned i, const std::uint64_t ORDER[4]) noexcept {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "HSMA_PEDERSEN_PALLAS_H%u", i);
    std::uint8_t dg[32];
    digest::sha256((const std::uint8_t*)buf, std::strlen(buf), dg);
    std::uint64_t h[4];
    pedutil::scalar_from_digest(dg, ORDER, h);
    return g1p::Vmul(g1p::generator(), h);
}
inline PtP commit(const std::uint64_t m[8][4], const std::uint64_t r[4],
                  const std::uint64_t ORDER[4]) noexcept {
    PtP C = g1p::Vmul(g1p::generator(), r);
    for (unsigned i = 0; i < 8; ++i)
        C = g1p::Vadd(C, g1p::Vmul(base_h(i, ORDER), m[i]));
    return C;
}
} // namespace hsma::pedp

namespace hsma::pedv {
using g2v::PtV;
inline PtV base_h(unsigned i, const std::uint64_t ORDER[4]) noexcept {
    char buf[40];
    std::snprintf(buf, sizeof(buf), "HSMA_PEDERSEN_VESTA_H%u", i);
    std::uint8_t dg[32];
    digest::sha256((const std::uint8_t*)buf, std::strlen(buf), dg);
    std::uint64_t h[4];
    pedutil::scalar_from_digest(dg, ORDER, h);
    return g2v::Vmul(g2v::generator(), h);
}
inline PtV commit(const std::uint64_t m[8][4], const std::uint64_t r[4],
                  const std::uint64_t ORDER[4]) noexcept {
    PtV C = g2v::Vmul(g2v::generator(), r);
    for (unsigned i = 0; i < 8; ++i)
        C = g2v::Vadd(C, g2v::Vmul(base_h(i, ORDER), m[i]));
    return C;
}

// P1-19 (DEC-263): vector commitment with PER-POSITION distinct bases.
// CA-R187: the 8-base batch commit repeats h_j every 8 positions - for
// n > 8, a delta at position i and -delta at position i+8 (same base)
// commits identically (kernel shift; demonstrated in p19probe [P3-forge]).
// Distinct bases per position close the kernel: forgery requires a
// multi-base representation break (DLP-hard).
inline PtV commit_vec(const std::vector<fp::fe>& v, const std::uint64_t r[4],
                      const std::uint64_t ORDER[4]) noexcept {
    PtV C = g2v::Vmul(g2v::generator(), r);
    for (unsigned k = 0; k < v.size(); ++k)
        C = g2v::Vadd(C, g2v::Vmul(base_h(k, ORDER), v[k].l.data()));
    return C;
}
} // namespace hsma::pedv
