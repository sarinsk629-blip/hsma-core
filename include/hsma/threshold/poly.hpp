// HSMA :: threshold/poly.hpp - DKG scalar semantics (Step 7, DEC-184).
// Degree-(t-1) polys over F_r; Horner; Lagrange-at-zero over id domain {1..n}.
// Feldman commitments (G1) land at Step 9.
#pragma once
#include <hsma/threshold/scalar_r.hpp>
#include <vector>

namespace hsma::threshold {

struct Poly {
    std::vector<Fr> c;                        // c[0] = secret term; degree = c.size() - 1
};

inline Fr poly_eval(const Poly& p, const Fr& x) {
    if (p.c.empty()) return Fr{};
    Fr acc = p.c.back();
    for (std::size_t k = p.c.size() - 1; k-- > 0; )
        acc = fr_add(fr_mul(acc, x), p.c[k]);
    return acc;
}

// lam[i] = L_i(0) = prod_{j != i} (-x_j) / (x_i - x_j); false on duplicate points.
inline bool lagrange_zero(std::vector<Fr>& lam, const std::vector<Fr>& xs) {
    const std::size_t n = xs.size();
    lam.assign(n, fr_one());
    for (std::size_t i = 0; i < n; ++i) {
        for (std::size_t j = 0; j < n; ++j) {
            if (i == j) continue;
            const Fr den = fr_sub(xs[i], xs[j]);
            if (den.is_zero()) return false;  // duplicate evaluation point
            Fr dinv;
            if (!fr_inv(dinv, den)) return false;
            lam[i] = fr_mul(lam[i], fr_mul(fr_neg(xs[j]), dinv));
        }
    }
    return true;
}

} // namespace hsma::threshold
