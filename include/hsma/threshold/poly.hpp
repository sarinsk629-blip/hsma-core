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

// P2 (production aggregation kernel): the SAME coefficients as lagrange_zero,
// bit-identical, but with ONE field inversion total (Montgomery's trick) instead
// of one per point. The per-point products stay O(n^2) multiplications (inherent
// to exact Lagrange); the inversions — 256-step Fermat each, the real cost —
// collapse from n to 1. At t=112: 12,432 inversions -> 1.
// lam[i] = num[i] * inv(den[i]) with num[i] = prod_{j!=i}(-x_j),
// den[i] = prod_{j!=i}(x_i - x_j); field associativity makes the batched
// product identical to the per-factor product mod r.
inline bool lagrange_zero_batch(std::vector<Fr>& lam, const std::vector<Fr>& xs) {
    const std::size_t n = xs.size();
    lam.assign(n, fr_one());
    if (n == 0) return true;
    // numerators (no inversions): num[i] = prod_{j != i} (-x_j)
    for (std::size_t i = 0; i < n; ++i)
        for (std::size_t j = 0; j < n; ++j) {
            if (i == j) continue;
            lam[i] = fr_mul(lam[i], fr_neg(xs[j]));
        }
    // denominators: den[i] = prod_{j != i} (x_i - x_j)
    std::vector<Fr> den(n, fr_one());
    for (std::size_t i = 0; i < n; ++i)
        for (std::size_t j = 0; j < n; ++j) {
            if (i == j) continue;
            const Fr d = fr_sub(xs[i], xs[j]);
            if (d.is_zero()) return false;    // duplicate evaluation point
            den[i] = fr_mul(den[i], d);
        }
    // Montgomery's trick: prefix products, ONE inversion of the total, suffix walk.
    std::vector<Fr> pre(n, fr_one());
    Fr run = fr_one();
    for (std::size_t i = 0; i < n; ++i) { pre[i] = run; run = fr_mul(run, den[i]); }
    Fr itot;
    if (!fr_inv(itot, run)) return false;     // THE one inversion
    run = itot;                               // run now carries inv(prod_{m>i} den_m)
    for (std::size_t i = n; i-- > 0;) {
        lam[i] = fr_mul(lam[i], fr_mul(pre[i], run));   // num[i] * inv(den[i])
        run = fr_mul(run, den[i]);
    }
    return true;
}

} // namespace hsma::threshold
