// HSMA :: mfold.hpp - P1-11 (GAP-06 core, DEC-229).
// The HyperNova multifold core over SPARSE R1CS in the Pallas field (F_p).
//   Relaxed instance: Az ∘ Bz = u*Cz + E   (fresh: u=1, E=0).
//   k-fold with FS challenges r_j:
//     T_j   = Az_U∘Bz_j + Az_j∘Bz_U - Cz_U - u_U*Cz_j      (cross-terms)
//     z_U'  = z_U + sum_j r_j z_j
//     u_U'  = u_U + sum_j r_j
//     E_U'  = E_U + sum_j r_j T_j
//   The folded relation holds EXACTLY for any r_j (the algebra identity) -
//   machine-checked at every fold, in both languages.
//   FS: seed = Sponge(HSM_SUMCHECK_v1) over (u_U, z_U, E_U, then per instance
//   u_j, z_j, T_j); r_j = P3(seed, j) - the derive_points pattern, golden-pinned.
// LAWS INHERITED: CA-R78 (LSB-first bit order), CA-R79/80 (d=2 products,
// p2=g(2)), CA-R133 (bit-order is a contract - the golden pins it),
// CA-R134 (negatives model the attack), CA-R126 (pre-emit self-check).
// HONEST BOUNDARY: dense witnesses at golden scale; commitment folding
// (Pedersen, DEC-227) + the multifold sumcheck over the constraint multiset
// = P1-12; circuit instantiation at epoch scale = P1-13 (GAP-07).
#pragma once
#include <hsma/pcs.hpp>      // fp::Sponge, dom
#include <hsma/poseidon.hpp> // fp::poseidon3
#include <hsma/nifs.hpp>     // feq, the Step-21 proven fold family
#include <vector>
#include <cassert>
#include <cstdint>

namespace hsma::mfold {

using nifs::feq;

// ---- sparse R1CS (COO) ----
struct SparseMat {
    unsigned n_rows = 0, n_cols = 0;
    std::vector<unsigned> row, col;
    std::vector<fp::fe> val;
};

inline std::vector<fp::fe> mat_vec(const SparseMat& M, const std::vector<fp::fe>& z) noexcept {
    std::vector<fp::fe> out(M.n_rows, fp::fe_zero());
    for (std::size_t t = 0; t < M.val.size(); ++t)
        out[M.row[t]] = fp::fe_add(out[M.row[t]], fp::fe_mul(M.val[t], z[M.col[t]]));
    return out;
}

// ---- relaxed instance ----
struct Relaxed {
    fp::fe u{};                 // 1 for fresh instances
    std::vector<fp::fe> z;      // full assignment (public | witness), n_cols
    std::vector<fp::fe> E;      // per-constraint error, n_rows (0 for fresh)
};

inline Relaxed fresh(const std::vector<fp::fe>& z, unsigned n_rows) noexcept {
    Relaxed R; R.u = fp::fe_one(); R.z = z; R.E.assign(n_rows, fp::fe_zero());
    return R;
}

// sat: Az∘Bz == u*Cz + E, row by row. Returns the first failing row,
// n_rows == SAT (the CA-R83 sentinel discipline).
inline constexpr std::size_t MFOLD_SAT_FAIL_FINAL = static_cast<std::size_t>(-1);
inline std::size_t sat_relaxed(const SparseMat& A, const SparseMat& B, const SparseMat& C,
                               const Relaxed& R) noexcept {
    const std::vector<fp::fe> az = mat_vec(A, R.z);
    const std::vector<fp::fe> bz = mat_vec(B, R.z);
    const std::vector<fp::fe> cz = mat_vec(C, R.z);
    for (std::size_t i = 0; i < az.size(); ++i) {
        const fp::fe lhs = fp::fe_mul(az[i], bz[i]);
        const fp::fe rhs = fp::fe_add(fp::fe_mul(R.u, cz[i]), R.E[i]);
        if (!feq(lhs, rhs)) return i;
    }
    return az.size();
}

// ---- the cross-term (the fold algebra's heart) ----
// The standard HyperNova cross-term:
//   T = Az_U∘Bz_j + Az_j∘Bz_U - u_U*Cz_j - u_j*Cz_U.
// SCHEME PRECONDITION: incoming instances are FRESH (u_j = 1, E_j = 0) -
// only the accumulator is relaxed. The general form is written anyway
// (coincides with the fresh-specialization; the assert enforces it).
inline std::vector<fp::fe> cross_term(const SparseMat& A, const SparseMat& B, const SparseMat& C,
                                      const Relaxed& U, const Relaxed& J) noexcept {
    const std::vector<fp::fe> azU = mat_vec(A, U.z), bzU = mat_vec(B, U.z), czU = mat_vec(C, U.z);
    const std::vector<fp::fe> azJ = mat_vec(A, J.z), bzJ = mat_vec(B, J.z), czJ = mat_vec(C, J.z);
    std::vector<fp::fe> T(azU.size());
    for (std::size_t i = 0; i < T.size(); ++i) {
        fp::fe t = fp::fe_add(fp::fe_mul(azU[i], bzJ[i]), fp::fe_mul(azJ[i], bzU[i]));
        t = fp::fe_sub(t, fp::fe_mul(U.u, czJ[i]));
        t = fp::fe_sub(t, fp::fe_mul(J.u, czU[i]));
        T[i] = t;
    }
    return T;
}

// ---- the k-fold ----
struct MultifoldResult {
    Relaxed folded{};
    std::vector<std::vector<fp::fe>> T;   // k cross-terms
    std::vector<fp::fe> r;                // k FS challenges
    fp::fe seed{};                        // the FS seed (transcript-bound)
};

inline MultifoldResult multifold(const SparseMat& A, const SparseMat& B, const SparseMat& C,
                                 const Relaxed& U,
                                 const std::vector<Relaxed>& js) noexcept {
    MultifoldResult M;
    const unsigned k = (unsigned)js.size();
    for (const auto& J : js) {   // scheme precondition, enforced (CA-R135)
        assert(feq(J.u, fp::fe_one()) && "mfold: incoming instances must be fresh (u=1)");
        for (const auto& e : J.E)
            assert(fp::fe_is_zero(e) && "mfold: incoming instances must be fresh (E=0)");
    }
    M.T.resize(k);
    for (unsigned j = 0; j < k; ++j) M.T[j] = cross_term(A, B, C, U, js[j]);

    // FS transcript: absorb U, then each instance and its cross-term.
    fp::Sponge sp(dom::Dom::HSM_SUMCHECK_v1);
    sp.absorb(U.u);
    for (const auto& v : U.z) sp.absorb(v);
    for (const auto& e : U.E) sp.absorb(e);
    for (unsigned j = 0; j < k; ++j) {
        sp.absorb(js[j].u);
        for (const auto& v : js[j].z) sp.absorb(v);
        for (const auto& e : js[j].E) sp.absorb(e);
        for (const auto& t : M.T[j]) sp.absorb(t);
    }
    M.seed = sp.squeeze();
    M.r.resize(k);
    for (unsigned j = 0; j < k; ++j)
        M.r[j] = fp::poseidon3(dom::Dom::HSM_SUMCHECK_v1, M.seed, fp::fe_from_u64(j));

    // the fold (EXACT algebra for any r_j)
    M.folded = U;
    M.folded.u = fp::fe_add(U.u, fp::fe_zero());
    for (unsigned j = 0; j < k; ++j) M.folded.u = fp::fe_add(M.folded.u, M.r[j]);
    for (std::size_t t = 0; t < U.z.size(); ++t) {
        fp::fe acc = U.z[t];
        for (unsigned j = 0; j < k; ++j)
            acc = fp::fe_add(acc, fp::fe_mul(M.r[j], js[j].z[t]));
        M.folded.z[t] = acc;
    }
    for (std::size_t i = 0; i < U.E.size(); ++i) {
        fp::fe acc = U.E[i];
        for (unsigned j = 0; j < k; ++j)
            acc = fp::fe_add(acc, fp::fe_mul(M.r[j], M.T[j][i]));
        M.folded.E[i] = acc;
    }
    return M;
}

} // namespace hsma::mfold
