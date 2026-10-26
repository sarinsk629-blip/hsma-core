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
#include <hsma/sha256.hpp>   // the v2 production transcript (DEF-405 law)
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

    // THE FOLD, SEQUENTIALLY (DEF-379 fix). The pair-fold identity is exact
    // for ONE instance against the CURRENT accumulator; folding k instances
    // SIMULTANEOUSLY (the old z/E accumulation) drops the cross-j terms
    // sum_{i!=j} r_i r_j (Az_i.Boz_j - Cz_j) — test_step62 (k=3) exposed it.
    // The challenges are UNCHANGED (the transcript above is untouched, so
    // every k=1 caller - steps 31/32/33 - reproduces its exact r and fold);
    // only the application is chained: each round folds js[j] into the
    // CURRENT accumulator with a cross-term recomputed against it, which is
    // exactly the proven 2-to-1 identity, applied k times.
    M.folded = U;
    M.folded.u = fp::fe_add(U.u, fp::fe_zero());
    for (unsigned j = 0; j < k; ++j) {
        // k=1 fast path: M.folded IS U at j=0, so the applied cross-term is
        // the SAME field element as the transcript's T[0] - recomputing it is
        // bit-identical waste; skip (halves the k=1 fold cost, the node's path).
        const std::vector<fp::fe> Tj = (j == 0 && k == 1)
            ? M.T[0] : cross_term(A, B, C, M.folded, js[j]);
        M.T[j] = Tj;                       // the cross-term actually applied
        M.folded.u = fp::fe_add(M.folded.u, M.r[j]);
        for (std::size_t t = 0; t < M.folded.z.size(); ++t)
            M.folded.z[t] = fp::fe_add(M.folded.z[t],
                                       fp::fe_mul(M.r[j], js[j].z[t]));
        for (std::size_t i = 0; i < M.folded.E.size(); ++i)
            M.folded.E[i] = fp::fe_add(M.folded.E[i],
                                       fp::fe_mul(M.r[j], Tj[i]));
    }
    return M;
}

// ---- the PRODUCTION multifold (v2, DEF-405) ------------------------------
// THE MEASURED PROBLEM: the v1 transcript absorbs witness vectors
// ELEMENT-WISE into a Poseidon sponge. At production circuit width
// (141,002-row entry circuit, ~145k vars) that is ~700k permutations per
// fold at 34us each - 6.3 s PER FOLD, 50 min per k=476 epoch (p4bench,
// measured). The fold ALGEBRA was never the bottleneck; the transcript was.
//
// THE v2 LAW (CA-R373a): the FS transcript binds the CANONICAL BYTES of the
// vectors through a STREAMING SHA-256 - one hash pass over O(n) BYTES per
// fold (bytes are ~600x cheaper than field permutations), challenges via
// the PROVEN whir::digest_scalar reduction (256-bit digest -> F_p, the
// CA-R132 family). Same binding surface as v1 (u, z, E, and each instance's
// (u, z, E, T)), same sequential fold application (DEF-379's chained
// cross-terms), different transport. v1 stays the GOLDEN-SCALE law (steps
// 31-33 / test_step62/63/65/66 pin its r stream); v2 is production scale.
// Both are machine-checked; selection is explicit by function name.
//
// Bit-exactness: field ops are EXACT (no floats - DEC-090), the fold
// identity is transcript-independent (exact for ANY r), and test_step67
// proves v2 at k=476 with SAT at every milestone.
struct MultifoldResult2 {
    Relaxed folded{};
    std::vector<std::vector<fp::fe>> T;   // k cross-terms (as applied)
    std::vector<fp::fe> r;                // k FS challenges
    std::uint8_t seed[32]{};              // the v2 transcript digest
};

inline void _v2_absorb_fe(::hsma::digest::Sha256& h, const fp::fe& x) {
    std::byte b[32];
    fp::fe_to_le_bytes(x, b);            // canonicalizes internally (CA-R132)
    h.update(reinterpret_cast<const std::uint8_t*>(b), 32);
}
inline void _v2_absorb_vec(::hsma::digest::Sha256& h, const std::vector<fp::fe>& v) {
    for (const auto& x : v) _v2_absorb_fe(h, x);
}

inline MultifoldResult2 multifold_v2(const SparseMat& A, const SparseMat& B, const SparseMat& C,
                                     const Relaxed& U,
                                     const std::vector<Relaxed>& js) noexcept {
    MultifoldResult2 M;
    const unsigned k = (unsigned)js.size();
    for (const auto& J : js) {   // the same scheme precondition (CA-R135)
        assert(feq(J.u, fp::fe_one()) && "mfold_v2: incoming instances must be fresh (u=1)");
        for (const auto& e : J.E)
            assert(fp::fe_is_zero(e) && "mfold_v2: incoming instances must be fresh (E=0)");
    }
    M.T.resize(k);
    for (unsigned j = 0; j < k; ++j) M.T[j] = cross_term(A, B, C, U, js[j]);

    // THE v2 TRANSCRIPT: one streaming SHA-256 over the same binding surface
    // v1 spelled element-wise. Absorb order (the law): u_U, z_U, E_U, then
    // per instance j: u_j, z_j, E_j, T_j.
    ::hsma::digest::Sha256 h;
    _v2_absorb_fe(h, U.u);
    _v2_absorb_vec(h, U.z);
    _v2_absorb_vec(h, U.E);
    for (unsigned j = 0; j < k; ++j) {
        _v2_absorb_fe(h, js[j].u);
        _v2_absorb_vec(h, js[j].z);
        _v2_absorb_vec(h, js[j].E);
        _v2_absorb_vec(h, M.T[j]);
    }
    h.finish(M.seed);

    // challenges: r_j = digest_scalar(SHA256("HSMA_MFOLD_V2|R" || seed || j_le64))
    // (the whir::digest_scalar law: canonical LE -> <=8 subtracts -> F_p)
    M.r.resize(k);
    for (unsigned j = 0; j < k; ++j) {
        std::uint8_t msg[32 + 15 + 8];
        std::memcpy(msg, "HSMA_MFOLD_V2|R", 15);
        std::memcpy(msg + 15, M.seed, 32);
        std::uint8_t jb[8];
        for (int b = 0; b < 8; ++b) jb[b] = std::uint8_t(j >> (8 * b));
        std::memcpy(msg + 47, jb, 8);
        std::uint8_t dg[32];
        ::hsma::digest::sha256(reinterpret_cast<const std::uint8_t*>(msg), sizeof msg, dg);
        std::array<std::uint64_t, 4> l{};
        for (int b = 0; b < 4; ++b)
            for (int by = 0; by < 8; ++by) l[b] |= (std::uint64_t)dg[8 * b + by] << (8 * by);
        // <= 8 subtracts of p (digest < 2^256, p ~ 2^254.4)
        for (int t = 0; t < 8; ++t) {
            // can_geq_p inline (pallas modulus)
            const std::uint64_t P[4] = {0x8c46eb2100000001ull, 0x224698fc0994a8ddull, 0ull, 0x4000000000000000ull};
            bool geq = false;
            for (int i = 3; i >= 0; --i) {
                if (l[i] != P[i]) { geq = l[i] > P[i]; break; }
                if (i == 0) geq = true;
            }
            if (!geq) break;
            std::uint64_t borrow = 0;
            for (int i = 0; i < 4; ++i) {
                const std::uint64_t bi = P[i] + borrow;
                if (l[i] >= bi) { l[i] -= bi; borrow = 0; }
                else { l[i] -= bi; borrow = 1; }
            }
        }
        M.r[j] = fp::fe_from_canonical_limbs(l);
    }

    // THE FOLD, SEQUENTIALLY (DEF-379's chained application, unchanged)
    M.folded = U;
    M.folded.u = fp::fe_add(U.u, fp::fe_zero());
    for (unsigned j = 0; j < k; ++j) {
        // k=1 fast path: M.folded IS U at j=0, so the applied cross-term is
        // the SAME field element as the transcript's T[0] - recomputing it is
        // bit-identical waste; skip (halves the k=1 fold cost, the node's path).
        const std::vector<fp::fe> Tj = (j == 0 && k == 1)
            ? M.T[0] : cross_term(A, B, C, M.folded, js[j]);
        M.T[j] = Tj;                       // the cross-term actually applied
        M.folded.u = fp::fe_add(M.folded.u, M.r[j]);
        for (std::size_t t = 0; t < M.folded.z.size(); ++t)
            M.folded.z[t] = fp::fe_add(M.folded.z[t],
                                       fp::fe_mul(M.r[j], js[j].z[t]));
        for (std::size_t i = 0; i < M.folded.E.size(); ++i)
            M.folded.E[i] = fp::fe_add(M.folded.E[i],
                                       fp::fe_mul(M.r[j], Tj[i]));
    }
    return M;
}

} // namespace hsma::mfold
