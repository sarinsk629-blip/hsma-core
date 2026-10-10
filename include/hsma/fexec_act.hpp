#pragma once
// HSMA :: fexec_act.hpp - Phase 6.6 v1: the activation layer as CCS rows,
// digest-bound to the LogUp batch (the dual-receipt design).
//
//   GEMM (proven, 6.5) -> quantize (oracle, boundary) -> ordered pairs (idx,uv)
//         |                                              |
//         v                                              v
//   THIS CIRCUIT                                  LOGUP BATCH (LP field)
//   positional digest in R1CS rows                balanced() (P5-F proven)
//         └──────────── digest must match ────────────┘
//
//   Lie in the circuit  -> digest mismatch | Lazy tamper -> satisfaction fails
//   Lie to the batch    -> balanced() fails | Fake both -> must BE the honest pairs
//
// v1 BOUNDARIES (registered, honest): (1) one table per batch (multi-table=v2);
// (2) idx range enforced at quantization (in-circuit range checks = v2);
// (3) the digest binds (idx,|val|) — the same object LogUp consumes;
// (4) denominator arithmetic as circuit rows over Pallas = v2 (the full
// LogUp-in-CCS; the cross-field boundary is why v1 binds by digest).
// CA-R230/DEC-090: integer-only; no floats cross this header.
#pragma once
#include <hsma/mfold.hpp>
#include <hsma/fe.hpp>
#include <hsma/pouw/logup.hpp>
#include <cstddef>
#include <vector>

namespace hsma::actcirc {

inline constexpr unsigned SLOTS = 4u;   // activation slots per instance (v1)

// wire layout: z[0]=u (relaxed scalar, mfold convention)  z[1]=ONE (CA-R144)
//   z[2]=acc_0   per slot i: z[3+2i]=idx_i  z[4+2i]=uv_i
//   acc chain:   z[3+2*SLOTS+i] = acc_{i+1}
inline constexpr unsigned NW_ACC    = SLOTS;
inline constexpr unsigned NZ_ACT    = 3u + 2u * SLOTS + NW_ACC;   // 15 @ SLOTS=4
inline constexpr unsigned NROWS_ACT = SLOTS;                      // one row per slot
inline constexpr unsigned W_U = 0u, W_ONE = 1u, W_ACC0 = 2u;
inline constexpr unsigned W_IDX(unsigned i)  { return 3u + 2u * i; }
inline constexpr unsigned W_UV (unsigned i)  { return 4u + 2u * i; }
inline constexpr unsigned W_ACC (unsigned i) { return 3u + 2u * SLOTS + i; }

// public binding constants; POSITION POWERS make the digest order-sensitive
// (swapping two slots changes it — a multiset alone would not).
inline constexpr std::uint64_t C1 = 0x9E3779B97F4A7C15ull;
inline constexpr std::uint64_t C2 = 0xC2B2AE3D27D4EB4Full;

inline void slot_coeffs(unsigned i, fp::fe& p1, fp::fe& p2) noexcept {
    p1 = fp::fe_from_u64(C1);
    p2 = fp::fe_from_u64(C2);
    for (unsigned k = 0; k < i; ++k) {              // p = C^(i+1)
        p1 = fp::fe_mul(p1, fp::fe_from_u64(C1));
        p2 = fp::fe_mul(p2, fp::fe_from_u64(C2));
    }
}

// the pair object both sides consume (uv = |val_q7| — what balanced() verifies)
struct Pair { unsigned idx; unsigned uv; };

// batch-side digest: the same constant-combination, computed OUTSIDE the circuit
inline fp::fe pairs_digest(const std::vector<Pair>& ps) noexcept {
    fp::fe acc = fp::fe_zero();
    for (unsigned i = 0; i < ps.size() && i < SLOTS; ++i) {
        fp::fe p1, p2; slot_coeffs(i, p1, p2);
        acc = fp::fe_add(acc, fp::fe_mul(p1, fp::fe_from_u64(ps[i].idx)));
        acc = fp::fe_add(acc, fp::fe_mul(p2, fp::fe_from_u64(ps[i].uv)));
    }
    return acc;
}

// the rows (COO over Pallas):  row i: (P1_i*idx_i + P2_i*uv_i + acc_i)*ONE = acc_{i+1}
inline void build_act_matrices(mfold::SparseMat& A, mfold::SparseMat& B, mfold::SparseMat& C) noexcept {
    A.n_rows = B.n_rows = C.n_rows = NROWS_ACT;
    A.n_cols = B.n_cols = C.n_cols = NZ_ACT;
    for (unsigned i = 0; i < SLOTS; ++i) {
        fp::fe p1, p2; slot_coeffs(i, p1, p2);
        A.row.push_back(i); A.col.push_back(W_IDX(i)); A.val.push_back(p1);
        A.row.push_back(i); A.col.push_back(W_UV(i));  A.val.push_back(p2);
        A.row.push_back(i); A.col.push_back(i == 0 ? W_ACC0 : W_ACC(i - 1));
        A.val.push_back(fp::fe_from_u64(1));
        B.row.push_back(i); B.col.push_back(W_ONE); B.val.push_back(fp::fe_from_u64(1));
        C.row.push_back(i); C.col.push_back(W_ACC(i)); C.val.push_back(fp::fe_from_u64(1));
    }
}

inline std::vector<fp::fe> honest_z(const std::vector<Pair>& ps) noexcept {
    std::vector<fp::fe> z(NZ_ACT, fp::fe_zero());
    z[W_U]   = fp::fe_from_u64(1);
    z[W_ONE] = fp::fe_from_u64(1);
    fp::fe acc = fp::fe_zero();
    for (unsigned i = 0; i < SLOTS && i < ps.size(); ++i) {
        z[W_IDX(i)] = fp::fe_from_u64(ps[i].idx);
        z[W_UV(i)]  = fp::fe_from_u64(ps[i].uv);
        fp::fe p1, p2; slot_coeffs(i, p1, p2);
        acc = fp::fe_add(acc, fp::fe_mul(p1, z[W_IDX(i)]));
        acc = fp::fe_add(acc, fp::fe_mul(p2, z[W_UV(i)]));
        z[W_ACC(i)] = acc;
    }
    return z;
}

inline fp::fe circuit_digest(const std::vector<fp::fe>& z) noexcept {
    return z[W_ACC(SLOTS - 1)];                     // acc_S
}

// fresh-instance satisfaction: (A·z)∘(B·z) == C·z  (u=1, E=0)
inline bool satisfied(const mfold::SparseMat& A, const mfold::SparseMat& B,
                      const mfold::SparseMat& C, const std::vector<fp::fe>& z) noexcept {
    const auto az = mfold::mat_vec(A, z);
    const auto bz = mfold::mat_vec(B, z);
    const auto cz = mfold::mat_vec(C, z);
    for (unsigned r = 0; r < A.n_rows; ++r)
        if (!(fp::fe_mul(az[r], bz[r]) == cz[r])) return false;
    return true;
}

} // namespace hsma::actcirc
