// HSMA :: pouw.hpp - P1-17 (the PoUW wiring: GEMM -> sumcheck -> weight, DEC-245).
//
// THE REDUCTION (one degree-2 sumcheck binds the WHOLE GEMM):
//   a(k)  = sum_i gamma^i A(i,k)            [prover folds rows]
//   b(k)  = sum_j delta^j B(k,j)            [prover folds cols]
//   claim = sum_{i,j} gamma^i delta^j C(i,j) [verifier, from the output]
//   IDENTITY: sum_k a(k)b(k) = claim.
//   A faked output deviates unless (gamma,delta) hits the zero set of
//   the deviation polynomial (prob <= 2(n-1)/p).
//
// THE TWO SECURITY CHECKS (both must pass):
//   [identity] sc::verify(T, claim) - faked RESULTS are caught here.
//   [binding]  T.fa/T.fb == MLE of the verifier's OWN arrays at T.r -
//              faked WITNESSES are caught here. Probe-grade: direct_eval.
//              P1-18: PCS commit(A),commit(B), open at T.r.
//
// THE PoUW WEIGHT: one verified GEMM proof = inner^3 verified MACs.
//
// HONEST SCOPE (P1-17): wiring + weight. Poseidon-FS challenges, PCS
// bindings, epoch aggregation = P1-18.
#pragma once
#include <hsma/sumcheck.hpp>
#include <vector>
#include <cstdint>

namespace hsma::pouw {

using sc::Transcript;

struct GemmProof {
    fp::fe claim{};      // sum_{i,j} gamma^i delta^j C(i,j)
    Transcript T{};      // the degree-2 sumcheck transcript
    unsigned inner{};    // the k-dimension (the work measure)
};

// prover-side reduction: fold the GEMM into the k-index arrays
inline void fold_witness(
    const std::vector<fp::fe>& A, const std::vector<fp::fe>& B,
    unsigned rows, unsigned cols, unsigned inner,
    const fp::fe& gamma, const fp::fe& delta,
    std::vector<fp::fe>& a, std::vector<fp::fe>& b) noexcept
{
    a.assign(inner, fp::fe_zero());
    b.assign(inner, fp::fe_zero());
    fp::fe gp = fp::fe_one();                  // gamma^i
    for (unsigned i = 0; i < rows; ++i) {
        for (unsigned k = 0; k < inner; ++k)
            a[k] = fp::fe_add(a[k], fp::fe_mul(gp, A[i * inner + k]));
        gp = fp::fe_mul(gp, gamma);
    }
    fp::fe dp = fp::fe_one();                  // delta^j
    for (unsigned j = 0; j < cols; ++j) {
        for (unsigned k = 0; k < inner; ++k)
            b[k] = fp::fe_add(b[k], fp::fe_mul(dp, B[k * cols + j]));
        dp = fp::fe_mul(dp, delta);
    }
}

// verifier-side claim from the (received or committed) output matrix
inline fp::fe claim_from_C(
    const std::vector<fp::fe>& C, unsigned rows, unsigned cols,
    const fp::fe& gamma, const fp::fe& delta) noexcept
{
    fp::fe acc = fp::fe_zero();
    fp::fe gp = fp::fe_one();
    for (unsigned i = 0; i < rows; ++i) {
        fp::fe dp = fp::fe_one();
        for (unsigned j = 0; j < cols; ++j) {
            acc = fp::fe_add(acc, fp::fe_mul(gp, fp::fe_mul(dp, C[i * cols + j])));
            dp = fp::fe_mul(dp, delta);
        }
        gp = fp::fe_mul(gp, gamma);
    }
    return acc;
}

inline void pad_to(const std::vector<fp::fe>& v, unsigned nv,
                   std::vector<fp::fe>& out) noexcept {
    out.assign(1u << nv, fp::fe_zero());
    for (unsigned t = 0; t < v.size() && t < out.size(); ++t) out[t] = v[t];
}

inline unsigned kdim(unsigned inner) noexcept {
    unsigned nv = 0; while ((1u << nv) < inner) ++nv; return nv;
}

// THE PROVER: one whole-GEMM PoUW proof
inline GemmProof prove_gemm(
    const std::vector<fp::fe>& A, const std::vector<fp::fe>& B,
    const std::vector<fp::fe>& C,
    unsigned rows, unsigned cols, unsigned inner,
    const fp::fe& gamma, const fp::fe& delta) noexcept
{
    GemmProof P;
    P.inner = inner;
    P.claim = claim_from_C(C, rows, cols, gamma, delta);
    std::vector<fp::fe> a, b, ap, bp;
    fold_witness(A, B, rows, cols, inner, gamma, delta, a, b);
    const unsigned nv = kdim(inner);
    pad_to(a, nv, ap);
    pad_to(b, nv, bp);
    P.T = sc::prove_2(nv, ap, bp);
    return P;
}

// THE VERIFIER (probe-grade binding; PCS openings at T.r = P1-18)
inline bool verify_gemm(const GemmProof& P,
                        const std::vector<fp::fe>& a_ref,
                        const std::vector<fp::fe>& b_ref) noexcept
{
    const unsigned nv = kdim(P.inner);
    std::vector<fp::fe> aref, bref;
    pad_to(a_ref, nv, aref);
    pad_to(b_ref, nv, bref);
    return (sc::verify(P.T, P.claim) == P.T.nv)
        && sc::feq(P.T.fa, sc::direct_eval(aref, P.T.r))
        && sc::feq(P.T.fb, sc::direct_eval(bref, P.T.r));
}

// PoUW consensus weight: one verified proof = inner^3 verified MACs
inline std::uint64_t weight(unsigned inner, std::uint64_t proofs) noexcept {
    return (std::uint64_t)inner * inner * inner * proofs;
}

} // namespace hsma::pouw
