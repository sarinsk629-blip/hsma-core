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
#include <hsma/pcs.hpp>
#include <hsma/pedersen.hpp>
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


// ---- P1-18 (DEC-248): the FS-bound proof --------------------------------
// Grinding kill: gamma/delta derive FROM the commitments (HSM_POUW_v1
// domain) - commitments are fixed before challenges exist, so each grind
// attempt faces fresh challenges (expected cost ~2^253).
// Split-brain kill: the verifier recomputes every commitment from the
// delivered arrays and cross-checks.
// HONEST BOUNDARY: the Phase-0 PCS is a Sponge hash (NOT homomorphic,
// NOT hiding) - the at-point Opening is production-faithful infrastructure;
// standalone witness binding (verifier holds NO arrays) lands with the
// Pedersen dual-layer (DEC-063/071). Until then direct_eval binding with
// verifier-held arrays is retained.
struct GemmProofV2 {
    fp::fe comA{}, comB{}, comC{};   // Sponge commitments
    fp::fe gamma{}, delta{};         // FS challenges (derived from the coms)
    fp::fe claim{};                  // sumcheck claim over the output
    Transcript T{};                  // the degree-2 sumcheck transcript
    pcs::Opening O{};                // at-point opening at T.r (infrastructure)
    unsigned rows{}, cols{}, inner{};
};

inline void fs_challenges(const fp::fe& comA, const fp::fe& comB,
                          const fp::fe& comC,
                          fp::fe& gamma, fp::fe& delta) noexcept {
    gamma = poseidon3(dom::Dom::HSM_POUW_v1, comA, comB);
    delta = poseidon3(dom::Dom::HSM_POUW_v1, gamma, comC);
}

inline GemmProofV2 prove_gemm_v2(
    const std::vector<fp::fe>& A, const std::vector<fp::fe>& B,
    const std::vector<fp::fe>& C,
    unsigned rows, unsigned cols, unsigned inner) noexcept
{
    GemmProofV2 P;
    P.rows = rows; P.cols = cols; P.inner = inner;
    P.comA = pcs::commit(A);
    P.comB = pcs::commit(B);
    P.comC = pcs::commit(C);
    fs_challenges(P.comA, P.comB, P.comC, P.gamma, P.delta);
    P.claim = claim_from_C(C, rows, cols, P.gamma, P.delta);
    std::vector<fp::fe> a, b, ap, bp;
    fold_witness(A, B, rows, cols, inner, P.gamma, P.delta, a, b);
    const unsigned nv = kdim(inner);
    pad_to(a, nv, ap); pad_to(b, nv, bp);
    P.T = sc::prove_2(nv, ap, bp);
    P.O = pcs::open_2_at(ap, bp, P.T.r);
    return P;
}

inline bool verify_gemm_v2(const GemmProofV2& P,
                           const std::vector<fp::fe>& A_ref,
                           const std::vector<fp::fe>& B_ref,
                           const std::vector<fp::fe>& C_delivered) noexcept
{
    // (1) commitment cross-checks - the split-brain kill
    if (!sc::feq(P.comA, pcs::commit(A_ref)))       return false;
    if (!sc::feq(P.comB, pcs::commit(B_ref)))       return false;
    if (!sc::feq(P.comC, pcs::commit(C_delivered))) return false;
    // (2) FS recompute - the grinding kill
    fp::fe g{}, d{};
    fs_challenges(P.comA, P.comB, P.comC, g, d);
    if (!sc::feq(g, P.gamma) || !sc::feq(d, P.delta)) return false;
    // (3) output binding
    if (!sc::feq(P.claim, claim_from_C(C_delivered, P.rows, P.cols, g, d)))
        return false;
    // (4) identity - CA-R170-conformant accept (== T.nv, never != 0)
    if (sc::verify(P.T, P.claim) != P.T.nv) return false;
    // (5) at-point opening: internal consistency + agrees with the transcript
    if (pcs::verify_at(P.O, P.T.claims[0], P.T.r) != P.O.nv) return false;
    if (!sc::feq(P.O.fa, P.T.fa) || !sc::feq(P.O.fb, P.T.fb)) return false;
    // (6) witness binding (direct_eval, verifier-held arrays; dual-layer = P1-19)
    const unsigned nv = kdim(P.inner);
    std::vector<fp::fe> a, b, aref, bref;
    fold_witness(A_ref, B_ref, P.rows, P.cols, P.inner, g, d, a, b);
    pad_to(a, nv, aref); pad_to(b, nv, bref);
    return sc::feq(P.T.fa, sc::direct_eval(aref, P.T.r))
        && sc::feq(P.T.fb, sc::direct_eval(bref, P.T.r));
}


// ---- P1-19 (DEC-263): the externally-submittable verifier (v3) ----
// The last PoUW asterisk dies: verify_gemm_v2 required a_ref/b_ref from
// the verifier's own recomputation - useless for external submissions.
// v3 binds the SUBMITTED arrays to the REGISTERED model via Pedersen
// vector commitments (per-position distinct bases, CA-R187), then runs
// the FULL v2 chain on the submission. The verifier NEVER performs the
// n^3 multiply. Honest boundary: O(n^2) submission bandwidth; succinct
// no-submission binding = the homomorphic fold (P1-22, DEC-071).
inline bool ped_eq(const g2v::PtV& P, const g2v::PtV& Q) noexcept {
    g2v::PtV NQ;
    NQ.x = Q.x; NQ.y = fq::fev_sub(fq::fev_zero(), Q.y); NQ.z = Q.z;
    return fq::fev_is_zero(g2v::Vadd(P, NQ).z);   // P + (-Q) == inf <=> P == Q (fq/fev: CA-R117)
}

inline bool verify_gemm_v3(const GemmProofV2& P,
                           const std::vector<fp::fe>& A_sub,
                           const std::vector<fp::fe>& B_sub,
                           const std::vector<fp::fe>& C_sub,
                           const g2v::PtV& regA, const g2v::PtV& regB,
                           const std::uint64_t r_pub[4],
                           const std::uint64_t ORDER[4]) noexcept
{
    // (0) registration binding - the front door. A SELF-CONSISTENT proof
    // over a DOCTORED model dies here and only here ([P3-fakeA]).
    if (!ped_eq(pedv::commit_vec(A_sub, r_pub, ORDER), regA)) return false;
    if (!ped_eq(pedv::commit_vec(B_sub, r_pub, ORDER), regB)) return false;
    // (1..6) the full v2 chain on the submitted arrays
    return verify_gemm_v2(P, A_sub, B_sub, C_sub);
}
} // namespace hsma::pouw
