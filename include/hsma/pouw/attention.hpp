// HSMA :: pouw/attention.hpp - Phase 6.19 rung-1 (DEC-s4): attention as a GEMM composition.
//
// THE DECOMPOSITION. Multi-head attention is five GEMM leg families over the
// existing v2 proof machinery:
//   Q = X · Wq      (seq×dm · dm×dm)   projections
//   K = X · Wk      (seq×dm · dm×dm)
//   V = X · Wv      (seq×dm · dm×dm)
//   S_h = Q_h · K_h^T                  per-head scores (seq×seq)
//   A_h = P_h · V_h                    per-head attention output (seq×dh)
//   OUT = concat_h(A_h) · Wo           the output projection (seq×dm)
// Every leg is proven by prove_gemm_v2 (FS challenges from its own
// commitments) — the transformer's linear substrate rides machinery that is
// already golden-proven, sumcheck-bound, and grind-resistant.
//
// THE HONEST BOUNDARY (the fence, in writing). P_h — the post-softmax,
// post-scale attention weights — was an INPUT to the rung-1 scaffold below
// (prove_attention/verify_attention, retained for the s4 receipts). Phase
// 6.14 (DEC-s5) CLOSED the fence: pouw/softmax.hpp is the certified P_h
// producer, and prove_attention_full/verify_attention_full DERIVE P_h from
// the proven score-leg outputs through the 0-LSB-certified tables — a
// doctored P_h is no longer expressible in the full path. Softmax is exp +
// division over the reals; in a float-free field core (DEC-090) it is
// TABLE work: the 6.14 exp_shifted table + the RCP division (step49),
// every lookup riding the LogUp multiset argument. The 1/sqrt(d) scale
// rides the RCP machinery (step49).
//
// The K_h^T transpose is materialized physically (dh×seq row-major) — a
// layout operation, not a new proof obligation.
#pragma once
#include <hsma/pouw.hpp>
#include <hsma/fe.hpp>
#include <hsma/pouw/softmax.hpp>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace hsma::pouw::attn {

struct AttnProof {
    unsigned seq = 0;    // sequence length
    unsigned dm = 0;     // d_model
    unsigned heads = 0;  // head count (dm % heads == 0)
    unsigned dh = 0;     // per-head dimension = dm / heads
    GemmProofV2 Q, K, V, OUT;          // the projection legs + output leg
    std::vector<GemmProofV2> S;        // per-head score legs (heads entries)
    std::vector<GemmProofV2> A;        // per-head attention·V legs (heads entries)
};

inline bool spec_ok(unsigned seq, unsigned dm, unsigned heads) noexcept {
    return seq > 0 && dm > 0 && heads > 0 && (dm % heads) == 0;
}

// column slice of an row-major seq×dm matrix into seq×dh
inline void col_slice(const std::vector<fp::fe>& M, unsigned seq, unsigned dm,
                      unsigned h, unsigned dh, std::vector<fp::fe>& out) noexcept {
    out.assign((std::size_t)seq * dh, fp::fe_zero());
    for (unsigned r = 0; r < seq; ++r)
        for (unsigned c = 0; c < dh; ++c)
            out[(std::size_t)r * dh + c] = M[(std::size_t)r * dm + (h * dh + c)];
}

// physical transpose of an r×c row-major matrix
inline void transpose(const std::vector<fp::fe>& M, unsigned r, unsigned c,
                      std::vector<fp::fe>& out) noexcept {
    out.assign((std::size_t)r * c, fp::fe_zero());
    for (unsigned i = 0; i < r; ++i)
        for (unsigned j = 0; j < c; ++j)
            out[(std::size_t)j * r + i] = M[(std::size_t)i * c + j];
}

// THE rectangular CPU reference (rows×inner · inner×cols) — the backend's
// pouw::gemm is square-only by design; attention's projection legs are not
// square. Same shape as gemm_cpu: fe_mul/fe_add, float-free (DEC-090).
inline void matmul(const std::vector<fp::fe>& A, const std::vector<fp::fe>& B,
                   std::vector<fp::fe>& C, unsigned rows, unsigned inner,
                   unsigned cols) noexcept {
    C.assign((std::size_t)rows * cols, fp::fe_zero());
    for (unsigned i = 0; i < rows; ++i)
        for (unsigned j = 0; j < cols; ++j) {
            fp::fe acc = fp::fe_zero();
            for (unsigned k = 0; k < inner; ++k)
                acc = fp::fe_add(acc, fp::fe_mul(A[(std::size_t)i * inner + k],
                                                 B[(std::size_t)k * cols + j]));
            C[(std::size_t)i * cols + j] = acc;
        }
}

// THE PROVER: X(seq×dm), Wq/Wk/Wv/Wo(dm×dm), Ps[h](seq×seq per head).
inline AttnProof prove_attention(const std::vector<fp::fe>& X,
                                 const std::vector<fp::fe>& Wq,
                                 const std::vector<fp::fe>& Wk,
                                 const std::vector<fp::fe>& Wv,
                                 const std::vector<fp::fe>& Wo,
                                 const std::vector<std::vector<fp::fe>>& Ps,
                                 unsigned seq, unsigned dm, unsigned heads) noexcept {
    const unsigned dh = dm / heads;
    AttnProof P;
    P.seq = seq; P.dm = dm; P.heads = heads; P.dh = dh;
    std::vector<fp::fe> Qm((std::size_t)seq * dm), Km((std::size_t)seq * dm),
                         Vm((std::size_t)seq * dm), OUTm((std::size_t)seq * dm);
    matmul(X, Wq, Qm, seq, dm, dm);
    matmul(X, Wk, Km, seq, dm, dm);
    matmul(X, Wv, Vm, seq, dm, dm);
    P.Q = prove_gemm_v2(X, Wq, Qm, seq, dm, dm);
    P.K = prove_gemm_v2(X, Wk, Km, seq, dm, dm);
    P.V = prove_gemm_v2(X, Wv, Vm, seq, dm, dm);
    P.S.reserve(heads); P.A.reserve(heads);
    std::vector<fp::fe> Qh, Kh, Vh, KhT, Sh((std::size_t)seq * seq),
                         Ah((std::size_t)seq * dh);
    for (unsigned h = 0; h < heads; ++h) {
        col_slice(Qm, seq, dm, h, dh, Qh);
        col_slice(Km, seq, dm, h, dh, Kh);
        col_slice(Vm, seq, dm, h, dh, Vh);
        transpose(Kh, seq, dh, KhT);                    // dh×seq
        matmul(Qh, KhT, Sh, seq, seq, dh);
        matmul(Ps[h], Vh, Ah, seq, seq, dh);
        P.S.push_back(prove_gemm_v2(Qh, KhT, Sh, seq, seq, dh));
        P.A.push_back(prove_gemm_v2(Ps[h], Vh, Ah, seq, dh, seq));
        // concat A_h into the output matrix columns
        for (unsigned r = 0; r < seq; ++r)
            for (unsigned c = 0; c < dh; ++c)
                OUTm[(std::size_t)r * dm + (h * dh + c)] = Ah[(std::size_t)r * dh + c];
    }
    // the output projection: OUT = concat · Wo
    const std::vector<fp::fe> Fin = OUTm;
    matmul(Fin, Wo, OUTm, seq, dm, dm);
    P.OUT = prove_gemm_v2(Fin, Wo, OUTm, seq, dm, dm);
    return P;
}

struct AttnOutcome {
    bool structure_ok = false;
    bool legs_ok = false;       // every leg proof verifies against recomputed views
    bool pass = false;
    unsigned legs_checked = 0;
};

// THE VERIFIER: recomputes every leg from ITS OWN copies of the public
// inputs (the v2 honest boundary: verifier-held arrays), then runs the full
// v2 chain per leg. Any doctored leg — or a leg lifted from another head —
// dies in its own commitment cross-check.
inline AttnOutcome verify_attention(const AttnProof& P,
                                    const std::vector<fp::fe>& X,
                                    const std::vector<fp::fe>& Wq,
                                    const std::vector<fp::fe>& Wk,
                                    const std::vector<fp::fe>& Wv,
                                    const std::vector<fp::fe>& Wo,
                                    const std::vector<std::vector<fp::fe>>& Ps) noexcept {
    AttnOutcome o;
    if (!spec_ok(P.seq, P.dm, P.heads)) return o;
    if (P.dh != P.dm / P.heads) return o;
    if (Ps.size() != P.heads) return o;
    for (const auto& ph : Ps)
        if (ph.size() != (std::size_t)P.seq * P.seq) return o;
    if (P.S.size() != P.heads || P.A.size() != P.heads) return o;
    o.structure_ok = true;
    const unsigned seq = P.seq, dm = P.dm, heads = P.heads, dh = P.dh;
    std::vector<fp::fe> Qm((std::size_t)seq * dm), Km((std::size_t)seq * dm),
                         Vm((std::size_t)seq * dm), OUTm((std::size_t)seq * dm),
                         Fin((std::size_t)seq * dm);
    matmul(X, Wq, Qm, seq, dm, dm);
    matmul(X, Wk, Km, seq, dm, dm);
    matmul(X, Wv, Vm, seq, dm, dm);
    bool ok = true;
    unsigned checked = 0;
    ok &= verify_gemm_v2(P.Q, X, Wq, Qm); ++checked;
    ok &= verify_gemm_v2(P.K, X, Wk, Km); ++checked;
    ok &= verify_gemm_v2(P.V, X, Wv, Vm); ++checked;
    std::vector<fp::fe> Qh, Kh, Vh, KhT, Sh((std::size_t)seq * seq),
                         Ah((std::size_t)seq * dh);
    for (unsigned h = 0; h < heads && ok; ++h) {
        col_slice(Qm, seq, dm, h, dh, Qh);
        col_slice(Km, seq, dm, h, dh, Kh);
        col_slice(Vm, seq, dm, h, dh, Vh);
        transpose(Kh, seq, dh, KhT);
        matmul(Qh, KhT, Sh, seq, seq, dh);
        ok &= verify_gemm_v2(P.S[h], Qh, KhT, Sh); ++checked;
        matmul(Ps[h], Vh, Ah, seq, seq, dh);
        ok &= verify_gemm_v2(P.A[h], Ps[h], Vh, Ah); ++checked;
        for (unsigned r = 0; r < seq; ++r)
            for (unsigned c = 0; c < dh; ++c)
                Fin[(std::size_t)r * dm + (h * dh + c)] = Ah[(std::size_t)r * dh + c];
    }
    if (ok) {
        matmul(Fin, Wo, OUTm, seq, dm, dm);
        ok &= verify_gemm_v2(P.OUT, Fin, Wo, OUTm); ++checked;
    }
    o.legs_ok = ok;
    o.legs_checked = checked;
    o.pass = o.structure_ok && o.legs_ok;
    return o;
}

// ============ Phase 6.14 CLOSE (DEC-s5): the FULL path — P_h derived ======
//
// The fixed-point policy (in writing): X / W entries are q7 (canonical <
// 2^15, caller's contract). Each projection output is DE-SCALED >> 7 — the
// standard integer-transformer renormalization — so Q/K/V return to q7 and
// the scores S_h = Q_h·K_h^T are q14, exactly the softmax producer's domain.
// The de-scale is a floor on the canonical integer; the verifier applies the
// IDENTICAL op to ITS OWN recomputation, so the policy is self-consistent
// by construction. Everything downstream of S_h is DERIVED — the A legs are
// proven against the producer's P_h, and the verifier re-derives P_h from
// ITS OWN recomputed (and de-scaled) S_h before checking them.

// THE FIXED-POINT POLICY, PRECISELY: the projection legs are proven over the
// RAW products (the true GEMM statements — C = X·Wq etc.). The de-scale
// (>> 7, q14 -> q7) is PUBLIC deterministic post-processing applied to the
// verifier-held recomputed arrays AFTER the leg verifies — it needs no proof
// of its own, because both sides run the identical op on identical arrays.
// De-scaled Q/K/V feed the score legs, whose outputs are q14 — exactly the
// softmax producer's domain.

struct AttnFullProof {
    unsigned seq = 0, dm = 0, heads = 0, dh = 0;
    GemmProofV2 Q, K, V, OUT;
    std::vector<GemmProofV2> S;               // per-head score legs
    std::vector<GemmProofV2> A;               // per-head P·V legs
    std::vector<std::vector<int>> P_q7;       // the derived producer output
    std::vector<softmax::SoftmaxBatch> sm;    // the LogUp audit trail per head
};

// q7 deterministic fill for tests: canonical values in [1, 2^14)
inline void fill_q7(std::vector<fp::fe>& M, std::uint64_t seed) noexcept {
    std::uint64_t st = seed;
    for (std::size_t k = 0; k < M.size(); ++k) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        M[k] = fp::fe_from_u64((st * 0x9E3779B97F4A7C15ull) % 16384ull + 1);
    }
}

// THE DE-SCALE (the fixed-point renormalization): every canonical entry
// >> 7, q14 -> q7. Floor rounding; identical on both sides by construction.
inline void descale7(std::vector<fp::fe>& M) noexcept {
    for (auto& x : M) {
        const auto e = softmax::fe_u64(x);
        x = fp::fe_from_u64(e.ok ? e.v >> 7 : 0ull);
    }
}

// THE FULL PROVER. P_h never enters as an argument — there is nothing to
// fake. alpha seeds the per-head LogUp batches.
inline AttnFullProof prove_attention_full(const std::vector<fp::fe>& X,
                                          const std::vector<fp::fe>& Wq,
                                          const std::vector<fp::fe>& Wk,
                                          const std::vector<fp::fe>& Wv,
                                          const std::vector<fp::fe>& Wo,
                                          unsigned seq, unsigned dm, unsigned heads,
                                          const logup::Tables& T,
                                          std::uint64_t alpha) noexcept {
    const unsigned dh = dm / heads;
    AttnFullProof P;
    P.seq = seq; P.dm = dm; P.heads = heads; P.dh = dh;
    std::vector<fp::fe> Qraw((std::size_t)seq * dm), Kraw((std::size_t)seq * dm),
                         Vraw((std::size_t)seq * dm), OUTm((std::size_t)seq * dm);
    matmul(X, Wq, Qraw, seq, dm, dm);
    matmul(X, Wk, Kraw, seq, dm, dm);
    matmul(X, Wv, Vraw, seq, dm, dm);
    P.Q = prove_gemm_v2(X, Wq, Qraw, seq, dm, dm);   // the TRUE product
    P.K = prove_gemm_v2(X, Wk, Kraw, seq, dm, dm);
    P.V = prove_gemm_v2(X, Wv, Vraw, seq, dm, dm);
    descale7(Qraw); descale7(Kraw); descale7(Vraw);  // public post-processing
    const std::vector<fp::fe> Qm = Qraw, Km = Kraw, Vm = Vraw;
    P.S.reserve(heads); P.A.reserve(heads);
    P.P_q7.resize(heads); P.sm.reserve(heads);
    std::vector<fp::fe> Qh, Kh, Vh, KhT, Sh, Ah((std::size_t)seq * dh);
    for (unsigned h = 0; h < heads; ++h) {
        col_slice(Qm, seq, dm, h, dh, Qh);
        col_slice(Km, seq, dm, h, dh, Kh);
        col_slice(Vm, seq, dm, h, dh, Vh);
        transpose(Kh, seq, dh, KhT);
        Sh.assign((std::size_t)seq * seq, fp::fe_zero());
        matmul(Qh, KhT, Sh, seq, seq, dh);
        P.S.push_back(prove_gemm_v2(Qh, KhT, Sh, seq, seq, dh));
        // THE FENCE: P_h is PRODUCED from the proven scores — never supplied.
        P.sm.emplace_back(alpha + h);
        const auto R = softmax::softmax_rows(Sh, seq, T, &P.sm[h]);
        P.P_q7[h] = R.P;                        // the producer's own record
        std::vector<fp::fe> Pfe((std::size_t)seq * seq);
        for (std::size_t k = 0; k < R.P.size(); ++k)
            Pfe[k] = fp::fe_from_u64((std::uint64_t)R.P[k]);
        matmul(Pfe, Vh, Ah, seq, seq, dh);
        P.A.push_back(prove_gemm_v2(Pfe, Vh, Ah, seq, dh, seq));
        for (unsigned r = 0; r < seq; ++r)
            for (unsigned c = 0; c < dh; ++c)
                OUTm[(std::size_t)r * dm + (h * dh + c)] = Ah[(std::size_t)r * dh + c];
    }
    const std::vector<fp::fe> Fin = OUTm;
    matmul(Fin, Wo, OUTm, seq, dm, dm);
    P.OUT = prove_gemm_v2(Fin, Wo, OUTm, seq, dm, dm);
    return P;
}

struct AttnFullOutcome {
    bool structure_ok = false;
    bool legs_ok = false;
    bool softmax_ok = false;      // every head's LogUp batch balances BOTH sides
    bool pass = false;
    unsigned legs_checked = 0;
};

// THE FULL VERIFIER: recomputes Q/K/V, verifies the projection legs,
// recomputes S_h, verifies the score legs, RE-DERIVES P_h through the same
// certified producer, verifies the A legs AGAINST THE DERIVED P_h, then the
// output leg. A proof carrying a doctored P_h dies here without a dedicated
// check — the A-leg sumcheck is simply run on the derived object.
inline AttnFullOutcome verify_attention_full(const AttnFullProof& P,
                                             const std::vector<fp::fe>& X,
                                             const std::vector<fp::fe>& Wq,
                                             const std::vector<fp::fe>& Wk,
                                             const std::vector<fp::fe>& Wv,
                                             const std::vector<fp::fe>& Wo,
                                             const logup::Tables& T) noexcept {
    AttnFullOutcome o;
    if (!spec_ok(P.seq, P.dm, P.heads)) return o;
    if (P.dh != P.dm / P.heads) return o;
    if (P.S.size() != P.heads || P.A.size() != P.heads) return o;
    if (P.P_q7.size() != P.heads || P.sm.size() != P.heads) return o;
    for (unsigned h = 0; h < P.heads; ++h)
        if (P.P_q7[h].size() != (std::size_t)P.seq * P.seq) return o;
    o.structure_ok = true;
    const unsigned seq = P.seq, dm = P.dm, heads = P.heads, dh = P.dh;
    std::vector<fp::fe> Qraw((std::size_t)seq * dm), Kraw((std::size_t)seq * dm),
                         Vraw((std::size_t)seq * dm), OUTm((std::size_t)seq * dm),
                         Fin((std::size_t)seq * dm);
    matmul(X, Wq, Qraw, seq, dm, dm);
    matmul(X, Wk, Kraw, seq, dm, dm);
    matmul(X, Wv, Vraw, seq, dm, dm);
    bool ok = true, smok = true;
    unsigned checked = 0;
    ok &= verify_gemm_v2(P.Q, X, Wq, Qraw); ++checked;   // over the TRUE product
    ok &= verify_gemm_v2(P.K, X, Wk, Kraw); ++checked;
    ok &= verify_gemm_v2(P.V, X, Wv, Vraw); ++checked;
    descale7(Qraw); descale7(Kraw); descale7(Vraw);      // public post-processing
    const std::vector<fp::fe> Qm = Qraw, Km = Kraw, Vm = Vraw;
    std::vector<fp::fe> Qh, Kh, Vh, KhT, Sh, Ah((std::size_t)seq * dh);
    for (unsigned h = 0; h < heads && ok; ++h) {
        col_slice(Qm, seq, dm, h, dh, Qh);
        col_slice(Km, seq, dm, h, dh, Kh);
        col_slice(Vm, seq, dm, h, dh, Vh);
        transpose(Kh, seq, dh, KhT);
        Sh.assign((std::size_t)seq * seq, fp::fe_zero());
        matmul(Qh, KhT, Sh, seq, seq, dh);
        ok &= verify_gemm_v2(P.S[h], Qh, KhT, Sh); ++checked;
        // re-derive: the verifier's OWN producer run over the verifier's OWN
        // recomputed scores — the proof's P_q7 is cross-checked, never trusted.
        const auto R = softmax::softmax_rows(Sh, seq, T, nullptr);
        smok &= R.ok;
        if (!R.ok) { ok = false; break; }              // contract violation: dead
        if (R.P != P.P_q7[h]) { ok = false; break; }   // carried record must match
        std::vector<fp::fe> Pfe((std::size_t)seq * seq);
        for (std::size_t k = 0; k < R.P.size(); ++k)
            Pfe[k] = fp::fe_from_u64((std::uint64_t)R.P[k]);
        matmul(Pfe, Vh, Ah, seq, seq, dh);
        ok &= verify_gemm_v2(P.A[h], Pfe, Vh, Ah); ++checked;
        if (!ok) break;
        for (unsigned r = 0; r < seq; ++r)
            for (unsigned c = 0; c < dh; ++c)
                Fin[(std::size_t)r * dm + (h * dh + c)] = Ah[(std::size_t)r * dh + c];
    }
    if (ok) {
        // the LogUp audit trail: both sides must balance for every head
        for (unsigned h = 0; h < heads; ++h)
            smok &= P.sm[h].balanced([&T](unsigned i){ return softmax::exp_at(T, i); },
                                     [&T](unsigned i){ return softmax::rcp_at(T, i); });
        matmul(Fin, Wo, OUTm, seq, dm, dm);
        ok &= verify_gemm_v2(P.OUT, Fin, Wo, OUTm); ++checked;
    }
    o.legs_ok = ok;
    o.softmax_ok = smok;
    o.legs_checked = checked;
    o.pass = o.structure_ok && o.legs_ok && o.softmax_ok;
    return o;
}

} // namespace hsma::pouw::attn
