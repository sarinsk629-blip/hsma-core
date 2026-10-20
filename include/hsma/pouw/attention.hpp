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
// post-scale attention weights — is an INPUT to this scaffold, not a proven
// object. Softmax is exp + division over the reals; in a float-free field
// core (DEC-090) it is TABLE work: the 6.14 softmax table via the 0-LSB
// oracle machinery, with the 1/sqrt(d) scale riding the RCP machinery
// (step49). Laying the legs first is the honest rung: when the table lands,
// softmax(S_h) drops in as the P_h producer and NOTHING else moves.
//
// The K_h^T transpose is materialized physically (dh×seq row-major) — a
// layout operation, not a new proof obligation.
#pragma once
#include <hsma/pouw.hpp>
#include <hsma/fe.hpp>
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
        matmul(Ps[h], Vh, Ah, seq, dh, seq);
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
        matmul(Ps[h], Vh, Ah, seq, dh, seq);
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

} // namespace hsma::pouw::attn
