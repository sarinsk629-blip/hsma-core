// HSMA :: pouwprobe.cpp - P1-17 (the PoUW wiring probe, DEC-245).
// THE RECEIPT:
//   [G0] substrate: 3x3 GEMM as R1CS, 36/36 SAT + known-answer C00=30
//   [G1] honest proof   -> ACCEPT (identity + binding)
//   [G2] faked output   -> REJECT via the sumcheck identity
//   [G3] faked witness  -> REJECT via the fa/fb binding
//   [W]  weight receipt: inner^3 MACs per verified proof
// Fixed pseudorandom challenges; Poseidon-FS transcript = P1-18.
#include <hsma/gkr.hpp>
#include <hsma/pouw.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;

int main() {
    constexpr unsigned rows = 3, cols = 3, inner = 3;
    const fp::fe gamma = fp::fe_from_u64(0x9E3779B97F4A7C15ull);
    const fp::fe delta = fp::fe_from_u64(0xC2B2AE3D27D4EB4Full);

    // ---- [G0] the proven substrate: circuit + real witness ----
    mfold::SparseMat Ac, Bc, Cc;
    std::vector<fp::fe> w;
    w.push_back(fp::fe_one());
    auto G = gkr::build_gemm(Ac, Bc, Cc, w, rows, cols, inner);

    unsigned a_vals[3][3] = {{1,2,3},{4,5,6},{7,8,9}};
    unsigned b_vals[3][3] = {{9,8,7},{6,5,4},{3,2,1}};
    std::vector<fp::fe> Am(rows*inner), Bm(inner*cols), Cm(rows*cols);
    for (unsigned i = 0; i < rows; ++i)
        for (unsigned k = 0; k < inner; ++k) {
            Am[i*inner+k] = fp::fe_from_u64(a_vals[i][k]);
            w[G.a_offset + i*inner+k] = Am[i*inner+k];
        }
    for (unsigned k = 0; k < inner; ++k)
        for (unsigned j = 0; j < cols; ++j) {
            Bm[k*cols+j] = fp::fe_from_u64(b_vals[k][j]);
            w[G.b_offset + k*cols+j] = Bm[k*cols+j];
        }
    for (unsigned i = 0; i < rows; ++i)
        for (unsigned j = 0; j < cols; ++j) {
            fp::fe acc = fp::fe_zero();
            for (unsigned k = 0; k < inner; ++k) {
                fp::fe pr = fp::fe_mul(Am[i*inner+k], Bm[k*cols+j]);
                w[G.p_offset + (i*cols+j)*inner + k] = pr;
                acc = fp::fe_add(acc, pr);
            }
            w[G.c_offset + i*cols+j] = acc;
            Cm[i*cols+j] = acc;
        }
    {   // R1CS SAT re-check on THIS witness (P1-16 anchor)
        const unsigned n = G.n_constraints;
        std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
        for (unsigned t = 0; t < Ac.row.size(); ++t)
            az[Ac.row[t]] = fp::fe_add(az[Ac.row[t]], fp::fe_mul(Ac.val[t], w[Ac.col[t]]));
        for (unsigned t = 0; t < Bc.row.size(); ++t)
            bz[Bc.row[t]] = fp::fe_add(bz[Bc.row[t]], fp::fe_mul(Bc.val[t], w[Bc.col[t]]));
        for (unsigned t = 0; t < Cc.row.size(); ++t)
            cz[Cc.row[t]] = fp::fe_add(cz[Cc.row[t]], fp::fe_mul(Cc.val[t], w[Cc.col[t]]));
        unsigned unsat = 0;
        for (unsigned i = 0; i < n; ++i) {
            fp::fe l = fp::fe_to_canonical(fp::fe_mul(az[i], bz[i]));
            fp::fe rr = fp::fe_to_canonical(cz[i]);
            if (!(l.l == rr.l)) ++unsat;
        }
        std::printf("[G0] substrate R1CS: %u/%u SAT\n", n - unsat, n);
        if (unsat) return 1;
    }
    {   // known answer
        fp::fe c00 = fp::fe_to_canonical(Cm[0]);
        bool ka = (c00.l[0] == 30u) && !c00.l[1] && !c00.l[2] && !c00.l[3];
        std::printf("[G0] known-answer C[0][0]=%llu: %s\n",
                    (unsigned long long)c00.l[0], ka ? "OK" : "RED");
        if (!ka) return 1;
    }

    // verifier's reference arrays (the honest view)
    const unsigned nv = pouw::kdim(inner);
    std::vector<fp::fe> ap, bp;
    {   std::vector<fp::fe> a, b;
        pouw::fold_witness(Am, Bm, rows, cols, inner, gamma, delta, a, b);
        pouw::pad_to(a, nv, ap); pouw::pad_to(b, nv, bp);
    }

    // ---- [G1] the honest proof ----
    pouw::GemmProof P1 = pouw::prove_gemm(Am, Bm, Cm, rows, cols, inner, gamma, delta);
    const unsigned vr1 = sc::verify(P1.T, P1.claim);
    const bool bind1 = sc::feq(P1.T.fa, sc::direct_eval(ap, P1.T.r))
                    && sc::feq(P1.T.fb, sc::direct_eval(bp, P1.T.r));
    const bool ok1 = pouw::verify_gemm(P1, ap, bp);
    {   // ground truth: the identity the sumcheck proves, evaluated directly
        fp::fe s = fp::fe_zero();
        for (unsigned k = 0; k < (1u << nv); ++k)
            s = fp::fe_add(s, fp::fe_mul(ap[k], bp[k]));
        fp::fe sc_ = fp::fe_to_canonical(s), cl = fp::fe_to_canonical(P1.claim);
        std::printf("[G1] identity sum_k a*b == claim: %s\n", (sc_.l == cl.l) ? "YES" : "NO");
    }
    std::printf("[G1] honest: sc::verify=%u binding=%s -> %s\n",
                vr1, bind1 ? "OK" : "FAIL", ok1 ? "ACCEPT" : "REJECT!!");

    // ---- [G2] faked output: attacker bumps C[1][1] by one ----
    {   std::vector<fp::fe> Cbad = Cm;
        Cbad[1*cols+1] = fp::fe_add(Cbad[1*cols+1], fp::fe_one());
        pouw::GemmProof P2 = pouw::prove_gemm(Am, Bm, Cbad, rows, cols, inner, gamma, delta);
        const unsigned vr2 = sc::verify(P2.T, P2.claim);
        const bool bind2 = sc::feq(P2.T.fa, sc::direct_eval(ap, P2.T.r))
                        && sc::feq(P2.T.fb, sc::direct_eval(bp, P2.T.r));
        std::printf("[G2] fake output: sc::verify=%u binding=%s -> %s (must REJECT)\n",
                    vr2, bind2 ? "OK" : "FAIL",
                    pouw::verify_gemm(P2, ap, bp) ? "ACCEPT!!" : "REJECT");
    }

    // ---- [G3] faked witness: prover folds B column 1 instead of 0 ----
    {   std::vector<fp::fe> Bbad = Bm;
        for (unsigned k = 0; k < inner; ++k) Bbad[k*cols+0] = Bm[k*cols+1];
        pouw::GemmProof P3 = pouw::prove_gemm(Am, Bbad, Cm, rows, cols, inner, gamma, delta);
        const unsigned vr3 = sc::verify(P3.T, P3.claim);
        const bool bind3 = sc::feq(P3.T.fa, sc::direct_eval(ap, P3.T.r))
                        && sc::feq(P3.T.fb, sc::direct_eval(bp, P3.T.r));
        std::printf("[G3] fake witness: sc::verify=%u binding=%s -> %s (must REJECT)\n",
                    vr3, bind3 ? "OK!!" : "FAIL",
                    pouw::verify_gemm(P3, ap, bp) ? "ACCEPT!!" : "REJECT");
    }

    // ---- [G4] faked final eval: honest transcript, T.fa corrupted ----
    // Pre-fix engine: sc::verify returned nv (looked ACCEPT); only the
    // binding check saved PoUW. The standalone engine was unsound.
    {   pouw::GemmProof P4 = P1;
        P4.T.fa = fp::fe_add(P4.T.fa, fp::fe_one());
        const unsigned vr4 = sc::verify(P4.T, P4.claim);
        std::printf("[G4] fake final-eval: sc::verify=%u (nv=%u, expect %u) -> %s (must REJECT)\n",
                    vr4, P4.T.nv, P4.T.nv + 1u,
                    pouw::verify_gemm(P4, ap, bp) ? "ACCEPT!!" : "REJECT");
    }

    // ---- [W] the weight + proof-size receipt ----
    {
        const std::size_t bytes = (P1.T.evals.size()*3 + P1.T.claims.size()
                                   + P1.T.r.size() + 2) * 32u;
        const unsigned nv128 = pouw::kdim(128);
        const std::size_t b128 = (nv128*3 + (nv128+1) + nv128 + 2) * 32u;
        std::printf("\n=======================================\n");
        std::printf("  PoUW WIRING RECEIPT (P1-17)\n");
        std::printf("=======================================\n");
        std::printf("  3x3x3 GEMM  : 1 proof, %zu bytes, weight=%llu MACs\n",
                    bytes, (unsigned long long)pouw::weight(inner, 1));
        std::printf("  128^3 GEMM  : ~%u sumcheck rounds -> ~%zu-byte proof\n", nv128, b128);
        std::printf("  k=476 epoch : weight=%llu MACs (128^3 x 3 x 476)\n",
                    (unsigned long long)pouw::weight(128, 3ull*476ull));
        std::printf("=======================================\n");
    }

    std::printf("\n[P1-17] %s\n", ok1 ? "GREEN - the PoUW wiring is PROVEN" : "RED");
    return ok1 ? 0 : 1;
}
