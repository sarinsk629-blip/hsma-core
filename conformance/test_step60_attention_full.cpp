// HSMA :: test_step60 - Phase 6.14 CLOSE + 6.19 fence (DEC-s5): the FULL
// attention path — P_h is DERIVED by the certified producer, never supplied.
//   P1 the full pipeline : X -> Q/K/V (proven) -> S_h (proven) -> P_h
//                          (table producer) -> A_h (proven vs derived P)
//                          -> OUT (proven); every leg's full v2 chain verifies
//   P2 the softmax law   : the derived P matches the real softmax of the
//                          recomputed scores within the q7 drift; both LogUp
//                          sides balance for every head
//   P3 THE FENCE CLOSURE : a proof whose A leg is re-proven against a
//                          DOCTORED P (the attack the rung-1 scaffold could
//                          not even express as an attack) is REJECTED — the
//                          verifier's own producer run is the arbiter
//   P4 tamper evidence   : a flipped X entry kills the projection legs
//   P5 the legacy path   : prove_attention (P_h as input) still verifies —
//                          documented as the s4 rung, NOT the production path
#include <hsma/pouw/attention.hpp>
#include <hsma/pouw/logup_ref.hpp>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <vector>
using namespace hsma;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

int main() {
    std::printf("test_step60: attention FULL path — the 6.14 fence, closed\n");
    const unsigned seq = 4, dm = 8, heads = 2, dh = dm / heads;
    const auto T = pouw::logup::build_all();
    chk(T.certified, "P0 tables certified");

    // q7-contract inputs, TAMED for a live softmax distribution: reals in
    // [1/128, 0.5) so the de-scaled scores spread across the exp window
    // instead of degenerating to one-hot
    auto fill_tamed = [](std::vector<fp::fe>& M, std::uint64_t seed) {
        std::uint64_t st = seed;
        for (std::size_t k = 0; k < M.size(); ++k) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            M[k] = fp::fe_from_u64((st * 0x9E3779B97F4A7C15ull) % 64ull + 1);
        }
    };
    std::vector<fp::fe> X((std::size_t)seq * dm), Wq((std::size_t)dm * dm),
        Wk((std::size_t)dm * dm), Wv((std::size_t)dm * dm), Wo((std::size_t)dm * dm);
    fill_tamed(X, 0x4174746Eull);       // "Attn"
    fill_tamed(Wq, 0x5711ull);
    fill_tamed(Wk, 0x5722ull);
    fill_tamed(Wv, 0x5733ull);
    fill_tamed(Wo, 0x5744ull);

    // ---- P1: the full pipeline ----
    auto P = pouw::attn::prove_attention_full(X, Wq, Wk, Wv, Wo,
                                              seq, dm, heads, T, 900);
    chk(P.Q.rows == seq && P.Q.inner == dm, "P1 projection legs shaped seq x dm x dm");
    auto o = pouw::attn::verify_attention_full(P, X, Wq, Wk, Wv, Wo, T);
    chk(o.structure_ok, "P1 structure ok");
    chk(o.legs_checked == 3 + heads + heads + 1, "P1 all legs checked (2*heads + 4)");
    chk(o.legs_ok && o.softmax_ok && o.pass,
        "P1 FULL pipeline VERIFIES (legs + LogUp both sides)");

    // ---- P2: the derived P matches the real softmax ----
    {
        std::vector<fp::fe> Qm, Km, Vm;
        pouw::attn::matmul(X, Wq, Qm, seq, dm, dm);
        pouw::attn::matmul(X, Wk, Km, seq, dm, dm);
        pouw::attn::matmul(X, Wv, Vm, seq, dm, dm);
        pouw::attn::descale7(Qm); pouw::attn::descale7(Km);
        pouw::attn::descale7(Vm);              // the policy, replicated
        double worst = 0.0;
        for (unsigned h = 0; h < heads; ++h) {
            std::vector<fp::fe> Qh, Kh, Vh, KhT, Sh;
            pouw::attn::col_slice(Qm, seq, dm, h, dh, Qh);
            pouw::attn::col_slice(Km, seq, dm, h, dh, Kh);
            pouw::attn::col_slice(Vm, seq, dm, h, dh, Vh);
            pouw::attn::transpose(Kh, seq, dh, KhT);
            pouw::attn::matmul(Qh, KhT, Sh, seq, seq, dh);
            const auto sq = pouw::softmax::fe_u64(Sh[0]);   // spot: row 0 col 0
            (void)sq;
            double mx = -1, sum = 0;
            std::vector<double> sr(seq);
            for (unsigned r = 0; r < seq; ++r) {
                double m2 = -1;
                std::vector<double> row(seq);
                for (unsigned c = 0; c < seq; ++c) {
                    const auto e = pouw::softmax::fe_u64(
                        Sh[(std::size_t)r * seq + c]);
                    row[c] = double(e.v) / 16384.0;
                    m2 = std::max(m2, row[c]);
                }
                mx = std::max(mx, 0.0); (void)mx;
                double s2 = 0;
                for (unsigned c = 0; c < seq; ++c) {
                    row[c] = std::exp(row[c] - m2); s2 += row[c];
                }
                for (unsigned c = 0; c < seq; ++c) sr[c] = row[c] / s2;
                for (unsigned c = 0; c < seq; ++c)
                    worst = std::max(worst, std::abs(
                        P.P_q7[h][(std::size_t)r * seq + c] / 128.0 - sr[c]));
                sum += 0; (void)sum;
            }
            int psum = 0;
            for (int v : P.P_q7[h]) psum += v;
            // per-head drift: every entry floors toward ~0.5 q7-unit, so a
            // seq*seq grid drifts up to ~seq^2/2 — measured 5 at seq=4
            chk(std::abs(psum - 128 * (int)seq) <= (int)(seq * seq) / 2 + 2,
                "P2 every head's rows sum to ~128 each (softmax law)");
        }
        std::printf("  [info] worst |P - real softmax| = %.5f\\n", worst);
        chk(worst <= 0.02, "P2 derived P within the pinned 0.02 drift");
    }

    // ---- P3: THE FENCE CLOSURE — the doctored-P attack dies ----
    {
        // re-prove head 0's A leg against P+5 (a doctored attention weight)
        std::vector<fp::fe> Qm, Km, Vm;
        pouw::attn::matmul(X, Wq, Qm, seq, dm, dm);
        pouw::attn::matmul(X, Wk, Km, seq, dm, dm);
        pouw::attn::matmul(X, Wv, Vm, seq, dm, dm);
        pouw::attn::descale7(Vm);
        std::vector<fp::fe> Vh, Ah((std::size_t)seq * dh);
        pouw::attn::col_slice(Vm, seq, dm, 0, dh, Vh);
        std::vector<fp::fe> Pfe((std::size_t)seq * seq);
        for (std::size_t k = 0; k < Pfe.size(); ++k)
            Pfe[k] = fp::fe_from_u64((std::uint64_t)P.P_q7[0][k] + 5ull); // DOCTORED
        pouw::attn::matmul(Pfe, Vh, Ah, seq, seq, dh);
        P.A[0] = pouw::prove_gemm_v2(Pfe, Vh, Ah, seq, dh, seq);   // self-consistent leg
        for (std::size_t k = 0; k < Pfe.size(); ++k)
            P.P_q7[0][k] += 5;                                     // carried record matches
        const auto o2 = pouw::attn::verify_attention_full(P, X, Wq, Wk, Wv, Wo, T);
        chk(!o2.pass, "P3 doctored-P proof REJECTED (the fence holds)");
        chk(!o2.legs_ok, "P3 the A-leg sumcheck dies against the DERIVED P");
    }

    // ---- P4: tamper evidence — flipped X ----
    {
        auto X2 = X;
        X2[3] = fp::fe_add(X2[3], fp::fe_one());
        const auto o3 = pouw::attn::verify_attention_full(P, X2, Wq, Wk, Wv, Wo, T);
        chk(!o3.pass, "P4 flipped X REJECTED by the projection legs");
    }

    // ---- P5: the legacy scaffold still verifies (documented rung) ----
    {
        std::vector<std::vector<fp::fe>> Ps(heads);
        // honest P from the producer, fed to the LEGACY API
        for (unsigned h = 0; h < heads; ++h)
            for (std::size_t k = 0; k < P.P_q7[h].size(); ++k)
                Ps[h].push_back(fp::fe_from_u64((std::uint64_t)P.P_q7[h][k]));
        const auto LP = pouw::attn::prove_attention(X, Wq, Wk, Wv, Wo, Ps,
                                                    seq, dm, heads);
        const auto lo = pouw::attn::verify_attention(LP, X, Wq, Wk, Wv, Wo, Ps);
        chk(lo.pass, "P5 legacy scaffold verifies (the s4 rung, kept for receipts)");
    }

    std::printf("test_step60: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
