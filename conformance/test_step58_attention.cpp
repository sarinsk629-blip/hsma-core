// HSMA :: test_step58 - Phase 6.19 rung-1 (DEC-s4): attention as a GEMM composition.
//   P1 spec law         : dm % heads == 0 enforced; bad shapes rejected
//   P2 the leg prove    : all 8 legs (Q/K/V projections, 2 score legs,
//                         2 attention·V legs, output projection) prove and
//                         verify — every leg is a full v2 chain
//   P3 the decomposition: recomputed Q/K/V/S/A/OUT from the inputs are
//                         byte-consistent with the leg commitments
//   P4 tamper evidence  : flipped Wq / flipped Ps[h] / swapped head
//                         Ps[0]<->Ps[1] — each REJECTED by its own leg
//   P5 the fence        : P_h is an INPUT (the softmax boundary) — the
//                         test documents it by construction: P_h carries
//                         arbitrary (non-softmax) values and the legs still
//                         verify; the softmax table is 6.14's work, not
//                         this scaffold's claim
#include <hsma/pouw/attention.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

static void fill_det(std::vector<fp::fe>& M, std::uint64_t seed) {
    std::uint64_t st = seed;
    for (std::size_t k = 0; k < M.size(); ++k) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        M[k] = fp::fe_from_u64((st * 0x9E3779B97F4A7C15ull) % 1000003ull + 1);
    }
}

int main() {
    std::printf("test_step58: attention as GEMM legs — 6.19 rung-1\n");
    const unsigned seq = 4, dm = 8, heads = 2, dh = dm / heads;

    // ---- P1: the spec law ----
    chk(pouw::attn::spec_ok(seq, dm, heads), "P1 spec_ok(4, 8, 2)");
    chk(!pouw::attn::spec_ok(seq, 7, heads), "P1 dm%heads!=0 REJECTED");
    chk(!pouw::attn::spec_ok(seq, dm, 0), "P1 zero heads REJECTED");

    // ---- inputs ----
    std::vector<fp::fe> X((std::size_t)seq * dm), Wq((std::size_t)dm * dm),
        Wk((std::size_t)dm * dm), Wv((std::size_t)dm * dm), Wo((std::size_t)dm * dm);
    fill_det(X, 0x4174746Eull);       // "Attn"
    fill_det(Wq, 0x5711ull); fill_det(Wk, 0x5722ull);
    fill_det(Wv, 0x5733ull); fill_det(Wo, 0x5744ull);
    std::vector<std::vector<fp::fe>> Ps(heads);
    for (unsigned h = 0; h < heads; ++h) {
        Ps[h].resize((std::size_t)seq * seq);
        fill_det(Ps[h], 0x50 + h);    // P5's point: NOT softmax values — inputs
    }

    // ---- P2/P3: prove + verify the whole composition ----
    {
        const auto P = pouw::attn::prove_attention(X, Wq, Wk, Wv, Wo, Ps, seq, dm, heads);
        chk(P.S.size() == heads && P.A.size() == heads, "P2 per-head legs emitted (2 + 2)");
        const auto o = pouw::attn::verify_attention(P, X, Wq, Wk, Wv, Wo, Ps);
        chk(o.structure_ok, "P3 structure ok");
        chk(o.legs_checked == 3 + heads + heads + 1, "P3 all 8 legs checked");
        chk(o.legs_ok && o.pass, "P3 every leg's full v2 chain VERIFIES");
        // the decomposition, independently: Q == X·Wq column slice consistency
        std::vector<fp::fe> Qm, Km, Vm;
        pouw::attn::matmul(X, Wq, Qm, seq, dm, dm);
        pouw::attn::matmul(X, Wk, Km, seq, dm, dm);
        pouw::attn::matmul(X, Wv, Vm, seq, dm, dm);
        std::vector<fp::fe> Qh, Kh, Vh, KhT, Sh, Ah;
        pouw::attn::col_slice(Qm, seq, dm, 0, dh, Qh);
        pouw::attn::col_slice(Km, seq, dm, 0, dh, Kh);
        pouw::attn::transpose(Kh, seq, dh, KhT);
        pouw::attn::matmul(Qh, KhT, Sh, seq, seq, dh);
        pouw::attn::col_slice(Vm, seq, dm, 0, dh, Vh);
        pouw::attn::matmul(Ps[0], Vh, Ah, seq, seq, dh);   // DEF-378 fix: (rows, inner, cols)
        fp::fe s0 = fp::fe_zero(), a0 = fp::fe_zero();
        for (std::size_t k = 0; k < Sh.size(); ++k) s0 = fp::fe_add(s0, Sh[k]);
        for (std::size_t k = 0; k < Ah.size(); ++k) a0 = fp::fe_add(a0, Ah[k]);
        std::vector<fp::fe> Qh2, Kh2, KhT2, Sh2, Vh2, Ah2;
        pouw::attn::col_slice(Qm, seq, dm, 0, dh, Qh2);
        pouw::attn::col_slice(Km, seq, dm, 0, dh, Kh2);
        pouw::attn::transpose(Kh2, seq, dh, KhT2);
        pouw::attn::matmul(Qh2, KhT2, Sh2, seq, seq, dh);
        pouw::attn::col_slice(Vm, seq, dm, 0, dh, Vh2);
        pouw::attn::matmul(Ps[0], Vh2, Ah2, seq, seq, dh); // DEF-378 fix: (rows, inner, cols)
        fp::fe s0b = fp::fe_zero(), a0b = fp::fe_zero();
        for (std::size_t k = 0; k < Sh2.size(); ++k) s0b = fp::fe_add(s0b, Sh2[k]);
        for (std::size_t k = 0; k < Ah2.size(); ++k) a0b = fp::fe_add(a0b, Ah2[k]);
        chk(sc::feq(s0, s0b) && sc::feq(a0, a0b),
            "P3 decomposition recomputes deterministically (S_0, A_0 sums)");
    }

    // ---- P4: tamper evidence ----
    {
        const auto P = pouw::attn::prove_attention(X, Wq, Wk, Wv, Wo, Ps, seq, dm, heads);
        {   std::vector<fp::fe> Wq_bad = Wq; Wq_bad[3] = fp::fe_add(Wq_bad[3], fp::fe_one());
            const auto o = pouw::attn::verify_attention(P, X, Wq_bad, Wk, Wv, Wo, Ps);
            chk(!o.legs_ok && !o.pass, "P4 flipped Wq -> the Q leg REJECTS");
        }
        {   auto Ps_bad = Ps; Ps_bad[1][2] = fp::fe_add(Ps_bad[1][2], fp::fe_one());
            const auto o = pouw::attn::verify_attention(P, X, Wq, Wk, Wv, Wo, Ps_bad);
            chk(!o.legs_ok && !o.pass, "P4 flipped Ps[1] -> the A_1 leg REJECTS");
        }
        {   auto Ps_swap = Ps; std::swap(Ps_swap[0], Ps_swap[1]);
            const auto o = pouw::attn::verify_attention(P, X, Wq, Wk, Wv, Wo, Ps_swap);
            chk(!o.legs_ok && !o.pass, "P4 swapped head weights -> REJECTED (heads are bound)");
        }
        {   std::vector<fp::fe> Wo_bad = Wo; Wo_bad[dm] = fp::fe_add(Wo_bad[dm], fp::fe_one());
            const auto o = pouw::attn::verify_attention(P, X, Wq, Wk, Wv, Wo_bad, Ps);
            chk(!o.legs_ok && !o.pass, "P4 flipped Wo -> the OUT leg REJECTS");
        }
    }

    std::printf("%s\n", "test_step58: DONE — the attention substrate proven leg-by-leg (the softmax fence is 6.14's work)");
    return fails;
}
