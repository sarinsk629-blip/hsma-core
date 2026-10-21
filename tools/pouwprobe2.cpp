// HSMA :: pouwprobe2.cpp - P1-18 (DEC-248): the FS-bound PoUW probe.
// [G1] honest v2 -> ACCEPT   [G2] faked output -> REJECT
// [G3] faked witness -> REJECT  [G4] faked final-eval -> REJECT (DEFECT-163
// regression under FS)  [G5] comC tampered -> REJECT
// [G6] 128^3 predictive: nv=7, sc::verify must print 7, ACCEPT.
#include <hsma/pouw.hpp>
#include <cstdio>
#include <vector>
#include <chrono>
using namespace hsma;

static void fill_rand(std::vector<fp::fe>& v, std::uint64_t seed) {
    std::uint64_t st = seed * 0x9E3779B97F4A7C15ull + 1;
    for (auto& x : v) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        x = fp::fe_from_u64(st);
    }
}

int main() {
    constexpr unsigned rows = 3, cols = 3, inner = 3;
    std::vector<fp::fe> Am(rows*inner), Bm(inner*cols), Cm(rows*cols);
    fill_rand(Am, 11); fill_rand(Bm, 22);
    for (unsigned i = 0; i < rows; ++i)
        for (unsigned j = 0; j < cols; ++j) {
            fp::fe acc = fp::fe_zero();
            for (unsigned k = 0; k < inner; ++k)
                acc = fp::fe_add(acc, fp::fe_mul(Am[i*inner+k], Bm[k*cols+j]));
            Cm[i*cols+j] = acc;
        }

    auto P1 = pouw::prove_gemm_v2(Am, Bm, Cm, rows, cols, inner);
    std::printf("[G1] honest v2: %s\n",
        pouw::verify_gemm_v2(P1, Am, Bm, Cm) ? "ACCEPT" : "REJECT!!");

    { auto Cb = Cm; Cb[4] = fp::fe_add(Cb[4], fp::fe_one());
      auto P2 = pouw::prove_gemm_v2(Am, Bm, Cb, rows, cols, inner);
      std::printf("[G2] fake output: %s (must REJECT)\n",
        pouw::verify_gemm_v2(P2, Am, Bm, Cm) ? "ACCEPT!!" : "REJECT"); }

    { auto Bb = Bm;
      for (unsigned k = 0; k < inner; ++k) Bb[k*cols+0] = Bm[k*cols+1];
      auto P3 = pouw::prove_gemm_v2(Am, Bb, Cm, rows, cols, inner);
      std::printf("[G3] fake witness: %s (must REJECT)\n",
        pouw::verify_gemm_v2(P3, Am, Bm, Cm) ? "ACCEPT!!" : "REJECT"); }

    { auto P4 = P1; P4.T.fa = fp::fe_add(P4.T.fa, fp::fe_one());
      std::printf("[G4] fake final-eval: %s (must REJECT)\n",
        pouw::verify_gemm_v2(P4, Am, Bm, Cm) ? "ACCEPT!!" : "REJECT"); }

    { auto P5 = P1; P5.comC = fp::fe_add(P5.comC, fp::fe_one());
      std::printf("[G5] comC tampered: %s (must REJECT)\n",
        pouw::verify_gemm_v2(P5, Am, Bm, Cm) ? "ACCEPT!!" : "REJECT"); }

    {   constexpr unsigned N = 128;
        std::vector<fp::fe> A2(N*N), B2(N*N), C2(N*N);
        fill_rand(A2, 7); fill_rand(B2, 9);
        auto t0 = std::chrono::steady_clock::now();
        for (unsigned i = 0; i < N; ++i)
            for (unsigned j = 0; j < N; ++j) {
                fp::fe acc = fp::fe_zero();
                for (unsigned k = 0; k < N; ++k)
                    acc = fp::fe_add(acc, fp::fe_mul(A2[i*N+k], B2[k*N+j]));
                C2[i*N+j] = acc;
            }
        auto P6 = pouw::prove_gemm_v2(A2, B2, C2, N, N, N);
        const unsigned vr = sc::verify(P6.T, P6.claim);
        const bool ok = pouw::verify_gemm_v2(P6, A2, B2, C2);
        auto t1 = std::chrono::steady_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        std::printf("[G6] 128^3: nv=%u sc::verify=%u (predict 7) -> %s | %.0f ms | %u MACs\n",
                    P6.T.nv, vr, ok ? "ACCEPT" : "REJECT!!", ms, N*N*N);
    }
    return 0;
}
