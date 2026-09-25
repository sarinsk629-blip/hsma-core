// HSMA :: p19probe.cpp - P1-19 (DEC-263): the externally-submittable PoUW.
// [P3-forge] kernel shift across SUMMED batch commits (the naive >8 pattern):
//            z != z' but commit(z0..7,r1)+commit(z8..15,r2) EQUAL
// [P3-fix]   commit_vec (per-position bases): z != z' -> commits DIFFER
// [P3-ok]    honest external flow n=4: ACCEPT - verifier never multiplied
// [P3-fakeA] self-consistent proof over a SHIFTED model -> REJECT (Pedersen)
// [P3-fakeC] tampered output -> REJECT (identity)
// [P3-time]  n=64: prover vs verifier wall time - honest numbers, no winner claim
#include <hsma/pouw.hpp>
#include "pedersen_golden.hpp"
#include <chrono>
#include <cstdio>
#include <vector>
using namespace hsma;

static void fill(std::vector<fp::fe>& v, std::uint64_t seed) {
    std::uint64_t st = seed * 0x9E3779B97F4A7C15ull + 1;
    for (auto& x : v) { st ^= st<<13; st ^= st>>7; st ^= st<<17; x = fp::fe_from_u64(st); }
}
static void to8(const std::vector<fp::fe>& z, unsigned off, std::uint64_t m[8][4]) {
    for (unsigned i = 0; i < 8; ++i)
        for (int k = 0; k < 4; ++k) m[i][k] = z[off + i].l[k];
}
int main() {
    const std::uint64_t* ORD = golden::VESTA_PED_ORDER;
    const std::uint64_t R_PUB[4] = {0xC0FFEEull, 1, 2, 3};  // published blinding
    bool all = true;

    {   // [P3-forge] + [P3-fix]: the naive 16-element pattern vs commit_vec
        std::vector<fp::fe> z, z2;
        for (unsigned k = 0; k < 16; ++k) z.push_back(fp::fe_from_u64(k * 11ull + 3));
        z2 = z;
        z2[0] = fp::fe_add(z[0], fp::fe_one());   // +1 at position 0
        z2[8] = fp::fe_sub(z[8], fp::fe_one());   // -1 at position 8 (same base h0)
        std::uint64_t a1[8][4], a2[8][4], b1[8][4], b2[8][4];
        to8(z, 0, a1);  to8(z, 8, a2);
        to8(z2, 0, b1); to8(z2, 8, b2);
        g2v::PtV Ch  = g2v::Vadd(pedv::commit(a1, R_PUB, ORD), pedv::commit(a2, R_PUB, ORD));
        g2v::PtV Ch2 = g2v::Vadd(pedv::commit(b1, R_PUB, ORD), pedv::commit(b2, R_PUB, ORD));
        const bool forge = pouw::ped_eq(Ch, Ch2);
        std::printf("[P3-forge] summed batch commits (naive 16-elem), z != z': "
                    "EQUAL -> %s (kernel shift %s)\n",
                    forge ? "YES" : "no", forge ? "DEMONSTRATED" : "NOT SHOWN");
        const bool bind = !pouw::ped_eq(pedv::commit_vec(z, R_PUB, ORD),
                                        pedv::commit_vec(z2, R_PUB, ORD));
        std::printf("[P3-fix]   commit_vec (per-position bases): commits DIFFER -> %s (BINDING)\n",
                    bind ? "YES" : "NO");
        all = all && forge && bind;
    }
    {   // n=4 flow: register, submit, verify - the verifier NEVER multiplied
        constexpr unsigned n = 4;
        std::vector<fp::fe> A(n*n), B(n*n), C(n*n);
        fill(A, 5); fill(B, 9);
        for (unsigned i = 0; i < n; ++i)
            for (unsigned j = 0; j < n; ++j) {
                fp::fe acc = fp::fe_zero();
                for (unsigned k = 0; k < n; ++k)
                    acc = fp::fe_add(acc, fp::fe_mul(A[i*n+k], B[k*n+j]));
                C[i*n+j] = acc;
            }
        const g2v::PtV regA = pedv::commit_vec(A, R_PUB, ORD);
        const g2v::PtV regB = pedv::commit_vec(B, R_PUB, ORD);
        auto P = pouw::prove_gemm_v2(A, B, C, n, n, n);
        const bool ok = pouw::verify_gemm_v3(P, A, B, C, regA, regB, R_PUB, ORD);
        std::printf("[P3-ok]    honest external submission n=4 (verifier never multiplied): %s\n",
                    ok ? "ACCEPT" : "REJECT!!");
        all = all && ok;
        {   // [P3-fakeA] shifted model, SELF-CONSISTENT proof
            std::vector<fp::fe> A2 = A, C2(n*n);
            A2[0] = fp::fe_add(A[0], fp::fe_one());
            A2[8] = fp::fe_sub(A[8], fp::fe_one());
            for (unsigned i = 0; i < n; ++i)
                for (unsigned j = 0; j < n; ++j) {
                    fp::fe acc = fp::fe_zero();
                    for (unsigned k = 0; k < n; ++k)
                        acc = fp::fe_add(acc, fp::fe_mul(A2[i*n+k], B[k*n+j]));
                    C2[i*n+j] = acc;
                }
            auto P2 = pouw::prove_gemm_v2(A2, B, C2, n, n, n);
            const bool rej = !pouw::verify_gemm_v3(P2, A2, B, C2, regA, regB, R_PUB, ORD);
            const bool caught = !pouw::ped_eq(pedv::commit_vec(A2, R_PUB, ORD), regA);
            std::printf("[P3-fakeA] shifted-model submission (proof self-consistent): %s "
                        "| caught by Pedersen: %s\n",
                        rej ? "REJECT" : "ACCEPT!!", caught ? "YES" : "no");
            all = all && rej && caught;
        }
        {   // [P3-fakeC]
            std::vector<fp::fe> C3 = C;
            C3[0] = fp::fe_add(C[0], fp::fe_one());
            auto P3 = pouw::prove_gemm_v2(A, B, C3, n, n, n);
            const bool rej = !pouw::verify_gemm_v3(P3, A, B, C3, regA, regB, R_PUB, ORD);
            std::printf("[P3-fakeC] tampered output: %s (must REJECT)\n", rej ? "REJECT" : "ACCEPT!!");
            all = all && rej;
        }
    }
    {   // [P3-time] n=64 - honest numbers, no pre-committed winner
        constexpr unsigned n = 64;
        std::vector<fp::fe> A(n*n), B(n*n), C(n*n);
        fill(A, 7); fill(B, 11);
        using clk = std::chrono::steady_clock;
        auto t0 = clk::now();
        for (unsigned i = 0; i < n; ++i)
            for (unsigned j = 0; j < n; ++j) {
                fp::fe acc = fp::fe_zero();
                for (unsigned k = 0; k < n; ++k)
                    acc = fp::fe_add(acc, fp::fe_mul(A[i*n+k], B[k*n+j]));
                C[i*n+j] = acc;
            }
        auto P = pouw::prove_gemm_v2(A, B, C, n, n, n);
        auto t1 = clk::now();
        const bool ok = pouw::verify_gemm_v3(P, A, B, C,
            pedv::commit_vec(A, R_PUB, ORD), pedv::commit_vec(B, R_PUB, ORD),
            R_PUB, ORD);
        auto t2 = clk::now();
        const double tp = std::chrono::duration<double,std::milli>(t1-t0).count();
        const double tv = std::chrono::duration<double,std::milli>(t2-t1).count();
        std::printf("[P3-time]  n=64: prover %.0f ms (incl. the 64^3 multiply, %u MACs) | "
                    "verifier %.0f ms (NO multiply: O(n^2) fold + O(n) Pedersen) | %s\n",
                    tp, n*n*n, tv, ok ? "ACCEPT" : "REJECT!!");
        all = all && ok;
    }
    std::printf("\n[P1-19] %s\n", all ? "GREEN - the external-submission mode is PROVEN" : "RED");
    return all ? 0 : 1;
}
