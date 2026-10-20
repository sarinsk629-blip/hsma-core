// HSMA :: rung_probe.cpp - Phase 6.16 receipt (DEC-s4): the verifier-cost gate.
//
// The 6.16 question: what does a tier-2 RECOMPUTE actually cost on CPU, so
// the fleet rung is a MEASURED number, not a folklore number? This probe
// times pouw::gemm (the exact function verifier.hpp's tier-2 calls) at the
// ladder's rungs and prints the verdict table. The TIER2_RUNG constant in
// verifier.hpp cites THIS receipt.
//
// Float-free (DEC-090): timings print as integer ms; MACs are exact counts.
#include <hsma/pouw/gemm_backend.hpp>
#include <hsma/fe.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace hsma;

int main(int argc, char** argv) {
    const bool deep = argc > 1 && argv[1][0] == 'd';   // "deep": include 1024
    std::printf("[rung-6.16] CPU GEMM cost ladder (pouw::gemm, the tier-2 call)\n");
    if (pouw::gpu_available())
        std::printf("[rung-6.16] NOTE: GPU backend present — CPU numbers below are the FLOOR\n");
    const unsigned rungs[] = {64, 96, 128, 256, 512};
    for (unsigned n : rungs) {
        if (n == 512 && !deep) continue;   // 512³ costs real seconds on CPU: opt-in via "deep"
        std::vector<fp::fe> A((std::size_t)n * n), B((std::size_t)n * n), C((std::size_t)n * n);
        // deterministic fill (the house PRNG shape, CA-R90) — no floats anywhere
        std::uint64_t st = 0x52454E47ull + n;   // "RENG"
        for (std::size_t k = 0; k < A.size(); ++k) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            A[k] = fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            B[k] = fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
        }
        const auto t0 = std::chrono::steady_clock::now();
        pouw::gemm(A.data(), B.data(), C.data(), n);
        const auto t1 = std::chrono::steady_clock::now();
        const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        const unsigned long long macs = (unsigned long long)n * n * n;
        const unsigned long long macps = ms > 0 ? macs / (unsigned long long)ms / 1000ull : 0;
        // sink: the result is consumed so the timed call cannot be elided
        unsigned long long sink = 0;
        for (std::size_t k = 0; k < C.size(); k += 997) sink += C[k].l[0];
        volatile unsigned long long vsink = sink; (void)vsink;
        // verdict: affordable once per pool lifecycle if under ~2s on this class
        const char* verdict = (ms <= 2000) ? "IN-RUNG (once-per-pool affordable)"
                                           : "ABOVE the CPU rung (digest-tier honestly)";
        std::printf("[rung] n=%4u  %6lld ms  %llu MACs  ~%llu M MAC/s  -> %s\n",
                    n, ms, macs, macps, verdict);
    }
    std::printf("[rung-6.16] receipt: the rung constant cites this table\n");
    return 0;
}
