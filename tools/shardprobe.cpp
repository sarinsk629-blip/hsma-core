// HSMA :: shardprobe.cpp - Phase 6.18 rung-1 receipt (DEC-s4): 1,024³ block-sharded.
//
// The 6.18 headline is 10,000³ (100×100 blocks of 100³, GPU fleet) — months
// of engineering. THIS receipt is the architecture rung the ladder needs
// first: the FULL sharded pipeline — shard -> per-block v2 proofs ->
// HSM_SHARD_v1 chain-fold -> root -> sampled verification — executed
// END-TO-END at 1,024³ on CPU: 16×16 = 256 output blocks of 64×64, each
// proven as a 64×64×1,024 GEMM (the inner dimension stays the full N —
// the shard law). No GPU, no test band, no theater: the probe exits
// nonzero on any root mismatch or any sampled verification failure.
#include <hsma/pouw/block_shard.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace hsma;

int main(int argc, char** argv) {
    const unsigned N = argc > 1 ? (unsigned)std::atoi(argv[1]) : 1024;
    const unsigned m = argc > 2 ? (unsigned)std::atoi(argv[2]) : 64;
    std::printf("[shard-6.18] N=%u block m=%u grid=%ux%u (each block: %ux%ux%u GEMM)\n",
                N, m, N / m, N / m, m, m, N);

    if (!pouw::shard::spec_ok(N, m)) {
        std::printf("[shard-6.18] FAIL: spec law rejected N=%u m=%u\n", N, m);
        return 1;
    }
    // deterministic fill — the house PRNG shape (CA-R90), float-free
    std::vector<fp::fe> A((std::size_t)N * N), B((std::size_t)N * N), C((std::size_t)N * N);
    std::uint64_t st = 0x53484152ull;   // "SHAR"
    for (std::size_t k = 0; k < A.size(); ++k) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        A[k] = fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        B[k] = fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
    }
    auto clk = [](auto t0, auto t1) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    };
    // 1. the honest computation (CPU backend — the reference)
    const auto c0 = std::chrono::steady_clock::now();
    pouw::gemm(A.data(), B.data(), C.data(), N);
    const auto c1 = std::chrono::steady_clock::now();
    std::printf("[shard] compute C: %lld ms\n", clk(c0, c1));

    // 2. shard + prove every output block (the v2 chain, per block)
    const auto p0 = std::chrono::steady_clock::now();
    const auto S = pouw::shard::prove_sharded(A, B, C, N, m);
    const auto p1 = std::chrono::steady_clock::now();
    std::printf("[shard] prove %zu blocks: %lld ms\n", S.proofs.size(), clk(p0, p1));

    // 3. sampled verification: 16 beacon-challenged blocks
    const auto v0 = std::chrono::steady_clock::now();
    const auto out = pouw::shard::verify_sharded(S, A, B, C, 0x5645524946494552ull, 16);
    const auto v1 = std::chrono::steady_clock::now();
    std::printf("[shard] verify (sampled %zu/%zu): %lld ms\n",
                out.sampled, S.proofs.size(), clk(v0, v1));
    std::printf("[shard] structure_ok=%d root_ok=%d sample_ok=%d pass=%d\n",
                (int)out.structure_ok, (int)out.root_ok, (int)out.sample_ok, (int)out.pass);
    if (!out.pass) {
        std::printf("[shard-6.18] FAIL\n");
        return 1;
    }
    std::printf("[shard-6.18] GREEN — 6.18 rung-1 receipt: block-sharded pipeline proven at N=%u\n", N);
    return 0;
}
