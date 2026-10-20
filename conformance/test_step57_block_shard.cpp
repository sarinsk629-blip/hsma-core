// HSMA :: test_step57 - Phase 6.18 rung-1 (DEC-s4): the block-sharded GEMM.
//   P1 the spec law     : N%m==0 positive shapes accepted; non-divisible,
//                         zero, and inverted shapes REJECTED
//   P2 shard semantics  : block C_ij is the GEMM A_i: (m×N) × B_:j (N×m) —
//                         recomputed independently, byte-identical
//   P3 the root         : rederive_root(S) == S.root (order-binding fold)
//   P4 full verification: every block proof verifies (N=256, 4×4 grid)
//   P5 sampled verify   : beacon-challenged sample verifies (N=512, 8×8
//                         grid, 8 of 64) and the sample is deterministic
//   P6 tamper evidence  : one flipped C byte inside the sampled window ->
//                         that block's v2 chain REJECTS
//   P7 proof-swap       : two blocks' proofs exchanged in place -> root
//                         mismatch (the fold binds the grid ORDER)
#include <hsma/pouw/block_shard.hpp>
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
        M[k] = fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
    }
}

int main() {
    std::printf("test_step57: the block-sharded GEMM — 6.18 rung-1\n");

    // ---- P1: the spec law ----
    chk(pouw::shard::spec_ok(512, 64), "P1 spec_ok(512, 64)");
    chk(pouw::shard::spec_ok(1024, 64), "P1 spec_ok(1024, 64) — the receipt rung");
    chk(!pouw::shard::spec_ok(513, 64), "P1 non-divisible REJECTED");
    chk(!pouw::shard::spec_ok(0, 64), "P1 zero N REJECTED");
    chk(!pouw::shard::spec_ok(64, 128), "P1 block larger than matrix REJECTED");

    // ---- P2: shard semantics — a block IS A_i: × B_:j ----
    {
        const unsigned N = 128, m = 32;
        std::vector<fp::fe> A((std::size_t)N * N), B((std::size_t)N * N), C((std::size_t)N * N);
        fill_det(A, 0xA11CE); fill_det(B, 0xB0B);
        pouw::gemm(A.data(), B.data(), C.data(), N);
        // independent recompute of block (1,2): rows [32,64) x cols [64,96)
        fp::fe acc = fp::fe_zero();
        bool block_ok = true;
        for (unsigned i = 0; i < m && block_ok; ++i) {
            for (unsigned j = 0; j < m; ++j) {
                acc = fp::fe_zero();
                for (unsigned k = 0; k < N; ++k)
                    acc = fp::fe_add(acc, fp::fe_mul(
                        A[(std::size_t)(1 * m + i) * N + k],
                        B[(std::size_t)k * N + (2 * m + j)]));
                if (!sc::feq(acc, C[(std::size_t)(1 * m + i) * N + (2 * m + j)])) {
                    block_ok = false; break;
                }
            }
        }
        chk(block_ok, "P2 block (1,2) == A[32:64,:] x B[:,64:96] (inner dim = FULL N)");
    }

    // ---- P3/P4: root + FULL verification at N=256 (4x4 grid) ----
    {
        const unsigned N = 256, m = 64;
        std::vector<fp::fe> A((std::size_t)N * N), B((std::size_t)N * N), C((std::size_t)N * N);
        fill_det(A, 0x5A11); fill_det(B, 0x5B22);
        pouw::gemm(A.data(), B.data(), C.data(), N);
        const auto S = pouw::shard::prove_sharded(A, B, C, N, m);
        chk(S.blocks.size() == 16 && S.proofs.size() == 16, "P3 4x4 grid -> 16 block proofs");
        chk(sc::feq(pouw::shard::rederive_root(S), S.root), "P3 rederive_root == committed root");
        const auto out = pouw::shard::verify_sharded(S, A, B, C, 0x5645524946494552ull, 16);
        chk(out.structure_ok, "P4 structure ok");
        chk(out.root_ok, "P4 root ok");
        chk(out.sample_ok && out.sampled == 16, "P4 FULL sample (16/16) verifies");
        chk(out.pass, "P4 overall PASS");
    }

    // ---- P5: sampled verification + determinism at N=512 (8x8 grid) ----
    {
        const unsigned N = 512, m = 64;
        std::vector<fp::fe> A((std::size_t)N * N), B((std::size_t)N * N), C((std::size_t)N * N);
        fill_det(A, 0x51AD); fill_det(B, 0x5B0B);
        pouw::gemm(A.data(), B.data(), C.data(), N);
        const auto S = pouw::shard::prove_sharded(A, B, C, N, m);
        chk(S.blocks.size() == 64, "P5 8x8 grid -> 64 block proofs");
        const auto out = pouw::shard::verify_sharded(S, A, B, C, 0xBEEF, 8);
        chk(out.sample_ok && out.sampled == 8, "P5 sampled 8/64 verifies");
        const auto i1 = pouw::shard::sample_blocks(0xBEEF ^ 0x53484152ull, 8, 64);
        const auto i2 = pouw::shard::sample_blocks(0xBEEF ^ 0x53484152ull, 8, 64);
        chk(i1 == i2, "P5 sample is deterministic (same seed -> same indices)");
        const auto i3 = pouw::shard::sample_blocks(0xCAFE, 8, 64);
        chk(i1 != i3, "P5 different seed -> different sample (the challenge moves)");

        // ---- P6: tamper evidence — flip one byte of C inside block (0,0) ----
        std::vector<fp::fe> Cbad = C;
        Cbad[0] = fp::fe_add(Cbad[0], fp::fe_one());
        const auto out_bad = pouw::shard::verify_sharded(S, A, B, Cbad, 0x5645524946494552ull, 64);
        chk(!out_bad.sample_ok && !out_bad.pass, "P6 one flipped C byte -> sampled verification REJECTS");

        // ---- P7: proof swap — the root binds grid order ----
        pouw::shard::ShardProof S2 = S;
        const auto tmp = S2.proofs[0];
        S2.proofs[0] = S2.proofs[1];
        S2.proofs[1] = tmp;
        chk(!sc::feq(pouw::shard::rederive_root(S2), S2.root),
            "P7 swapped block proofs -> root MISMATCH (the fold is order-binding)");
    }

    std::printf("%s\n", "test_step57: DONE — the sharded architecture real (shard law, fold, sampled verify, tamper, order-binding)");
    return fails;
}
