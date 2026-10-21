// HSMA :: pouw/block_shard.hpp - Phase 6.18 rung-1 (DEC-s4): the block-sharded GEMM.
//
// THE SHARD LAW. An N×N GEMM C = A×B shards on the OUTPUT grid: block
// C_ij (m×m at grid position (i,j)) is the GEMM A_i: (m×N) × B_:j (N×m) —
// the inner dimension stays the FULL N, so block proofs compose EXACTLY:
// sum over blocks of the m×m×N proofs is the whole N³ work, with zero
// re-normalization. Each output block is proven by the existing v2
// machinery (prove_gemm_v2); the per-block leaves are chain-folded under
// the HSM_SHARD_v1 domain into ONE root that commits to the entire sharded
// computation (grid order included — the fold is order-binding).
//
// THE VERIFIER'S BUDGET. verify_sharded recomputes the root from the
// delivered proofs, re-derives every leaf, and fully verifies the
// beacon-challenged SAMPLE of block proofs (CA-R90 xorshift64* over the
// caller's seed). O(sample) verifier GEMM work over an O(N³) computation
// is the rung the 6.16 ladder pointed at.
//
// HONEST SCOPE (rung-1). The fold is a Poseidon chain over block leaves —
// NOT the NIFS fold of block proofs into one succinct proof. That
// compression step is 6.18's remaining work (the 3-6 month headline:
// 10,000³ = 100×100 grid of 100³, GPU-computed). Rung-1 makes the sharded
// architecture REAL and PROVEN: 1,024³ = 16×16 blocks of 64³ proven and
// sampled-verified on CPU (tools/shardprobe receipt; CI carries 512³).
// Domain separation: HSM_SHARD_v1 is minted by the registry recipe
// (SHA256("HSM_IV_v1|HSM_SHARD_v1|nonce") -> canonical -> RR-lifted), the
// same law as the other 35 IVs.
#pragma once
#include <hsma/pouw.hpp>
#include <hsma/pouw/gemm_backend.hpp>
#include <hsma/fe.hpp>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace hsma::pouw::shard {

struct BlockRef {
    std::uint32_t bi = 0;   // row block index [0, gb)
    std::uint32_t bj = 0;   // col block index [0, gb)
};

struct ShardProof {
    unsigned N = 0;         // the full matrix edge
    unsigned m = 0;         // the block edge (N % m == 0)
    unsigned gb = 0;        // blocks per side = N / m
    fp::fe root{};          // the chain-fold root over row-major block leaves
    std::vector<BlockRef> blocks;
    std::vector<GemmProofV2> proofs;   // aligned with blocks (same index)
};

// The shard spec law: positive, square-blocking, exact division.
inline bool spec_ok(unsigned N, unsigned m) noexcept {
    return N > 0 && m > 0 && m <= N && (N % m) == 0;
}

// The block leaf: binds grid position AND the three v2 commitments. Five
// values through four 2->1 poseidon3 applications, all under HSM_SHARD_v1 —
// swapping two blocks' proofs, or lifting a proof out of its grid cell,
// breaks the leaf and therefore the root.
inline fp::fe block_leaf(const GemmProofV2& p, std::uint32_t bi, std::uint32_t bj) noexcept {
    const fp::fe bfe = fp::fe_from_u64((std::uint64_t)bi);
    const fp::fe jfe = fp::fe_from_u64((std::uint64_t)bj);
    const fp::fe h1 = poseidon3(dom::Dom::HSM_SHARD_v1, bfe, jfe);
    const fp::fe h2 = poseidon3(dom::Dom::HSM_SHARD_v1, h1, p.comA);
    const fp::fe h3 = poseidon3(dom::Dom::HSM_SHARD_v1, h2, p.comB);
    return poseidon3(dom::Dom::HSM_SHARD_v1, h3, p.comC);
}

// THE FOLD: order-binding chain over row-major leaves.
//   root_0 = leaf_0;  root_{k+1} = P3(HSM_SHARD_v1, root_k, leaf_k)
inline fp::fe fold_roots(const std::vector<fp::fe>& leaves) noexcept {
    fp::fe acc = leaves.empty() ? fp::fe_zero() : leaves[0];
    for (std::size_t k = 1; k < leaves.size(); ++k)
        acc = poseidon3(dom::Dom::HSM_SHARD_v1, acc, leaves[k]);
    return acc;
}

// THE PROVER: shard C = A×B (N×N) on an (N/m)×(N/m) grid; every output
// block is proven by the FULL v2 chain (FS challenges from its own
// commitments — each block faces fresh challenges). A/B/C are N×N
// row-major over the Pallas field.
inline ShardProof prove_sharded(const std::vector<fp::fe>& A,
                                const std::vector<fp::fe>& B,
                                const std::vector<fp::fe>& C,
                                unsigned N, unsigned m) noexcept {
    ShardProof S;
    S.N = N; S.m = m;
    S.gb = N / m;
    std::vector<fp::fe> Ab((std::size_t)m * N), Bb((std::size_t)N * m), Cb((std::size_t)m * m);
    S.blocks.reserve((std::size_t)S.gb * S.gb);
    S.proofs.reserve((std::size_t)S.gb * S.gb);
    for (unsigned bi = 0; bi < S.gb; ++bi) {
        for (unsigned bj = 0; bj < S.gb; ++bj) {
            // A block: rows [bi*m, bi*m+m), FULL width N
            for (unsigned r = 0; r < m; ++r)
                for (unsigned c = 0; c < N; ++c)
                    Ab[(std::size_t)r * N + c] = A[(std::size_t)(bi * m + r) * N + c];
            // B block: FULL height N, cols [bj*m, bj*m+m)
            for (unsigned r = 0; r < N; ++r)
                for (unsigned c = 0; c < m; ++c)
                    Bb[(std::size_t)r * m + c] = B[(std::size_t)r * N + (bj * m + c)];
            // C block: m×m at (bi*m, bj*m)
            for (unsigned r = 0; r < m; ++r)
                for (unsigned c = 0; c < m; ++c)
                    Cb[(std::size_t)r * m + c] = C[(std::size_t)(bi * m + r) * N + (bj * m + c)];
            S.blocks.push_back(BlockRef{bi, bj});
            S.proofs.push_back(prove_gemm_v2(Ab, Bb, Cb, m, m, N));
        }
    }
    std::vector<fp::fe> leaves;
    leaves.reserve(S.proofs.size());
    for (std::size_t k = 0; k < S.proofs.size(); ++k)
        leaves.push_back(block_leaf(S.proofs[k], S.blocks[k].bi, S.blocks[k].bj));
    S.root = fold_roots(leaves);
    return S;
}

// leaf/root re-derivation on the verifier side: the root recomputed from
// the DELIVERED proofs must equal the committed root.
inline fp::fe rederive_root(const ShardProof& S) noexcept {
    std::vector<fp::fe> leaves;
    leaves.reserve(S.proofs.size());
    for (std::size_t k = 0; k < S.proofs.size(); ++k)
        leaves.push_back(block_leaf(S.proofs[k], S.blocks[k].bi, S.blocks[k].bj));
    return fold_roots(leaves);
}

// THE SAMPLE: CA-R90 xorshift64* over the caller's seed (epoch tail at the
// node; the VERIFIER domain tag is folded in by the caller like s2 does).
inline std::vector<std::size_t> sample_blocks(std::uint64_t seed,
                                              std::size_t count,
                                              std::size_t pool) noexcept {
    std::vector<std::size_t> out;
    if (pool == 0) return out;
    if (count > pool) count = pool;
    std::uint64_t st = seed * 0x9E3779B97F4A7C15ull + 0x2545F4914F6CDD1Dull;
    for (std::size_t s = 0; s < count; ++s) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        out.push_back((std::size_t)((st * 0x9E3779B97F4A7C15ull) % (std::uint64_t)pool));
    }
    return out;
}

struct ShardOutcome {
    bool structure_ok = false;   // spec law + counts + alignment
    bool root_ok = false;        // re-derived root == committed root
    bool sample_ok = false;      // every sampled block proof verifies
    bool pass = false;
    std::size_t sampled = 0;
};

// THE VERIFIER: full C delivered (root recompute + leaf re-derivation needs
// the commitments only, but sampled verify_gemm_v2 needs the block views of
// A/B/C). seed = the beacon-challenge material.
inline ShardOutcome verify_sharded(const ShardProof& S,
                                   const std::vector<fp::fe>& A,
                                   const std::vector<fp::fe>& B,
                                   const std::vector<fp::fe>& C,
                                   std::uint64_t seed,
                                   std::size_t sample_count) noexcept {
    ShardOutcome o;
    if (!spec_ok(S.N, S.m) || S.gb != S.N / S.m) return o;
    if (S.blocks.size() != (std::size_t)S.gb * S.gb) return o;
    if (S.proofs.size() != S.blocks.size()) return o;
    if (A.size() != (std::size_t)S.N * S.N || B.size() != (std::size_t)S.N * S.N
        || C.size() != (std::size_t)S.N * S.N) return o;
    for (std::size_t k = 0; k < S.blocks.size(); ++k) {
        const auto& br = S.blocks[k];
        if (br.bi >= S.gb || br.bj >= S.gb) return o;
        const auto& p = S.proofs[k];
        if (p.rows != S.m || p.cols != S.m || p.inner != S.N) return o;
    }
    o.structure_ok = true;
    o.root_ok = sc::feq(rederive_root(S), S.root);
    // sampled full verification: extract the block views, run the v2 chain
    const unsigned m = S.m, N = S.N;
    std::vector<fp::fe> Ab((std::size_t)m * N), Bb((std::size_t)N * m), Cb((std::size_t)m * m);
    const auto idx = sample_blocks(seed ^ 0x53484152ull /* "SHAR" */, sample_count,
                                   S.proofs.size());
    o.sampled = idx.size();
    bool sok = !idx.empty();
    for (std::size_t k : idx) {
        const unsigned bi = S.blocks[k].bi, bj = S.blocks[k].bj;
        for (unsigned r = 0; r < m; ++r)
            for (unsigned c = 0; c < N; ++c)
                Ab[(std::size_t)r * N + c] = A[(std::size_t)(bi * m + r) * N + c];
        for (unsigned r = 0; r < N; ++r)
            for (unsigned c = 0; c < m; ++c)
                Bb[(std::size_t)r * m + c] = B[(std::size_t)r * N + (bj * m + c)];
        for (unsigned r = 0; r < m; ++r)
            for (unsigned c = 0; c < m; ++c)
                Cb[(std::size_t)r * m + c] = C[(std::size_t)(bi * m + r) * N + (bj * m + c)];
        if (!verify_gemm_v2(S.proofs[k], Ab, Bb, Cb)) { sok = false; break; }
    }
    o.sample_ok = sok;
    o.pass = o.structure_ok && o.root_ok && o.sample_ok;
    return o;
}

} // namespace hsma::pouw::shard
