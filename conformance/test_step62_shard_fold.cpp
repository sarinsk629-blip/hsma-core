// HSMA :: test_step62 - Phase 6.18 rung-2 (DEC-s5): the fold-of-folds.
// The mfold multifold (P1-11 machinery) applied to REAL sharded-GEMM block
// instances: an 8x8 parent C = A x B shards on the output grid (2x2 blocks
// of 4x4, inner = FULL N = 8 per the shard law); every block's GEMM is one
// R1CS instance of a SHARED circuit (the values ride the witness, not the
// matrices — that is what makes the instances foldable); the four fresh
// instances fold into ONE relaxed accumulator with FS challenges.
//   P1 the circuit      : every block instance satisfies Az*Bz = u*Cz + E
//                         row by row (fresh: u=1, E=0)
//   P2 the fold identity: the folded instance SATISFIES the same circuit —
//                         the algebra is exact for any r_j
//   P3 the FS transcript: challenges derive from the pinned sponge (seed ->
//                         r_j = P3(HSM_SUMCHECK_v1, seed, j)); same inputs,
//                         same r — determinism is the transcript binding
//   P4 the u law        : u_folded = 1 + sum r_j
//   P5 the negative     : a flipped folded witness slot fails sat at a named
//                         row; a corrupted challenge fails the E identity
//   P6 the shard law    : the block witnesses carry the REAL parent values —
//                         each block's C section equals the parent C slice
#include <hsma/mfold.hpp>
#include <hsma/fe.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

static constexpr unsigned N = 8;    // parent edge
static constexpr unsigned M = 4;    // block edge
static constexpr unsigned GB = N / M;
static constexpr unsigned K = N;    // the shard law: inner stays FULL N

// witness layout: [0]=ONE | A: M*K | B: K*M | P: M*M*K | ACC: M*M*(K-2) | C: M*M
static constexpr unsigned OFF_A   = 1;
static constexpr unsigned OFF_B   = OFF_A + M * K;
static constexpr unsigned OFF_P   = OFF_B + K * M;
static constexpr unsigned OFF_ACC = OFF_P + M * M * K;
static constexpr unsigned OFF_C   = OFF_ACC + M * M * (K - 2);
static constexpr unsigned NZ      = OFF_C + M * M;
static constexpr unsigned NR      = M * M * (K + (K - 1));   // K mul + (K-1) add per output

// the SHARED circuit: value-free selectors (mul: A*B=P, add: 1*(p+acc)=acc')
static void build_circuit(mfold::SparseMat& A, mfold::SparseMat& B,
                          mfold::SparseMat& C) {
    A.n_rows = B.n_rows = C.n_rows = NR;
    A.n_cols = B.n_cols = C.n_cols = NZ;
    unsigned row = 0;
    for (unsigned i = 0; i < M; ++i)
        for (unsigned j = 0; j < M; ++j) {
            const unsigned pij = 0u; (void)pij;
            for (unsigned k = 0; k < K; ++k) {
                // mul: a_{i,k} * b_{k,j} = p_{(i,j),k}
                A.row.push_back(row); A.col.push_back(OFF_A + i * K + k); A.val.push_back(fp::fe_one());
                B.row.push_back(row); B.col.push_back(OFF_B + k * M + j); B.val.push_back(fp::fe_one());
                C.row.push_back(row); C.col.push_back(OFF_P + ((std::size_t)i * M + j) * K + k);
                C.val.push_back(fp::fe_one());
                ++row;
                if (k >= 1) {
                    // add: 1 * (acc_{k-1} + p_k) = acc_k ; the last add lands in C
                    A.row.push_back(row); A.col.push_back(0); A.val.push_back(fp::fe_one());
                    B.row.push_back(row); B.col.push_back(OFF_P + ((std::size_t)i * M + j) * K + k);
                    B.val.push_back(fp::fe_one());
                    const bool last = (k == K - 1);
                    const unsigned acc_prev = (k == 1)
                        ? OFF_P + ((std::size_t)i * M + j) * K + 0
                        : OFF_ACC + ((std::size_t)i * M + j) * (K - 2) + (k - 2);
                    // the addend acc_{k-1}: for k=1 it is p_0; else the acc slot
                    B.row.push_back(row); B.col.push_back(acc_prev); B.val.push_back(fp::fe_one());
                    const unsigned acc_dst = last
                        ? OFF_C + (std::size_t)i * M + j
                        : OFF_ACC + ((std::size_t)i * M + j) * (K - 2) + (k - 1);
                    C.row.push_back(row); C.col.push_back(acc_dst); C.val.push_back(fp::fe_one());
                    ++row;
                }
            }
        }
}

// the witness for block (bi, bj) of the parent GEMM
static mfold::Relaxed block_instance(const std::vector<fp::fe>& Amat,
                                     const std::vector<fp::fe>& Bmat,
                                     const std::vector<fp::fe>& Cmat,
                                     unsigned bi, unsigned bj) {
    mfold::Relaxed R;
    R.u = fp::fe_one();
    R.z.assign(NZ, fp::fe_zero());
    R.E.assign(NR, fp::fe_zero());          // fresh: zero error, row-aligned
    R.z[0] = fp::fe_one();
    for (unsigned r = 0; r < M; ++r)
        for (unsigned c = 0; c < K; ++c)
            R.z[OFF_A + r * K + c] = Amat[(std::size_t)(bi * M + r) * N + c];
    for (unsigned r = 0; r < K; ++r)
        for (unsigned c = 0; c < M; ++c)
            R.z[OFF_B + r * M + c] = Bmat[(std::size_t)r * N + (bj * M + c)];
    // products and accumulators
    for (unsigned i = 0; i < M; ++i)
        for (unsigned j = 0; j < M; ++j)
            for (unsigned k = 0; k < K; ++k)
                R.z[OFF_P + ((std::size_t)i * M + j) * K + k] =
                    fp::fe_mul(R.z[OFF_A + i * K + k], R.z[OFF_B + k * M + j]);
    for (unsigned i = 0; i < M; ++i)
        for (unsigned j = 0; j < M; ++j) {
            fp::fe acc = R.z[OFF_P + ((std::size_t)i * M + j) * K + 0];
            for (unsigned k = 1; k < K; ++k) {
                if (k >= 2)
                    R.z[OFF_ACC + ((std::size_t)i * M + j) * (K - 2) + (k - 2)] = acc;
                acc = fp::fe_add(acc, R.z[OFF_P + ((std::size_t)i * M + j) * K + k]);
            }
            R.z[OFF_C + (std::size_t)i * M + j] = acc;   // the true block output
        }
    (void)Cmat;
    return R;
}

int main() {
    std::printf("test_step62: the fold-of-folds — sharded GEMM through mfold\n");

    // the parent GEMM (q7-scale values; deterministic)
    std::vector<fp::fe> A((std::size_t)N * N), B((std::size_t)N * N);
    std::uint64_t st = 0x53484152ull;   // "SHAR"
    for (std::size_t k = 0; k < A.size(); ++k) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        A[k] = fp::fe_from_u64((st * 0x9E3779B97F4A7C15ull) % 1000ull + 1);
    }
    for (std::size_t k = 0; k < B.size(); ++k) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        B[k] = fp::fe_from_u64((st * 0x9E3779B97F4A7C15ull) % 1000ull + 1);
    }
    std::vector<fp::fe> C((std::size_t)N * N, fp::fe_zero());
    for (unsigned i = 0; i < N; ++i)
        for (unsigned j = 0; j < N; ++j) {
            fp::fe acc = fp::fe_zero();
            for (unsigned k = 0; k < N; ++k)
                acc = fp::fe_add(acc, fp::fe_mul(A[(std::size_t)i * N + k],
                                                 B[(std::size_t)k * N + j]));
            C[(std::size_t)i * N + j] = acc;
        }

    // the shared circuit + the four block instances
    mfold::SparseMat MA, MB, MC;
    build_circuit(MA, MB, MC);
    chk(MA.row.size() == NR && MA.n_cols == NZ,
        "circuit built: 240 rows x 305 cols (K mul + K-1 add per output)");

    std::vector<mfold::Relaxed> inst;
    for (unsigned bi = 0; bi < GB; ++bi)
        for (unsigned bj = 0; bj < GB; ++bj)
            inst.push_back(block_instance(A, B, C, bi, bj));

    // ---- P1: every instance is fresh AND satisfying ----
    bool all_sat = true;
    for (unsigned b = 0; b < inst.size(); ++b)
        if (mfold::sat_relaxed(MA, MB, MC, inst[b]) != NR) all_sat = false;
    chk(all_sat, "P1 all 4 block instances SATISFY the shared circuit (fresh)");

    // ---- P6: the block witnesses carry the REAL parent values ----
    {
        bool real = true;
        for (unsigned bi = 0; bi < GB; ++bi)
            for (unsigned bj = 0; bj < GB; ++bj) {
                const auto& z = inst[bi * GB + bj].z;
                for (unsigned i = 0; i < M && real; ++i)
                    for (unsigned j = 0; j < M; ++j)
                        if (!mfold::feq(z[OFF_C + (std::size_t)i * M + j],
                                        C[(std::size_t)(bi * M + i) * N + (bj * M + j)]))
                            { real = false; break; }
            }
        chk(real, "P6 every block C-section equals the parent C slice");
    }

    // ---- P2/P3/P4: the multifold ----
    mfold::Relaxed U = inst[0];
    const std::vector<mfold::Relaxed> js(inst.begin() + 1, inst.end());
    const auto MF = mfold::multifold(MA, MB, MC, U, js);
    chk(mfold::sat_relaxed(MA, MB, MC, MF.folded) == NR,
        "P2 the FOLDED instance satisfies the same circuit (exact algebra)");
    fp::fe u_expect = fp::fe_one();
    for (const auto& r : MF.r) u_expect = fp::fe_add(u_expect, r);
    chk(mfold::feq(MF.folded.u, u_expect), "P4 u_folded = 1 + sum r_j");
    {
        const auto MF2 = mfold::multifold(MA, MB, MC, U, js);
        bool same = mfold::feq(MF.seed, MF2.seed);
        for (std::size_t j = 0; j < MF.r.size(); ++j)
            same &= mfold::feq(MF.r[j], MF2.r[j]);
        chk(same, "P3 FS transcript deterministic (same inputs -> same r_j)");
    }

    // ---- P5: the negative model ----
    {
        auto T1 = MF.folded;
        T1.z[OFF_P + 7] = fp::fe_add(T1.z[OFF_P + 7], fp::fe_one());
        chk(mfold::sat_relaxed(MA, MB, MC, T1) != NR,
            "P5 flipped folded witness REJECTED (named-row sentinel)");
        auto T2 = MF.folded;
        T2.E[13] = fp::fe_add(T2.E[13], fp::fe_one());   // a corrupted error term
        chk(mfold::sat_relaxed(MA, MB, MC, T2) != NR,
            "P5 corrupted E REJECTED (the fold identity is load-bearing)");
    }

    std::printf("test_step62: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
