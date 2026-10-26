// HSMA :: p4scale - P4 headroom receipt: the production circuit at k=1024
// ("thousands of entries" band). CA-R166: measured, never estimated.
// Run once; the receipt lands in DECISIONS.md. NOT in ctest (the flagship
// k=476 epoch is the conformance carrier; this probe doubles it).
#include <hsma/fexec_circuit.hpp>
#include <hsma/mfold.hpp>
#include <hsma/poseidon_r1cs.hpp>
#include <hsma/smt_r1cs.hpp>
#include "pallas_params_gen.hpp"
#include "poseidon_params_gen.hpp"
#include <cstdio>
#include <chrono>
#include <vector>
using namespace hsma;

static constexpr unsigned K = 1024u;
static constexpr unsigned SMT_DEPTH = 64u;

int main() {
    const std::vector<std::array<std::array<std::uint64_t,4>,3>> mds(
        p3_gen::MDS_CANON.begin(), p3_gen::MDS_CANON.end());
    const std::vector<std::array<std::uint64_t,4>> rc80(
        p3_gen::RC_CANON.begin(), p3_gen::RC_CANON.end());
    std::vector<std::array<std::uint64_t,4>> rc_smt;
    for (unsigned l = 0; l < SMT_DEPTH; ++l)
        rc_smt.insert(rc_smt.end(), rc80.begin(), rc80.end());
    mfold::SparseMat Af, Bf, Cf;
    fcirc::build_matrices(Af, Bf, Cf);
    const unsigned OFF = 4;

    auto build_entry = [&](mfold::SparseMat& A2, mfold::SparseMat& B2,
                           mfold::SparseMat& C2, std::vector<fp::fe>& w2,
                           const fp::fe& dp, const fp::fe& dn, const fp::fe& pt) {
        A2 = mfold::SparseMat{}; B2 = mfold::SparseMat{}; C2 = mfold::SparseMat{};
        auto off_merge = [&](mfold::SparseMat& D, const mfold::SparseMat& S) {
            for (std::size_t t = 0; t < S.val.size(); ++t) {
                D.row.push_back(S.row[t]); D.col.push_back(S.col[t] + OFF);
                D.val.push_back(S.val[t]); } };
        off_merge(A2, Af); off_merge(B2, Bf); off_merge(C2, Cf);
        w2.assign(OFF + fcirc::NZ, fp::fe_zero());
        w2[0] = fp::fe_one(); w2[OFF + fcirc::Z_ONE] = fp::fe_one();
        w2[OFF + fcirc::Z_DPREV] = dp; w2[OFF + fcirc::Z_DNEW] = dn;
        w2[OFF + fcirc::Z_PTHASH] = pt; w2[OFF + fcirc::Z_COMPUTED] = pt;
        w2[OFF + fcirc::Z_NONCES] = fp::fe_from_u64(7);
        w2[OFF + fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
        w2[OFF + fcirc::Z_LT] = fp::fe_one();
        w2[OFF + fcirc::Z_PC] = fp::fe_from_u64(1);
        w2[OFF + fcirc::Z_SELEXEC] = fp::fe_one();
        w2[OFF + fcirc::Z_NOTPAD] = fp::fe_one();
        w2[OFF + fcirc::Z_H] = fp::fe_one();
        const unsigned s0 = (unsigned)w2.size();
        w2.push_back(pt); w2.push_back(fp::fe_zero());
        w2.push_back(fp::iv_of(dom::Dom::HSM_PT_v1));
        pr1cs::build(A2, B2, C2, w2, s0, s0 + 1, s0 + 2, rc80, mds,
                     p3_gen::RF / 2, p3_gen::RP);
        for (unsigned acc = 0; acc < 2; ++acc) {
            const unsigned leaf = (unsigned)w2.size();
            w2.push_back(fp::poseidon3(dom::Dom::IV_STATE_NODE, pt,
                                       fp::fe_from_u64(acc + 1)));
            std::vector<unsigned> sibs, dirs;
            fp::fe sib = fp::poseidon3(dom::Dom::IV_STATE_NODE, pt,
                                       fp::fe_from_u64(acc + 77));
            for (unsigned l = 0; l < SMT_DEPTH; ++l) {
                sibs.push_back((unsigned)w2.size()); w2.push_back(sib);
                dirs.push_back((unsigned)w2.size());
                w2.push_back((l % 2) ? fp::fe_one() : fp::fe_zero());
                sib = fp::poseidon3(dom::Dom::IV_STATE_NODE, sib,
                                    fp::fe_from_u64(l + 1));
            }
            const unsigned ivv = (unsigned)w2.size();
            w2.push_back(fp::iv_of(dom::Dom::IV_STATE_NODE));
            const unsigned root = (unsigned)w2.size(); w2.push_back(fp::fe_zero());
            smtr1::build_smt_opening2(A2, B2, C2, w2, leaf, sibs, dirs, ivv,
                                      root, rc_smt, mds, p3_gen::RF / 2, p3_gen::RP);
            fp::fe cur = w2[leaf];
            for (unsigned l = 0; l < SMT_DEPTH; ++l) {
                const fp::fe d = w2[dirs[l]];
                const fp::fe t = fp::fe_mul(d, w2[sibs[l]]);
                const fp::fe u = fp::fe_mul(d, cur);
                cur = fp::poseidon3(dom::Dom::IV_STATE_NODE,
                                    fp::fe_add(fp::fe_sub(t, u), cur),
                                    fp::fe_add(fp::fe_sub(u, t), w2[sibs[l]]));
            }
            w2[root] = cur;
        }
        A2.n_rows = B2.n_rows = C2.n_rows = (unsigned)A2.row.size();
        A2.n_cols = B2.n_cols = C2.n_cols = (unsigned)w2.size();
    };

    std::printf("==== P4 HEADROOM: the production circuit at k=%u ====\n", K);
    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    const fp::fe d0 = fp::fe_from_u64(1000);
    const fp::fe pt0 = fp::poseidon3(dom::Dom::HSM_PT_v1,
                                     fp::fe_from_u64(11), fp::fe_from_u64(22));
    fp::fe dn0 = poseidon3(dom::Dom::HSM_FOLD_v1, d0, pt0);
    build_entry(A, B, C, w, d0, dn0, pt0);
    const unsigned ROWS = (unsigned)A.row.size();
    auto U = mfold::fresh(w, ROWS);
    fp::fe dp = d0, dn = dn0, pt = pt0;
    const auto t0 = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < K; ++i) {
        pt = fp::poseidon3(dom::Dom::HSM_PT_v1, dn,
                           fp::fe_from_u64((unsigned long long)(pt.l[0] ^ dn.l[0]) | 1ull));
        dp = dn;
        dn = poseidon3(dom::Dom::HSM_FOLD_v1, dp, pt);
        std::vector<fp::fe> wj;
        build_entry(A, B, C, wj, dp, dn, pt);
        auto Ji = mfold::fresh(wj, ROWS);
        auto M = mfold::multifold_v2(A, B, C, U, {Ji});
        U = M.folded;
        if ((i + 1) % 256 == 0)
            std::printf("  fold %u/%u (%.0f ms elapsed)\n", i + 1, K,
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count());
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    const bool sat = mfold::sat_relaxed(A, B, C, U) == ROWS;
    std::printf("  rows=%u  monolith=%llu  fold total=%.0f ms  per-fold=%.1f ms\n",
        ROWS, (unsigned long long)ROWS * K, ms, ms / K);
    std::printf("  accumulator wires=%zu (O(1) at k=1024)\n", U.z.size());
    std::printf("  headroom vs the 600s window: %.2fx\n", 600000.0 / ms);
    std::printf("%s\n", sat ? "P4 HEADROOM: ALL PASS - k=1024 MEASURED, SAT, O(1)"
                            : "P4 HEADROOM: FAILED");
    return sat ? 0 : 1;
}
