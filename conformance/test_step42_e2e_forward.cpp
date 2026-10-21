// HSMA :: test_step42 - Phase 6.6 s3: the end-to-end forward pass.
//   GEMM (6.5 CPU path, proven) -> integer quantize (registered boundary)
//   -> actcirc rows + LogUp batch (6.6 v1) -> THE REAL mfold FOLD
//   -> folded SAT. Plus: dishonesty propagates through folds (rejected).
#include <hsma/fexec_act.hpp>
#include <hsma/pouw/logup.hpp>
#include <hsma/pouw/logup_ref.hpp>   // oracle: table construction (CA-R231)
#include <hsma/pouw.hpp>
#include <hsma/pouw/gemm_backend.hpp>   // pouw::gemm (CA-R265)
#include <cstdio>
#include <vector>
using namespace hsma;

int main() {
    int fails = 0;
    auto C = [&](bool ok, const char* w) { if (!ok) { std::printf("FAIL: %s\n", w); ++fails; } };

    const auto T = pouw::logup::build_all();
    C(T.certified, "tables certified");

    // ── stage 1: GEMM n=4 through the backend (CPU), proven ──
    const unsigned n = 4;
    std::uint64_t st = 0x9E3779B97F4A7C15ull;
    auto rnd = [&st]() -> fp::fe {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        return fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
    };
    std::vector<fp::fe> A((std::size_t)n*n), B((std::size_t)n*n), Cg((std::size_t)n*n);
    for (auto& x : A) x = rnd();
    for (auto& x : B) x = rnd();
    const bool gpu = pouw::gemm(A.data(), B.data(), Cg.data(), n);
    const auto PP = pouw::prove_gemm_v2(A, B, Cg, n, n, n);
    C(pouw::verify_gemm_v2(PP, A, B, Cg), "stage1: GEMM proof verified");
    std::printf("[e2e] stage1 GEMM n=4 verified (backend: %s)\n", gpu ? "GPU" : "CPU");

    // ── stage 2: integer quantize (registered boundary, deterministic) ──
    std::vector<actcirc::Pair> ps;
    pouw::logup::LogUpBatch batch(12345);
    for (unsigned i = 0; i < actcirc::SLOTS; ++i) {
        const fp::fe cc = fp::fe_to_canonical(Cg[i]);
        const unsigned idx = (unsigned)(cc.l[0] % 256u);
        const int v = pouw::logup::lookup_by_index(T.sigmoid, idx);
        const unsigned uv = (unsigned)(v < 0 ? -v : v);
        ps.push_back({idx, uv});
        batch.add_lookup(idx, v);
    }
    C(ps.size() == actcirc::SLOTS, "stage2: four pairs quantized");

    // ── stage 3: LogUp balance ──
    const auto tsum = pouw::logup::table_side_sum(batch,
        [&](unsigned j) { return pouw::logup::lookup_by_index(T.sigmoid, j); });
    C(pouw::logup::balanced(batch, tsum), "stage3: LogUp balanced");

    // ── stage 4: the activation circuit + the binding ──
    mfold::SparseMat mA, mB, mC;
    actcirc::build_act_matrices(mA, mB, mC);
    const auto z = actcirc::honest_z(ps);
    C(actcirc::satisfied(mA, mB, mC, z), "stage4: activation circuit satisfied");
    C(actcirc::circuit_digest(z) == actcirc::pairs_digest(ps), "stage4: digest binding holds");
    C(mfold::sat_relaxed(mA, mB, mC, mfold::fresh(z, actcirc::NROWS_ACT)) == actcirc::NROWS_ACT,
      "stage4: mfold sat_relaxed confirms all rows");

    // ── stage 5: THE REAL FOLD — two honest activation instances ──
    std::vector<actcirc::Pair> ps2;
    pouw::logup::LogUpBatch b2(777);
    for (unsigned i = 0; i < actcirc::SLOTS; ++i) {
        const unsigned idx = (ps[i].idx + 97u) % 256u;
        const int v = pouw::logup::lookup_by_index(T.sigmoid, idx);
        ps2.push_back({idx, (unsigned)(v < 0 ? -v : v)});
        b2.add_lookup(idx, v);
    }
    const auto t2 = pouw::logup::table_side_sum(b2,
        [&](unsigned j) { return pouw::logup::lookup_by_index(T.sigmoid, j); });
    C(pouw::logup::balanced(b2, t2), "stage5: second instance's batch balanced");
    const auto z2 = actcirc::honest_z(ps2);
    C(actcirc::circuit_digest(z2) == actcirc::pairs_digest(ps2), "stage5: second binding holds");

    const auto U = mfold::fresh(z, actcirc::NROWS_ACT);
    const auto J = mfold::fresh(z2, actcirc::NROWS_ACT);
    const auto M = mfold::multifold(mA, mB, mC, U, {J});
    C(M.folded.z.size() == actcirc::NZ_ACT, "stage5: folded wire count");
    C(mfold::sat_relaxed(mA, mB, mC, M.folded) == actcirc::NROWS_ACT,
      "stage5: FOLDED instance satisfies all rows — the chain folds");

    // ── stage 6: dishonesty propagates — a tampered instance poisons the fold ──
    {
        auto zb = z2;
        zb[actcirc::W_UV(1)] = fp::fe_add(zb[actcirc::W_UV(1)], fp::fe_from_u64(1));
        const auto JB = mfold::fresh(zb, actcirc::NROWS_ACT);
        const auto MB = mfold::multifold(mA, mB, mC, U, {JB});
        C(mfold::sat_relaxed(mA, mB, mC, MB.folded) != actcirc::NROWS_ACT,
          "stage6: tampered instance -> folded accumulator REJECTED (dishonesty propagates)");
    }

    std::printf("%s\n", fails ? "test_step42: FAILED"
        : "test_step42: ALL PASS — forward pass: GEMM proof -> quantize -> activation rows -> LogUp balanced -> REAL fold -> folded SAT; tamper propagates and is rejected");
    return fails ? 1 : 0;
}
