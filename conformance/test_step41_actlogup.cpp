// HSMA :: test_step41 - Phase 6.6 v1: activations as CCS rows, digest-bound
// to the LogUp batch. THE GATE LAW: an adversarial table hit fails the chain.
#include <hsma/fexec_act.hpp>
#include <hsma/pouw/logup.hpp>
#include <hsma/pouw/logup_ref.hpp>   // oracle: table construction (CA-R231 exempt)
#include <cstdio>
#include <vector>
using namespace hsma;

int main() {
    int fails = 0;
    auto C = [&](bool ok, const char* w) { if (!ok) { std::printf("FAIL: %s\n", w); ++fails; } };

    // ---- the certified tables (P5-F) ----
    const auto T = pouw::logup::build_all();
    C(T.certified, "tables certified (1 LSB, exhaustive)");

    // ---- the honest forward pass: 4 sigmoid activations ----
    const double xs[actcirc::SLOTS] = {0.0, 1.5, -2.25, 3.75};
    std::vector<actcirc::Pair> ps;
    std::vector<int> svals;
    pouw::logup::LogUpBatch batch(12345);
    for (unsigned i = 0; i < actcirc::SLOTS; ++i) {
        const unsigned idx = pouw::logup::x_to_idx(xs[i]);
        const int v = pouw::logup::lookup_by_index(T.sigmoid, idx);
        const unsigned uv = (unsigned)(v < 0 ? -v : v);
        ps.push_back({idx, uv});
        svals.push_back(v);
        batch.add_lookup(idx, v);
    }
    C(ps.size() == actcirc::SLOTS, "four activation slots built");

    // ---- HONEST: LogUp balances; circuit satisfies; digests agree ----
    const auto tsum = pouw::logup::table_side_sum(batch,
        [&](unsigned j) { return pouw::logup::lookup_by_index(T.sigmoid, j); });
    C(pouw::logup::balanced(batch, tsum), "LogUp balanced (honest multiset)");

    mfold::SparseMat A, B, Cm;
    actcirc::build_act_matrices(A, B, Cm);
    const auto z = actcirc::honest_z(ps);
    C(actcirc::satisfied(A, B, Cm, z), "activation circuit satisfied (honest witness)");
    C(actcirc::circuit_digest(z) == actcirc::pairs_digest(ps),
      "circuit digest == batch-side digest (the binding)");

    // ---- ADV1a: lazy tamper (one uv wire, chain stale) ----
    {
        auto z2 = z;
        z2[actcirc::W_UV(1)] = fp::fe_add(z2[actcirc::W_UV(1)], fp::fe_from_u64(1));
        C(!actcirc::satisfied(A, B, Cm, z2), "ADV1a: tampered witness REJECTED by satisfaction");
    }

    // ---- ADV1b: THE STRONG ADVERSARY — tamper + recompute the chain honestly.
    // The circuit SATISFIES; only the digest binding catches it. ----
    {
        auto z2 = actcirc::honest_z(ps);
        z2[actcirc::W_UV(1)] = fp::fe_add(z2[actcirc::W_UV(1)], fp::fe_from_u64(1));
        fp::fe acc = fp::fe_zero();
        for (unsigned i = 0; i < actcirc::SLOTS; ++i) {
            fp::fe p1, p2; actcirc::slot_coeffs(i, p1, p2);
            acc = fp::fe_add(acc, fp::fe_mul(p1, z2[actcirc::W_IDX(i)]));
            acc = fp::fe_add(acc, fp::fe_mul(p2, z2[actcirc::W_UV(i)]));
            z2[actcirc::W_ACC(i)] = acc;
        }
        C(actcirc::satisfied(A, B, Cm, z2), "ADV1b: strong adversary SATISFIES (as designed)");
        C(!(actcirc::circuit_digest(z2) == actcirc::pairs_digest(ps)),
          "ADV1b: ...but the digest MISMATCHES the batch — REJECTED");
    }

    // ---- ADV2: fake table value in the BATCH (both sides consistent with it) ----
    {
        pouw::logup::LogUpBatch b2(12345);
        for (unsigned i = 0; i < actcirc::SLOTS; ++i)
            b2.add_lookup(ps[i].idx, (i == 2) ? svals[2] + 1 : svals[i]);
        const auto t2 = pouw::logup::table_side_sum(b2,
            [&](unsigned j) { return pouw::logup::lookup_by_index(T.sigmoid, j); });
        C(!pouw::logup::balanced(b2, t2), "ADV2: fake table value REJECTED by balanced()");
    }

    // ---- ADV3: a different pair-set cannot collide with the digest ----
    {
        auto ps3 = ps;
        ps3[0].idx = (ps3[0].idx + 1) % 256;
        C(!(actcirc::pairs_digest(ps) == actcirc::pairs_digest(ps3)),
          "ADV3: pair-set change changes the digest (positional binding)");
    }

    std::printf("%s\n", fails ? "test_step41: FAILED"
        : "test_step41: ALL PASS (activations as CCS rows, digest-bound to LogUp; honest accepted, 4 adversarial cases rejected)");
    return fails ? 1 : 0;
}
