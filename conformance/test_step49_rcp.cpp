// HSMA :: test_step49 - Phase 6.15 s1: the reciprocal primitive.
// Exhaustive q14 certification + the softmax-assembly smoke:
// exp_shifted lookups -> denominator sum -> rcp -> normalized output vs oracle.
#include <hsma/pouw/logup.hpp>
#include <hsma/pouw/logup_ref.hpp>
#include <cstdio>
#include <cmath>
using namespace hsma;

int main(){
    int fails = 0; auto C = [&](bool ok, const char* w){ if(!ok){ std::printf("FAIL: %s\n", w); ++fails; } };
    const auto T = pouw::logup::build_all();
    const auto R = pouw::logup::build_rcp_table();

    // (1) exhaustive rcp certification vs the oracle (q14, tolerance 1 LSB)
    for (unsigned y = 1; y <= pouw::logup::RCP_MAX; ++y) {
        const int expect = int(std::round((1 << 14) / double(y)));
        const int aerr = std::abs(R[y] - expect);
        C(aerr <= 1, "rcp certified vs oracle");
        if (aerr > 1) { std::printf("[diag] rcp[%u]=%d expect=%d\n", y, R[y], expect); break; }
    }
    // spot: rcp[1]=16384 (exactly 2^14), rcp[2]=8192, rcp[1024]=16
    C(R[1] == 1 << 14, "rcp[1] exact");
    C(R[2] == 1 << 13, "rcp[2] exact");
    C(R[1024] == 16, "rcp[1024] exact");
    C(pouw::logup::rcp_lookup(R, 0) == 0, "division-by-zero guarded");

    // (2) softmax assembly smoke: 3 logits through exp table -> sum -> rcp -> normalize
    const double logits[3] = {2.0, 1.0, 0.5};
    const auto& E = T.exp_shifted;
    std::vector<int> e; std::vector<unsigned> idxs;
    for (double x : logits) {
        const unsigned idx = pouw::logup::x_to_idx(x);
        idxs.push_back(idx);
        e.push_back(pouw::logup::lookup_by_index(E, idx));
    }
    const int denom_q7 = e[0] + e[1] + e[2];
    C(denom_q7 >= 1 && denom_q7 <= pouw::logup::RCP_MAX, "denominator in rcp domain");
    const int rcp = pouw::logup::rcp_lookup(R, unsigned(denom_q7));
    // normalized_i = (e_i * rcp) >> 14  -> in "per-OUT_ONE" units, should sum ~OUT_ONE
    std::vector<int> soft(3);
    for (int k = 0; k < 3; ++k) soft[k] = (e[k] * rcp) >> 7;   // DEF-332: e*rcp = 128*soft_q7 — shift 7, not 14
    const int soft_sum = soft[0] + soft[1] + soft[2];
    std::printf("[diag] e={%d,%d,%d} denom_q7=%d rcp=%d soft={%d,%d,%d} sum=%d (want %d)\n",
        e[0], e[1], e[2], denom_q7, rcp, soft[0], soft[1], soft[2], soft_sum, pouw::logup::OUT_ONE);
    C(std::abs(soft_sum - pouw::logup::OUT_ONE) <= 3, "softmax outputs sum to ~1.0 (q7, rounding)");
    // against the float oracle
    const double d = std::exp(-2.0) + std::exp(-3.0) + std::exp(-3.5);
    for (int k = 0; k < 3; ++k) {
        const double want = std::exp(logits[k] - 4.0) / d;
        std::printf("[diag] soft[%d]=%d (%.4f) vs oracle %.4f (drift %.4f)\n",
            k, soft[k], soft[k] / double(pouw::logup::OUT_ONE), want,
            std::abs(soft[k] / double(pouw::logup::OUT_ONE) - want));
        C(std::abs(soft[k] / double(pouw::logup::OUT_ONE) - want) < 0.02,
          "softmax[i] within 0.02 of oracle");
    }

    std::printf("%s\n", fails ? "test_step49: FAILED"
        : "test_step49: ALL PASS — rcp certified exhaustively (q14), softmax assembly within 0.02 of oracle, sum-to-1 honored");
    return fails ? 1 : 0;
}
