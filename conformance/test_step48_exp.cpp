// HSMA :: test_step48 - Phase 6.14: the exp_shifted table (the softmax primitive).
// Exhaustive 0-LSB certification + monotonicity + spot values + a mini-softmax
// through the LogUp batch + adversarial fake-value rejection.
#include <hsma/pouw/logup.hpp>
#include <hsma/pouw/logup_ref.hpp>
#include <cstdio>
#include <cmath>
using namespace hsma;

int main(){
    int fails = 0; auto C = [&](bool ok, const char* w){ if(!ok){ std::printf("FAIL: %s\n", w); ++fails; } };
    const auto T = pouw::logup::build_all();
    C(T.certified, "all four tables certified (0 LSB, exhaustive)");

    // spot values against the oracle
    const auto& E = T.exp_shifted;
    // exp_shifted(4.0) = exp(0) = 1.0 -> OUT_ONE
    // the last SAMPLED index is 255 -> x=3.96875 (x_to_idx clamps at the boundary);
    // its value is exp(-0.03125) ~ 0.9692 in q7. The exact 1.0 point is the domain
    // edge, not a sampled slot. Test the contract, not the wish (CA-R305).
    C(std::abs(E[pouw::logup::x_to_idx(4.0)] / double(pouw::logup::OUT_ONE) - std::exp(-0.03125)) < 0.01,
      "exp_shifted at the clamped boundary index matches the oracle (0.9692)");
    // exp_shifted(-4.0) = exp(-8) ~ 0.000335 -> below q7 resolution, clamps toward 0
    C(E[pouw::logup::x_to_idx(-4.0)] <= 1, "exp_shifted(-4.0) at/below q7 resolution");
    // monotonicity — exp is non-decreasing
    for (unsigned i = 1; i < pouw::logup::N_ENTRIES; ++i)
        C(E[i] >= E[i-1], "exp_shifted monotone");

    // mini-softmax through the LogUp machinery: logits {2.0, 1.0, 0.5}
    // shifted-exp values: exp(2-4)=e^-2, exp(1-4)=e^-3, exp(.5-4)=e^-3.5
    const double logits[3] = {2.0, 1.0, 0.5};
    std::vector<int> evals;
    pouw::logup::LogUpBatch batch(4242);
    for (double x : logits) {
        const unsigned idx = pouw::logup::x_to_idx(x);
        const int v = pouw::logup::lookup_by_index(E, idx);
        evals.push_back(v);
        batch.add_lookup(idx, v);
    }
    const double ref0 = std::exp(2.0 - 4.0), ref1 = std::exp(1.0 - 4.0), ref2 = std::exp(0.5 - 4.0);
    C(std::abs(evals[0] / double(pouw::logup::OUT_ONE) - ref0) < 0.01, "q7 exp(2-4) within 0.01 of oracle");
    C(std::abs(evals[1] / double(pouw::logup::OUT_ONE) - ref1) < 0.01, "q7 exp(1-4) within 0.01");
    C(std::abs(evals[2] / double(pouw::logup::OUT_ONE) - ref2) < 0.01, "q7 exp(.5-4) within 0.01");
    // the softmax denominator = the sum (6.15's division consumes this)
    const double denom = (evals[0] + evals[1] + evals[2]) / double(pouw::logup::OUT_ONE);
    C(denom > 0.0 && denom < 4.0, "softmax denominator sane");
    // LogUp balance over the three lookups
    const auto tsum = pouw::logup::table_side_sum(batch,
        [&](unsigned j){ return pouw::logup::lookup_by_index(E, j); });
    C(pouw::logup::balanced(batch, tsum), "exp lookups balanced through LogUp");
    // adversarial: a fake value breaks balance
    {   pouw::logup::LogUpBatch b2(4242);
        b2.add_lookup(pouw::logup::x_to_idx(2.0), evals[0] + 1);
        const auto t2 = pouw::logup::table_side_sum(b2,
            [&](unsigned j){ return pouw::logup::lookup_by_index(E, j); });
        C(!pouw::logup::balanced(b2, t2), "fake exp value REJECTED by balanced()");
    }

    std::printf("%s\n", fails ? "test_step48: FAILED"
        : "test_step48: ALL PASS — exp_shifted certified 0 LSB, monotone, softmax-smoke through LogUp, adversarial rejected");
    return fails ? 1 : 0;
}
