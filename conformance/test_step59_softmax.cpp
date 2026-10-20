// HSMA :: test_step59 - Phase 6.14 CLOSE (DEC-s5): the P_h producer.
//   P1 certification    : build_all() certifies the tables (exp 0-LSB, rcp, rsqrt grid)
//   P2 the oracle bound : P vs the double-precision softmax, drift measured
//                         and pinned (the producer is fixed-point q7/q14)
//   P3 the row-max law  : the max element takes the exact identity (128);
//                         monotonicity along the row; the 8-below-max clamp
//   P4 the exact rung   : D <= RCP_MAX enforced — 8 equal scores sit EXACTLY
//                         on the boundary (D=1024, accepted); 9 equal scores
//                         (D=1152) REJECTED
//   P5 the LogUp batch  : the genuine trace balances BOTH sides; one poisoned
//                         exp value and one poisoned rcp value each IMBALANCE
//   P6 determinism      : same scores -> same P (the producer is a function)
#include <hsma/pouw/softmax.hpp>
#include <hsma/pouw/logup_ref.hpp>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <vector>
using namespace hsma;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

int main() {
    std::printf("test_step59: the softmax producer — 6.14 CLOSE\n");
    const unsigned seq = 8;
    const auto T = pouw::logup::build_all();

    // ---- P1: certification ----
    chk(T.certified, "P1 all tables certified (exp 0-LSB | rcp | rsqrt grid)");

    // ---- inputs: q7/q14 NON-NEGATIVE scores (the producer's contract) ----
    std::vector<std::vector<double>> rows = {
        {10.0, 9.0, 8.5, 8.25, 8.0, 7.5, 7.0, 6.0},
        {11.0, 11.0, 10.0, 9.0, 8.0, 8.0, 7.0, 4.0},
        {12.0, 8.0, 8.0, 8.0, 8.0, 8.0, 8.0, 4.0},   // diff 8 at j=7: the clamp
    };
    std::uint64_t st = 0x5330;
    for (unsigned r = 3; r < seq; ++r) {
        rows.push_back({});
        for (unsigned j = 0; j < seq; ++j) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            rows.back().push_back(double((st * 0x9E3779B97F4A7C15ull) % 1024ull) / 128.0);
        }
    }
    std::vector<fp::fe> S((std::size_t)seq * seq);
    for (unsigned r = 0; r < seq; ++r)
        for (unsigned j = 0; j < seq; ++j) {
            const std::uint64_t q14 =
                (std::uint64_t)std::llround(rows[r][j] * 16384.0);
            S[(std::size_t)r * seq + j] = fp::fe_from_u64(q14);
        }

    // ---- P2: producer vs oracle (over the SAME q14-quantized scores) ----
    pouw::softmax::SoftmaxBatch batch(4242);
    const auto R = pouw::softmax::softmax_rows(S, seq, T, &batch);
    chk(R.ok, "P2 softmax_rows ACCEPTS contract-conforming scores");
    double worst = 0.0;
    for (unsigned r = 0; r < seq; ++r) {
        double mx = -1e30, sum = 0.0;
        std::vector<double> e(seq);
        for (unsigned j = 0; j < seq; ++j)
            mx = std::max(mx, std::llround(rows[r][j] * 16384.0) / 16384.0);
        for (unsigned j = 0; j < seq; ++j) {
            e[j] = std::exp(std::llround(rows[r][j] * 16384.0) / 16384.0 - mx);
            sum += e[j];
        }
        for (unsigned j = 0; j < seq; ++j) {
            const double oracle = e[j] / sum;
            const double got = R.P[(std::size_t)r * seq + j] / 128.0;
            worst = std::max(worst, std::abs(got - oracle));
        }
    }
    std::printf("  [info] worst |P - oracle| = %.5f (real units; q7 grid = 0.0078)\n", worst);
    chk(worst <= 0.02, "P2 P within the pinned 0.02 q7 drift bound");

    // ---- P3: the row laws (sum ~ 128, argmax preserved, monotone, clamp) --
    {
        bool sumlaw = true, argmax = true, mono = true;
        for (unsigned r = 0; r < seq; ++r) {
            int psum = 0; unsigned amax = 0, pmax_at = 0;
            for (unsigned j = 0; j < seq; ++j) {
                psum += R.P[(std::size_t)r * seq + j];
                if (rows[r][j] >= rows[r][amax]) amax = j;
                if (R.P[(std::size_t)r * seq + j] > R.P[(std::size_t)r * seq + pmax_at])
                    pmax_at = j;
            }
            // THE ROW-SUM LAW: sum_i P_i ~ 128 = q7 of 1.0 (rcp rounding drift
            // bounded by 0.5 q7-unit per entry)
            if (std::abs(psum - 128) > (int)seq / 2 + 1) sumlaw = false;
            // the P-max slot must carry a maximal score (ties legitimately
            // produce equal weights — row 1 duplicates its max)
            if (rows[r][pmax_at] != rows[r][amax]) argmax = false;
            for (unsigned j = 1; j < seq; ++j)
                if (rows[r][j] >= rows[r][j - 1]
                    && R.P[(std::size_t)r * seq + j] < R.P[(std::size_t)r * seq + j - 1])
                    mono = false;
        }
        chk(sumlaw, "P3 every row sums to ~128 (q7 of 1.0) — the softmax law");
        chk(argmax, "P3 argmax preserved (the max score wins the max weight)");
        chk(mono, "P3 producer monotone along the row order");
        chk(R.P[(std::size_t)2 * seq + 7] == 0, "P3 a score 8 below the max clamps to 0");
    }

    // ---- P4: the exact rung — D <= RCP_MAX, boundary-exact ----
    {
        std::vector<fp::fe> S8((std::size_t)8 * 8, fp::fe_from_u64(16384ull));
        const auto R8 = pouw::softmax::softmax_rows(S8, 8, T, nullptr);
        chk(R8.ok, "P4 eight equal scores: D=1024 == RCP_MAX, boundary ACCEPTED");
        std::vector<fp::fe> S9((std::size_t)9 * 9, fp::fe_from_u64(16384ull));
        const auto R9 = pouw::softmax::softmax_rows(S9, 9, T, nullptr);
        chk(!R9.ok, "P4 nine equal scores: D=1152 > RCP_MAX, REJECTED");
    }

    // ---- P5: the LogUp batch — balance + adversarial poison ----
    {
        const auto tsum_e = pouw::logup::table_side_sum(batch.exp,
            [&](unsigned i){ return pouw::softmax::exp_at(T, i); });
        const auto tsum_r = pouw::logup::table_side_sum(batch.rcp,
            [&](unsigned i){ return pouw::softmax::rcp_at(T, i); });
        chk(pouw::logup::balanced(batch.exp, tsum_e), "P5 exp side BALANCES");
        chk(pouw::logup::balanced(batch.rcp, tsum_r), "P5 rcp side BALANCES");

        // adversarial: replay the exact trace but poison ONE exp value (+1)
        pouw::softmax::SoftmaxBatch fake(batch.exp.alpha);
        bool poisoned = false;
        for (const auto& [idx, m] : batch.exp.multiplicity)
            for (std::uint64_t k = 0; k < m; ++k) {
                const int tv = pouw::softmax::exp_at(T, idx);
                const int v = (!poisoned && idx != 256u) ? tv + 1 : tv;
                if (!poisoned && idx != 256u) poisoned = true;
                fake.add_exp(idx, v);
            }
        const auto fs = pouw::logup::table_side_sum(fake.exp,
            [&](unsigned i){ return pouw::softmax::exp_at(T, i); });
        chk(!pouw::logup::balanced(fake.exp, fs),
            "P5 one poisoned exp value IMBALANCES the exp side");
        // adversarial: poison ONE rcp value
        pouw::softmax::SoftmaxBatch fake2(batch.rcp.alpha);
        bool poisoned2 = false;
        for (const auto& [idx, m] : batch.rcp.multiplicity)
            for (std::uint64_t k = 0; k < m; ++k) {
                const int tv = pouw::softmax::rcp_at(T, idx);
                const int v = !poisoned2 ? tv + 1 : tv;
                poisoned2 = true;
                fake2.add_rcp(idx, v);
            }
        const auto fs2 = pouw::logup::table_side_sum(fake2.rcp,
            [&](unsigned i){ return pouw::softmax::rcp_at(T, i); });
        chk(!pouw::logup::balanced(fake2.rcp, fs2),
            "P5 one poisoned rcp value IMBALANCES the rcp side");
    }

    // ---- P6: determinism ----
    {
        const auto R2 = pouw::softmax::softmax_rows(S, seq, T, nullptr);
        chk(R2.ok && R2.P == R.P, "P6 same scores -> identical P (a function, not a process)");
    }

    std::printf("test_step59: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
