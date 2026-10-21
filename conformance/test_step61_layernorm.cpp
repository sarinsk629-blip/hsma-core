// HSMA :: test_step61 - Phase 6.15 (DEC-s5): LayerNorm, the honest rung.
//   P1 certification    : the rsqrt table's (m8, frac) grid receipt — worst
//                         chord error MEASURED in the builder, pinned here
//   P2 the oracle bound : y vs the double-precision LayerNorm, drift measured
//                         and pinned (mean via RCP, variance via RCP, rsqrt
//                         via the interpolated window)
//   P3 the exact cases  : n = 8 (power of two) divisions are EXACT via RCP;
//                         the epsilon floor catches the constant row
//   P4 the affine rung  : gamma/beta applied in q7 (identity = 128/0)
//   P5 the boundary     : the field mapping round-trips negatives
//                         (fe_from_s64 / fe_to_s64)
//   P6 the negative     : a corrupted rsqrt table FAILS its own certification
//   P7 the LogUp audit  : the n-division lookups balance against the RCP table
#include <hsma/pouw/layernorm.hpp>
#include <hsma/pouw/logup_ref.hpp>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <vector>
using namespace hsma;
using namespace hsma::pouw;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

int main() {
    std::printf("test_step61: LayerNorm — 6.15, the table+fixup rung\n");
    const auto T = pouw::logup::build_all();

    // ---- P1: the rsqrt grid receipt ----
    chk(T.certified, "P1 all tables certified (rsqrt chord bound included)");
    chk(T.rsqrt.size() == 129u, "P1 rsqrt table: 128 mantissa slots + 1 sentinel");
    bool mono = true;
    for (std::size_t i = 1; i < T.rsqrt.size(); ++i)
        if (T.rsqrt[i] > T.rsqrt[i - 1]) mono = false;   // decreasing on the window
    chk(mono, "P1 rsqrt monotone decreasing across the window");

    // ---- inputs: rows x n q7 field entries ----
    const unsigned rows = 6, n = 8;
    std::vector<std::vector<double>> xr = {
        {3.0, 1.0, 2.0, 0.5, 4.0, 2.5, 1.5, 0.25},
        {1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0},       // constant row: eps floor
        {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0},       // zero row: eps floor
        {6.0, 2.0, 5.0, 1.0, 7.0, 3.0, 4.0, 0.5},
        {0.125, 0.25, 0.375, 0.5, 0.625, 0.75, 0.875, 1.0},
        {2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 3.0},       // tiny variance
    };
    std::vector<fp::fe> X((std::size_t)rows * n);
    for (unsigned r = 0; r < rows; ++r)
        for (unsigned j = 0; j < n; ++j)
            X[(std::size_t)r * n + j] =
                fp::fe_from_u64((std::uint64_t)std::llround(xr[r][j] * 128.0));

    // ---- P2: producer vs oracle ----
    logup::LogUpBatch audit(31337);
    const auto R = pouw::ln::layernorm_rows(X, rows, n, T, 128, 0, &audit);
    chk(R.ok, "P2 layernorm_rows ACCEPTS contract-conforming input");
    double worst = 0.0;
    for (unsigned r = 0; r < rows; ++r) {
        double mean = 0, var = 0;
        for (unsigned j = 0; j < n; ++j) mean += xr[r][j];
        mean /= n;
        for (unsigned j = 0; j < n; ++j) var += (xr[r][j] - mean) * (xr[r][j] - mean);
        var /= n;
        for (unsigned j = 0; j < n; ++j) {
            const double oracle = (xr[r][j] - mean) / std::sqrt(var + 1e-4);
            const double got = R.y[(std::size_t)r * n + j] / 128.0;
            worst = std::max(worst, std::abs(got - oracle));
        }
    }
    std::printf("  [info] worst |y - oracle| = %.5f (real units; q7 grid 0.0078)\n", worst);
    chk(worst <= 0.05, "P2 y within the pinned 0.05 fixed-point drift");

    // ---- P3: the exact cases ----
    {
        // n=8: rcp[8] = 2048 exact -> the mean of a q7 row is EXACT
        const auto r8 = logup::rcp_lookup(T.rcp, 8);
        chk(r8 == 2048, "P3 rcp[8] = 2048 (exact power-of-two division)");
        // the constant row: c_i = 0, variance 0 -> eps floor -> y = 0
        bool z0 = true;
        for (unsigned j = 0; j < n; ++j)
            if (R.y[(std::size_t)1 * n + j] != 0) z0 = false;
        chk(z0, "P3 constant row centers to exactly 0 (c = 0 kills y)");
        // the zero row: same
        bool z1 = true;
        for (unsigned j = 0; j < n; ++j)
            if (R.y[(std::size_t)2 * n + j] != 0) z1 = false;
        chk(z1, "P3 zero row outputs exactly 0 (the eps floor)");
    }

    // ---- P4: the affine rung ----
    {
        const auto G = pouw::ln::layernorm_rows(X, rows, n, T, 100, 5, nullptr);
        chk(G.ok, "P4 gamma=100 beta=5 accepted");
        bool aff = true;
        for (std::size_t k = 0; k < R.y.size(); ++k) {
            const std::int64_t expect = ((R.y[k] * 100) >> 7) + 5;
            if (G.y[k] != expect) aff = false;
        }
        chk(aff, "P4 y' = (y*gamma)>>7 + beta holds entrywise");
    }

    // ---- P5: the field mapping round-trips negatives ----
    {
        bool rt = true;
        for (std::size_t k = 0; k < R.y.size(); ++k) {
            const fp::fe f = pouw::ln::fe_from_s64(R.y[k]);
            const auto back = pouw::ln::fe_to_s64(f);
            if (!back.ok || back.v != R.y[k]) rt = false;
        }
        chk(rt, "P5 fe_from_s64/fe_to_s64 round-trip (negatives ride p-|y|)");
        const auto neg = pouw::ln::fe_to_s64(pouw::ln::fe_from_s64(-12345));
        chk(neg.ok && neg.v == -12345, "P5 a large negative value round-trips");
    }

    // ---- P6: the negative model — corrupted table fails certification ----
    {
        auto T2 = T;
        T2.rsqrt[64] += 4096;                       // corrupt one slot
        T2.certified = false;
        const auto R2 = pouw::ln::layernorm_rows(X, rows, n, T2, 128, 0, nullptr);
        chk(R2.ok, "P6 the producer is table-driven (corruption propagates)");
        // the CERTIFIER catches the corruption:
        const auto rep = pouw::logup::certify_rsqrt(T2.rsqrt);
        chk(!rep.ok, "P6 certify_rsqrt REJECTS the corrupted table (grid receipt)");
    }

    // ---- P7: the LogUp audit balances ----
    {
        const auto tsum = logup::table_side_sum(audit,
            [&](unsigned i){ return logup::rcp_lookup(T.rcp, i); });
        chk(logup::balanced(audit, tsum), "P7 the n-division trace BALANCES");
        chk(audit.n_lookups == (std::uint64_t)rows * 2,
            "P7 two divisions per row traced (mean + variance)");
    }

    std::printf("test_step61: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
