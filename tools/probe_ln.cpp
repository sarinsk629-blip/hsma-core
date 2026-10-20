// probe: step61 per-row drift
#include <hsma/pouw/layernorm.hpp>
#include <hsma/pouw/logup_ref.hpp>
#include <cstdio>
#include <cmath>
#include <vector>
using namespace hsma;
using namespace hsma::pouw;
int main() {
    const auto T = pouw::logup::build_all();
    const unsigned rows = 6, n = 8;
    std::vector<std::vector<double>> xr = {
        {3.0, 1.0, 2.0, 0.5, 4.0, 2.5, 1.5, 0.25},
        {1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0},
        {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0},
        {6.0, 2.0, 5.0, 1.0, 7.0, 3.0, 4.0, 0.5},
        {0.125, 0.25, 0.375, 0.5, 0.625, 0.75, 0.875, 1.0},
        {2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 3.0},
    };
    std::vector<fp::fe> X((std::size_t)rows * n);
    for (unsigned r = 0; r < rows; ++r)
        for (unsigned j = 0; j < n; ++j)
            X[(std::size_t)r * n + j] =
                fp::fe_from_u64((std::uint64_t)std::llround(xr[r][j] * 128.0));
    const auto R = pouw::ln::layernorm_rows(X, rows, n, T, 128, 0, nullptr);
    std::printf("ok=%d\n", (int)R.ok);
    for (unsigned r = 0; r < rows; ++r) {
        double mean = 0, var = 0;
        for (unsigned j = 0; j < n; ++j) mean += xr[r][j];
        mean /= n;
        for (unsigned j = 0; j < n; ++j) var += (xr[r][j] - mean) * (xr[r][j] - mean);
        var /= n;
        double worst = 0; unsigned wj = 0;
        for (unsigned j = 0; j < n; ++j) {
            const double oracle = (xr[r][j] - mean) / std::sqrt(var + 1e-4);
            const double got = R.y[(std::size_t)r * n + j] / 128.0;
            if (std::abs(got - oracle) > worst) { worst = std::abs(got - oracle); wj = j; }
        }
        const double oracle_w = (xr[r][wj] - mean) / std::sqrt(var + 1e-4);
        std::printf("row %u: worst=%.4f @j=%u got=%.4f oracle=%.4f (var=%.5f)\n",
                    r, worst, wj, R.y[(std::size_t)r * n + wj] / 128.0, oracle_w, var);
    }
    return 0;
}
