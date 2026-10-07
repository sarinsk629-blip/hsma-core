#include <hsma/threshold/dkg_vss.hpp>
#include <hsma/consensus.hpp>
#include <cstdio>
#include <chrono>
using namespace hsma;
int main() {
    for (auto n : {3, 5, 10, 50, 100, 224}) {
        unsigned t = n / 2;
        auto start = std::chrono::steady_clock::now();
        threshold::vss::Transcript T{};
        if (!threshold::vss::deal(T, 0, n, t)) {
            std::printf("n=%llu t=%llu: DEAL FAILED\n", (unsigned long long)n, (unsigned long long)t);
            continue;
        }
        auto deal_end = std::chrono::steady_clock::now();
        double deal_ms = std::chrono::duration<double, std::milli>(deal_end - start).count();
        
        auto verify_start = std::chrono::steady_clock::now();
        unsigned verified = 0;
        for (std::uint64_t j = 1; j <= n; ++j) {
            if (threshold::vss::verify_share(T, j, T.Y[j])) verified++;
        }
        auto verify_end = std::chrono::steady_clock::now();
        double verify_ms = std::chrono::duration<double, std::milli>(verify_end - verify_start).count();
        
        std::printf("n=%3llu t=%3llu | deal: %8.1f ms | verify: %8.1f ms | %llu/%llu verified\n",
            (unsigned long long)n, (unsigned long long)t,
            (unsigned long long)verified, (unsigned long long)n,
            deal_ms, verify_ms);
    }
    return 0;
}
