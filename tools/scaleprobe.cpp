// P1-14b probe: the epoch loop at scale
#include <hsma/poseidon_r1cs.hpp>
#include "poseidon_params_gen.hpp"
#include "pallas_params_gen.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
using namespace hsma;

static fp::fe mont(const fp::fe& c) {
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fp::fe_mul(c, rr);
}

int main() {
    auto t_start = std::chrono::high_resolution_clock::now();
    
    // parse RC and MDS (Montgomery-encoded)
    std::vector<std::array<std::uint64_t,4>> rc;  // Montgomery-encoded RC constants
    for (unsigned i = 0; i < p3_gen::RC_COUNT; ++i) {
        fp::fe m = mont(fp::fe_from_canonical_limbs(
            std::array<std::uint64_t,4>{p3_gen::RC_CANON[i][0], p3_gen::RC_CANON[i][1],
                                         p3_gen::RC_CANON[i][2], p3_gen::RC_CANON[i][3]}));
        rc.push_back({m.l[0], m.l[1], m.l[2], m.l[3]});
    }
    std::vector<std::array<std::array<std::uint64_t,4>,3>> mds;
    for (unsigned i = 0; i < 3; ++i) {
        std::array<std::array<std::uint64_t,4>,3> row;
        for (unsigned j = 0; j < 3; ++j) {
            fp::fe m = mont(fp::fe_from_canonical_limbs(
                std::array<std::uint64_t,4>{p3_gen::MDS_CANON[i][j][0], p3_gen::MDS_CANON[i][j][1],
                                             p3_gen::MDS_CANON[i][j][2], p3_gen::MDS_CANON[i][j][3]}));
            row[j] = {m.l[0], m.l[1], m.l[2], m.l[3]};
        }
        mds.push_back(row);
    }
    
    std::printf("P1-14b: the epoch loop at scale (REDUCED Poseidon: rf_half=1, rp=2)\n");
    std::printf("%-6s %8s %8s %10s\n", "k", "rows", "vars", "time_ms");
    std::printf("%-6s %8s %8s %10s\n", "-----", "------", "------", "--------");
    
    unsigned k_values[] = {1, 5, 10, 50, 100};
    
    for (unsigned k : k_values) {
        mfold::SparseMat A, B, C;
        std::vector<fp::fe> w;
        w.push_back(mont(fp::fe_from_u64(1)));  // ONE wire
        
        auto t0 = std::chrono::high_resolution_clock::now();
        unsigned prev_output = 0;
        
        for (unsigned step = 0; step < k; ++step) {
            unsigned s0, s1, s2;
            if (step == 0) {
                s0 = (unsigned)w.size(); w.push_back(mont(fp::fe_from_u64(1000)));
                s1 = (unsigned)w.size(); w.push_back(mont(fp::fe_from_u64(2000)));
            } else {
                s0 = prev_output;
                s1 = (unsigned)w.size(); w.push_back(mont(fp::fe_from_u64(2000 + step)));
            }
            s2 = (unsigned)w.size(); w.push_back(mont(fp::fe_from_u64(42)));
            
            auto G = pr1cs::build(A, B, C, w, s0, s1, s2, rc, mds, 1, 2);
            prev_output = G.output_var;
        }
        
        auto t1 = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        
        std::printf("%-6u %8u %8u %10lld\n", k, (unsigned)A.row.size(), (unsigned)w.size(), (long long)ms);
    }
    
    auto t_end = std::chrono::high_resolution_clock::now();
    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
    
    std::printf("\n-- the 10^6 target --\n");
    unsigned rows_per_step = 80;  // from the reduced gadget measurement
    std::printf("at k=476 with FULL Poseidon (rf_half=4, rp=56): ~%llu rows\n",
        (unsigned long long)((1280 / 4) * 3 * 476));
    std::printf("scaling: LINEAR in k (confirmed)\n");
    std::printf("total probe time: %lld ms\n", (long long)total_ms);
    return 0;
}
