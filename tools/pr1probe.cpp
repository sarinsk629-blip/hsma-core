// P1-14a probe: the Poseidon R1CS gadget (the clean restart)
#include <hsma/poseidon_r1cs.hpp>
#include "poseidon_params_gen.hpp"
#include "pallas_params_gen.hpp"
#include <cstdio>
#include <cstring>
using namespace hsma;

int main() {
    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    
    // z[0] = ONE wire = 1 (canonical)
    w.push_back(fp::fe_one());
    // z[1..3] = the input state (s0=1, s1=2, s2=42)
    w.push_back(fp::fe_from_u64(1));
    w.push_back(fp::fe_from_u64(2));
    w.push_back(fp::fe_from_u64(42));
    
    // the round constants (canonical, from the generated params)
    // for the REDUCED permutation (rf_half=1, rp=2), we need:
    // 1*3 + 2 + 1*3 = 8 round constants
    std::vector<std::uint64_t> rc;
    for (unsigned i = 0; i < 8; ++i)
        rc.push_back(i * 100 + 42);  // deterministic test values
    
    // the MDS matrix (from the generated params, canonical)
    std::vector<std::array<std::uint64_t, 3>> mds;
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned j = 0; j < 3; ++j)
            mds.push_back({{0}});  // we'll fill from the params
    
    // fill from the actual params
    {
        unsigned idx = 0;
        for (unsigned i = 0; i < 3; ++i)
            for (unsigned j = 0; j < 3; ++j) {
                const auto& limbs = p3_gen::MDS_CANON[i][j];
                std::uint64_t v = limbs[0];  // low limb for the test
                mds[idx] = {{v, v, v}};  // simplified for the probe
                ++idx;
            }
    }
    
    // build the gadget (REDUCED: rf_half=1, rp=2 → 1+2+1 = 4 rounds)
    auto R = pr1cs::build(A, B, C, w, 1, 2, 3, rc, mds, 1, 2);
    
    std::printf("gadget: %u rows, %u vars, output=%u\n", R.n_rows, R.n_vars, R.output_var);
    
    // SAT check: evaluate A(z) × B(z) = C(z) for all rows
    unsigned n = R.n_rows;
    std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
    for (unsigned t = 0; t < A.row.size(); ++t)
        az[A.row[t]] = fp::fe_add(az[A.row[t]], fp::fe_mul(A.val[t], w[A.col[t]]));
    for (unsigned t = 0; t < B.row.size(); ++t)
        bz[B.row[t]] = fp::fe_add(bz[B.row[t]], fp::fe_mul(B.val[t], w[B.col[t]]));
    for (unsigned t = 0; t < C.row.size(); ++t)
        cz[C.row[t]] = fp::fe_add(cz[C.row[t]], fp::fe_mul(C.val[t], w[C.col[t]]));
    
    bool all_sat = true;
    for (unsigned i = 0; i < n; ++i) {
        fp::fe lhs = fp::fe_mul(az[i], bz[i]);
        if (!(fp::fe_to_canonical(lhs).l == fp::fe_to_canonical(cz[i]).l)) {
            std::printf("UNSAT at row %u\n", i);
            all_sat = false;
            if (i > 2) break;
        }
    }
    std::printf("R1CS SAT: %s\n", all_sat ? "YES" : "NO");
    
    // the output value
    fp::fe out = fp::fe_to_canonical(w[R.output_var]);
    std::printf("output: %016llx%016llx%016llx%016llx\n",
        (unsigned long long)out.l[3], (unsigned long long)out.l[2],
        (unsigned long long)out.l[1], (unsigned long long)out.l[0]);
    
    // scaling
    std::printf("\n-- scaling --\n");
    std::printf("reduced (4 rounds): %u rows, %u vars\n", R.n_rows, R.n_vars);
    double per_round = (double)R.n_rows / 4;
    std::printf("per round: %.1f\n", per_round);
    unsigned full = (unsigned)(per_round * 64);
    std::printf("full (64 rounds): ~%u rows\n", full);
    std::printf("per entry (3 calls): ~%u rows\n", full * 3);
    std::printf("at k=476: ~%llu (the 10^6 target)\n", (unsigned long long)(full * 3 * 476));
    return 0;
}
