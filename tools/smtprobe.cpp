// P1-15b probe: the SMT opening — ONE Poseidon level first
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
    // parse RC and MDS (Montgomery-encoded)
    std::vector<std::array<std::uint64_t,4>> rc;
    for (unsigned i = 0; i < p3_gen::RC_COUNT; ++i)
        rc.push_back(p3_gen::RC_CANON[i]);
    std::vector<std::array<std::array<std::uint64_t,4>,3>> mds;
    for (unsigned i = 0; i < 3; ++i) {
        std::array<std::array<std::uint64_t,4>,3> row;
        for (unsigned j = 0; j < 3; ++j) row[j] = p3_gen::MDS_CANON[i][j];
        mds.push_back(row);
    }

    // build ONE Poseidon-3 R1CS gadget (the SMT hash at one level)
    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    
    // z[0] = ONE wire (Montgomery)
    w.push_back(fp::fe_from_u64(1));
    // z[1] = s0 = the current hash (leaf for level 0)
    w.push_back(fp::fe_from_u64(100));
    // z[2] = s1 = the sibling hash
    w.push_back(fp::fe_from_u64(200));
    // z[3] = s2 = the IV (a fixed domain-separation value)
    w.push_back(fp::fe_from_u64(42));

    unsigned s0_var = 1, s1_var = 2, s2_var = 3;
    
    // REDUCED Poseidon (rf_half=1, rp=2)
    unsigned rf_half = 1, rp = 2;
    
    auto t1 = std::chrono::high_resolution_clock::now();
    auto G = pr1cs::build(A, B, C, w, s0_var, s1_var, s2_var, rc, mds, rf_half, rp);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto build_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    
    std::printf("Poseidon gadget: %u rows, %u vars, output=%u\n", G.n_rows, G.n_vars, G.output_var);
    std::printf("build time: %lld ms\n", (long long)build_ms);
    
    // SAT check
    unsigned n = G.n_rows;
    std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
    for (unsigned t = 0; t < A.row.size(); ++t)
        az[A.row[t]] = fp::fe_add(az[A.row[t]], fp::fe_mul(A.val[t], w[A.col[t]]));
    for (unsigned t = 0; t < B.row.size(); ++t)
        bz[B.row[t]] = fp::fe_add(bz[B.row[t]], fp::fe_mul(B.val[t], w[B.col[t]]));
    for (unsigned t = 0; t < C.row.size(); ++t)
        cz[C.row[t]] = fp::fe_add(cz[C.row[t]], fp::fe_mul(C.val[t], w[C.col[t]]));
    
    bool all_sat = true;
    unsigned unsat_count = 0;
    for (unsigned i = 0; i < n; ++i) {
        fp::fe lhs = fp::fe_mul(az[i], bz[i]);
        if (!(fp::fe_to_canonical(lhs).l == fp::fe_to_canonical(cz[i]).l)) {
            if (unsat_count < 2) {
                fp::fe lc = fp::fe_to_canonical(lhs), rc_ = fp::fe_to_canonical(cz[i]);
                std::printf("UNSAT row %u:\n  lhs: %016llx%016llx%016llx%016llx\n  rhs: %016llx%016llx%016llx%016llx\n",
                    i, (unsigned long long)lc.l[3], (unsigned long long)lc.l[2],
                    (unsigned long long)lc.l[1], (unsigned long long)lc.l[0],
                    (unsigned long long)rc_.l[3], (unsigned long long)rc_.l[2],
                    (unsigned long long)rc_.l[1], (unsigned long long)rc_.l[0]);
            }
            ++unsat_count;
            all_sat = false;
        }
    }
    
    std::printf("R1CS SAT: %s (%u unsat out of %u)\n", all_sat ? "YES" : "NO", unsat_count, n);
    
    // the output
    fp::fe oc = fp::fe_to_canonical(w[G.output_var]);
    std::printf("root: %016llx%016llx%016llx%016llx\n",
        (unsigned long long)oc.l[3], (unsigned long long)oc.l[2],
        (unsigned long long)oc.l[1], (unsigned long long)oc.l[0]);
    
    // scaling
    auto per_level = (double)G.n_rows;
    std::printf("\n-- SMT scaling --\n");
    std::printf("  constraints per Poseidon call: %u\n", G.n_rows);
    std::printf("  at depth=3 (3 calls): ~%u\n", (unsigned)(per_level * 3));
    std::printf("  at depth=64: ~%llu\n", (unsigned long long)(per_level * 64));
    std::printf("  per account opening (d=64): ~%llu\n", (unsigned long long)(per_level * 64));
    std::printf("  per decree entry (2 accounts): ~%llu\n", (unsigned long long)(per_level * 64 * 2));
    std::printf("  at k=476: ~%llu\n", (unsigned long long)(per_level * 64 * 2 * 476));
    
    auto t_end = std::chrono::high_resolution_clock::now();
    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t1).count();
    std::printf("total: %lld ms\n", (long long)total_ms);
    return all_sat ? 0 : 1;
}
