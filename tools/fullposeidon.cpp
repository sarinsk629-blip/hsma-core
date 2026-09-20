// P1-15a: the FULL Poseidon-3 as R1CS — rf_half=4, rp=56 (the production parameters)
// Measures the exact constraint count, verifies SAT, prints the scaling receipt.
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
    std::printf("P1-15a: FULL Poseidon-3 R1CS (rf_half=4, rp=56)\n");
    std::printf("================================================\n\n");

    // parse RC and MDS (canonical — the R1CS domain is canonical per CA-R158)
    std::vector<std::array<std::uint64_t,4>> rc;
    for (unsigned i = 0; i < p3_gen::RC_COUNT; ++i)
        rc.push_back(p3_gen::RC_CANON[i]);
    std::vector<std::array<std::array<std::uint64_t,4>,3>> mds;
    for (unsigned i = 0; i < 3; ++i) {
        std::array<std::array<std::uint64_t,4>,3> row;
        for (unsigned j = 0; j < 3; ++j)
            row[j] = p3_gen::MDS_CANON[i][j];
        mds.push_back(row);
    }

    // build the R1CS constraint system
    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    // z[0] = ONE wire = 1 (canonical)
    w.push_back(fp::fe_one());
    // z[1..3] = the input state (small values for the probe)
    w.push_back(fp::fe_from_u64(1));   // s0
    w.push_back(fp::fe_from_u64(2));   // s1
    w.push_back(fp::fe_from_u64(42));  // s2 (the IV placeholder)

    std::uint64_t iv[4] = {42, 0, 0, 0};

    auto t0 = std::chrono::high_resolution_clock::now();
    auto G = pr1cs::build(A, B, C, w, 1, 2, 3, rc, mds, 4, 56);
    auto t1 = std::chrono::high_resolution_clock::now();

    auto build_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    std::printf("gadget constraints: %u\n", G.n_rows);
    std::printf("gadget variables:   %u\n", G.n_vars);
    std::printf("output var:         %u\n", G.output_var);
    std::printf("build time:         %lld ms\n", (long long)build_ms);

    // SAT check: evaluate A(z) × B(z) = C(z) using fe_mul
    auto t2 = std::chrono::high_resolution_clock::now();
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
            if (unsat_count < 3) {
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
    auto t3 = std::chrono::high_resolution_clock::now();
    auto sat_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();

    std::printf("R1CS SAT: %s (%u unsat out of %u)\n", all_sat ? "YES" : "NO", unsat_count, n);
    std::printf("SAT check time: %lld ms\n", (long long)sat_ms);

    // the output value
    fp::fe oc = fp::fe_to_canonical(w[G.output_var]);
    std::printf("output: %016llx%016llx%016llx%016llx\n",
        (unsigned long long)oc.l[3], (unsigned long long)oc.l[2],
        (unsigned long long)oc.l[1], (unsigned long long)oc.l[0]);

    // the scaling receipt
    std::printf("\n═══════════════════════════════════════\n");
    std::printf("  SCALING RECEIPT — FULL POSEIDON\n");
    std::printf("═══════════════════════════════════════\n");
    std::printf("  constraints per Poseidon-3:  %u\n", G.n_rows);
    std::printf("  variables per Poseidon-3:    %u\n", G.n_vars);
    std::printf("  per decree entry (3 calls):  %u\n", G.n_rows * 3);
    std::printf("  at k=476 entries:            %llu\n", (unsigned long long)(G.n_rows * 3 * 476));
    std::printf("  the 10^6 target:             %s\n",
        (G.n_rows * 3 * 476 >= 1000000) ? "EXCEEDED ✓" : "NOT REACHED");
    std::printf("═══════════════════════════════════════\n");

    return all_sat ? 0 : 1;
}
