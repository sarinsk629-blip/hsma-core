// HSMA :: gkrprobe.cpp - P1-16 (the GEMM-as-R1CS probe, DEC-244).
// THE RECEIPT: 3x3 GEMM, 36/36 R1CS SAT, known-answer C exact.
// Layout: z[0]=ONE | A | B | C | products P(i,j,k) at G.p_offset.
//   product row: A[i][k] * B[k][j] = P_k   (SAT only if P_k is COMPUTED)
//   sum row:     C[i][j] * 1    = sum_k P_k
// 36 rows = 9 outputs x (3 product rows + 1 sum row).
#include <hsma/gkr.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;

int main() {
    constexpr unsigned rows = 3, cols = 3, inner = 3;
    std::printf("GKR/GEMM probe: %ux%u x %ux%u\n", rows, inner, inner, cols);

    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    w.push_back(fp::fe_one()); // z[0] = ONE wire

    auto G = gkr::build_gemm(A, B, C, w, rows, cols, inner);
    std::printf("rows: %u | vars: %u\n", G.n_constraints, G.n_vars);
    std::printf("a_off=%u b_off=%u c_off=%u p_off=%u\n",
                G.a_offset, G.b_offset, G.c_offset, G.p_offset);

    unsigned a_vals[3][3] = {{1,2,3},{4,5,6},{7,8,9}};
    unsigned b_vals[3][3] = {{9,8,7},{6,5,4},{3,2,1}};

    for (unsigned i = 0; i < rows; ++i)
        for (unsigned k = 0; k < inner; ++k)
            w[G.a_offset + i*inner + k] = fp::fe_from_u64(a_vals[i][k]);
    for (unsigned k = 0; k < inner; ++k)
        for (unsigned j = 0; j < cols; ++j)
            w[G.b_offset + k*cols + j] = fp::fe_from_u64(b_vals[k][j]);

    // [P1-16 FIX] product witnesses are COMPUTED, never assumed:
    for (unsigned i = 0; i < rows; ++i)
        for (unsigned j = 0; j < cols; ++j)
            for (unsigned k = 0; k < inner; ++k)
                w[G.p_offset + (i*cols + j)*inner + k] =
                    fp::fe_mul(w[G.a_offset + i*inner + k],
                               w[G.b_offset + k*cols + j]);

    // C[i][j] = sum of ITS OWN product witnesses (same order as the sum row)
    for (unsigned i = 0; i < rows; ++i)
        for (unsigned j = 0; j < cols; ++j) {
            fp::fe acc = fp::fe_zero();
            for (unsigned k = 0; k < inner; ++k)
                acc = fp::fe_add(acc, w[G.p_offset + (i*cols + j)*inner + k]);
            w[G.c_offset + i*cols + j] = acc;
        }

    unsigned n = G.n_constraints;
    std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
    for (unsigned t = 0; t < A.row.size(); ++t)
        az[A.row[t]] = fp::fe_add(az[A.row[t]], fp::fe_mul(A.val[t], w[A.col[t]]));
    for (unsigned t = 0; t < B.row.size(); ++t)
        bz[B.row[t]] = fp::fe_add(bz[B.row[t]], fp::fe_mul(B.val[t], w[B.col[t]]));
    for (unsigned t = 0; t < C.row.size(); ++t)
        cz[C.row[t]] = fp::fe_add(cz[C.row[t]], fp::fe_mul(C.val[t], w[C.col[t]]));

    bool all_sat = true; unsigned unsat = 0;
    for (unsigned i = 0; i < n; ++i) {
        fp::fe lhs = fp::fe_to_canonical(fp::fe_mul(az[i], bz[i]));
        fp::fe rhs = fp::fe_to_canonical(cz[i]);
        if (!(lhs.l == rhs.l)) {
            if (unsat < 3)
                std::printf("UNSAT row %u\n  lhs %016llx%016llx%016llx%016llx\n  rhs %016llx%016llx%016llx%016llx\n",
                    i, (unsigned long long)lhs.l[3], (unsigned long long)lhs.l[2],
                       (unsigned long long)lhs.l[1], (unsigned long long)lhs.l[0],
                       (unsigned long long)rhs.l[3], (unsigned long long)rhs.l[2],
                       (unsigned long long)rhs.l[1], (unsigned long long)rhs.l[0]);
            ++unsat; all_sat = false;
        }
    }
    std::printf("R1CS SAT: %s (%u unsat / %u rows)\n", all_sat ? "YES" : "NO", unsat, n);

    unsigned expect[3][3] = {{30,24,18},{84,69,54},{138,114,90}};
    bool ka_ok = true;
    std::printf("\n-- C = A x B --\n");
    for (unsigned i = 0; i < rows; ++i) {
        std::printf("  [");
        for (unsigned j = 0; j < cols; ++j) {
            fp::fe c = fp::fe_to_canonical(w[G.c_offset + i*cols + j]);
            bool m = (c.l[0] == expect[i][j]) && !c.l[1] && !c.l[2] && !c.l[3];
            ka_ok = ka_ok && m;
            std::printf("%llu%s", (unsigned long long)c.l[0], (j < cols-1) ? ", " : "");
        }
        std::printf(" ]\n");
    }
    std::printf("known-answer match: %s\n", ka_ok ? "YES" : "NO");

    std::printf("\n=======================================\n");
    std::printf("  GKR/GEMM SCALING RECEIPT (P1-16)\n");
    std::printf("=======================================\n");
    std::printf("  3x3    : %u rows, %u vars (this run)\n", G.n_constraints, G.n_vars);
    for (unsigned nn : {16u, 64u, 128u, 256u})
        std::printf("  %3ux%-3u : ~%u rows, ~%u vars\n", nn, nn,
                    nn*nn*(nn+1), 1 + 3*nn*nn + nn*nn*nn);
    std::printf("  k=476 epoch (128x128 x3 x476): ~%llu rows\n",
                (unsigned long long)128ull*128u*129u*3u*476u);
    std::printf("=======================================\n");

    return (all_sat && ka_ok) ? 0 : 1;
}
