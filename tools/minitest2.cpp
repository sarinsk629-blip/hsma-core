#include <hsma/fexec_circuit.hpp>
#include <cstdio>
using namespace hsma;
int main() {
    // test: fe_mul(2,3) == 6? YES (confirmed)
    // test: the R1CS constraint z1*z2=z3 with z=[1,2,3,6,12]
    mfold::SparseMat A, B, C;
    A.n_rows = B.n_rows = C.n_rows = 2;
    A.n_cols = B.n_cols = C.n_cols = 5;
    auto tri = [](mfold::SparseMat& M, unsigned r, unsigned c, unsigned v) {
        M.row.push_back(r); M.col.push_back(c); M.val.push_back(fp::fe_from_u64(v)); };
    // Constraint 1: z[1] * z[2] = z[3]  (A: z[1], B: z[2], C: z[3])
    // Constraint 2: z[1] * z[3] = z[4]  (A: z[1], B: z[3], C: z[4])
    tri(A,0,1,1); tri(A,1,1,1);
    tri(B,0,2,1); tri(B,1,3,1);
    tri(C,0,3,1); tri(C,1,4,1);
    std::vector<fp::fe> z(5, fp::fe_zero());
    z[0] = fp::fe_from_u64(1); z[1] = fp::fe_from_u64(2);
    z[2] = fp::fe_from_u64(3); z[3] = fp::fe_from_u64(6);
    z[4] = fp::fe_from_u64(12);
    // evaluate with fe_mul (the CORRECT multiplication)
    unsigned n = 2;
    std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
    for (unsigned t = 0; t < A.row.size(); ++t)
        az[A.row[t]] = fp::fe_add(az[A.row[t]], fp::fe_mul(A.val[t], z[A.col[t]]));
    for (unsigned t = 0; t < B.row.size(); ++t)
        bz[B.row[t]] = fp::fe_add(bz[B.row[t]], fp::fe_mul(B.val[t], z[B.col[t]]));
    for (unsigned t = 0; t < C.row.size(); ++t)
        cz[C.row[t]] = fp::fe_add(cz[C.row[t]], fp::fe_mul(C.val[t], z[C.col[t]]));
    for (unsigned i = 0; i < n; ++i) {
        fp::fe lhs = fp::fe_mul(az[i], bz[i]);
        bool sat = fp::fe_to_canonical(lhs).l == fp::fe_to_canonical(cz[i]).l;
        std::printf("row %u SAT: %s\n", i, sat ? "YES" : "NO");
    }
    return 0;
}
