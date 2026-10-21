#include <hsma/mfold.hpp>
#include <cstdio>
using namespace hsma;
int main() {
    // 4-row circuit, every witness coordinate assigned EXACTLY once:
    //   row0: (z0+z1)*z2 = z3      row1: z2*z3 = z7
    //   row2: z4*z4     = z5      row3: z5*z5 = z6
    mfold::SparseMat A, B, C;
    A.n_rows = B.n_rows = C.n_rows = 4;
    A.n_cols = B.n_cols = C.n_cols = 8;
    auto tri = [](mfold::SparseMat& M, unsigned r, unsigned c, unsigned v) {
        M.row.push_back(r); M.col.push_back(c); M.val.push_back(fp::fe_from_u64(v)); };
    tri(A,0,0,1); tri(A,0,1,1); tri(A,1,2,1); tri(A,2,4,1); tri(A,3,5,1);
    tri(B,0,2,1); tri(B,1,3,1); tri(B,2,4,1); tri(B,3,5,1);
    tri(C,0,3,1); tri(C,1,7,1); tri(C,2,5,1); tri(C,3,6,1);

    auto wit = [](unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d) {
        std::vector<fp::fe> z(8, fp::fe_zero());
        z[0] = fp::fe_from_u64(a); z[1] = fp::fe_from_u64(b);
        z[2] = fp::fe_from_u64(c); z[4] = fp::fe_from_u64(d);
        z[3] = fp::fe_mul(fp::fe_add(z[0], z[1]), z[2]);   // row0
        z[7] = fp::fe_mul(z[2], z[3]);                      // row1
        z[5] = fp::fe_mul(z[4], z[4]);                      // row2
        z[6] = fp::fe_mul(z[5], z[5]);                      // row3
        return z;
    };

    mfold::Relaxed U  = mfold::fresh(wit(3,4,5,6), 4);
    mfold::Relaxed J1 = mfold::fresh(wit(2,1,3,4), 4);
    std::printf("U  sat: %s\\n", mfold::sat_relaxed(A,B,C,U)  == 4 ? "SAT" : "FAIL");
    std::printf("J1 sat: %s\\n", mfold::sat_relaxed(A,B,C,J1) == 4 ? "SAT" : "FAIL");

    // fold 1: fresh+fresh -> RELAXED (u = 1+r, E = r*T which is NONZERO)
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,U,{J1});
    bool e_nz = false; for (const auto& e : M1.folded.E) if (!fp::fe_is_zero(e)) e_nz = true;
    std::printf("fold1: sat=%s u=%s E_nonzero=%s\\n",
        mfold::sat_relaxed(A,B,C,M1.folded) == 4 ? "SAT" : "FAIL",
        nifs::feq(M1.folded.u, fp::fe_add(fp::fe_one(), M1.r[0])) ? "OK" : "BAD",
        e_nz ? "yes" : "no");

    // fold 2: RELAXED accumulator + fresh -> the HyperNova loop, still SAT
    mfold::MultifoldResult M2 = mfold::multifold(A,B,C,M1.folded,{J1});
    std::printf("fold2: sat=%s\\n", mfold::sat_relaxed(A,B,C,M2.folded) == 4 ? "SAT" : "FAIL");

    // negative (CA-R134): fold with a TAMPERED instance -> accumulator corrupted
    mfold::Relaxed Bad = J1; Bad.z[0] = fp::fe_add(Bad.z[0], fp::fe_one());
    mfold::MultifoldResult MB = mfold::multifold(A,B,C,U,{Bad});
    std::printf("neg(tampered J): folded sat=%s (want FAIL)\\n",
        mfold::sat_relaxed(A,B,C,MB.folded) == 4 ? "SAT (!!)" : "FAIL (correct)");
    return 0;
}
