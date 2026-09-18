// Step-31 conformance: the HyperNova multifold core (DEC-229, GAP-06).
// Rebuilds the circuit + witnesses, runs the REAL mfold::multifold, checks
// every vector vs the flat golden. Negatives per CA-R134. CA-R127: flat arrays.
#include <hsma/mfold.hpp>
#include "mfold_golden.hpp"
#include <cstdio>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", m, __LINE__); ++failures; } } while (0)
static bool eq4(const std::uint64_t a[4], const std::uint64_t b[4]) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false; return true; }
static fp::fe can(const fp::fe& x) { return fp::fe_to_canonical(x); }
int main() {
    mfold::SparseMat A, B, C;
    A.n_rows = B.n_rows = C.n_rows = golden::MF_ROWS;
    A.n_cols = B.n_cols = C.n_cols = golden::MF_COLS;
    auto tri = [](mfold::SparseMat& M, unsigned r, unsigned c, unsigned v) {
        M.row.push_back(r); M.col.push_back(c); M.val.push_back(fp::fe_from_u64(v)); };
    tri(A,0,0,1); tri(A,0,1,1); tri(A,1,2,1); tri(A,2,4,1); tri(A,3,5,1);
    tri(B,0,2,1); tri(B,1,3,1); tri(B,2,4,1); tri(B,3,5,1);
    tri(C,0,3,1); tri(C,1,7,1); tri(C,2,5,1); tri(C,3,6,1);
    auto wit = [](unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d) {
        std::vector<fp::fe> z(8, fp::fe_zero());
        z[0] = fp::fe_from_u64(a); z[1] = fp::fe_from_u64(b);
        z[2] = fp::fe_from_u64(c); z[4] = fp::fe_from_u64(d);
        z[3] = fp::fe_mul(fp::fe_add(z[0], z[1]), z[2]);
        z[7] = fp::fe_mul(z[2], z[3]);
        z[5] = fp::fe_mul(z[4], z[4]);
        z[6] = fp::fe_mul(z[5], z[5]);
        return z; };
    mfold::Relaxed U = mfold::fresh(wit(3,4,5,6), golden::MF_ROWS);
    mfold::Relaxed J = mfold::fresh(wit(2,1,3,4), golden::MF_ROWS);
    CHECK(mfold::sat_relaxed(A,B,C,U) == golden::MF_ROWS, "U SAT");
    CHECK(mfold::sat_relaxed(A,B,C,J) == golden::MF_ROWS, "J SAT");
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,U,{J});
    CHECK(eq4(can(M1.seed).l.data(), golden::MF_SEED1.data()), "FS seed1 parity");
    CHECK(eq4(can(M1.r[0]).l.data(), golden::MF_R1.data()), "r1 parity");
    CHECK(M1.T[0].size() == golden::MF_T1.size(), "T1 count");
    for (unsigned i = 0; i < golden::MF_T1.size(); ++i)
        CHECK(eq4(can(M1.T[0][i]).l.data(), golden::MF_T1[i].data()), "T1 row parity");
    CHECK(M1.folded.z.size() == golden::MF_F1_Z.size(), "F1 z count");
    for (unsigned i = 0; i < golden::MF_F1_Z.size(); ++i)
        CHECK(eq4(can(M1.folded.z[i]).l.data(), golden::MF_F1_Z[i].data()), "F1 z parity");
    CHECK(eq4(can(M1.folded.u).l.data(), golden::MF_F1_U.data()), "F1 u parity");
    for (unsigned i = 0; i < golden::MF_F1_E.size(); ++i)
        CHECK(eq4(can(M1.folded.E[i]).l.data(), golden::MF_F1_E[i].data()), "F1 E parity");
    CHECK(mfold::sat_relaxed(A,B,C,M1.folded) == golden::MF_ROWS, "fold1 SAT");
    { bool nz = false; for (const auto& e : M1.folded.E) if (!fp::fe_is_zero(e)) nz = true;
      CHECK(nz, "fold1 E nonzero"); }
    mfold::MultifoldResult M2 = mfold::multifold(A,B,C,M1.folded,{J});
    CHECK(eq4(can(M2.seed).l.data(), golden::MF_SEED2.data()), "FS seed2 parity");
    CHECK(M2.r.size() == golden::MF_R2.size(), "r2 count");
    for (unsigned j = 0; j < golden::MF_R2.size(); ++j)
        CHECK(eq4(can(M2.r[j]).l.data(), golden::MF_R2[j].data()), "r2 parity");
    CHECK(mfold::sat_relaxed(A,B,C,M2.folded) == golden::MF_ROWS, "fold2 SAT");
    { mfold::Relaxed Bad = J; Bad.z[0] = fp::fe_add(Bad.z[0], fp::fe_one());
      mfold::MultifoldResult MB = mfold::multifold(A,B,C,U,{Bad});
      CHECK(mfold::sat_relaxed(A,B,C,MB.folded) != golden::MF_ROWS, "neg: tamper corrupts"); }
    if (failures == 0)
        std::printf("step31 conformance: ALL GREEN - multifold core: FS seeds/challenges, T, z/u/E parity, fold1 relaxed (E!=0), fold2 loop SAT, tamper negative\n");
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}
