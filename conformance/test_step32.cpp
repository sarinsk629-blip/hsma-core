// Step-32 conformance: commitment folding (DEC-230, GAP-06).
// The REAL cfold over the REAL mfold; commitments vs the flat golden;
// the binding identity; negatives per CA-R134.
#include <hsma/cfold.hpp>
#include "cfold_golden.hpp"
#include "pedersen_golden.hpp"
#include "mfold_golden.hpp"
#include <cstdio>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", m, __LINE__); ++failures; } } while (0)
static bool eq4(const std::array<std::uint64_t,4>& a, const std::array<std::uint64_t,4>& b) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false; return true; }
static fp::fe can(const fp::fe& x) { return fp::fe_to_canonical(x); }
static bool pt_eq(const g2v::PtV& P, const std::array<std::uint64_t,4>& gx, const std::array<std::uint64_t,4>& gy) {
    fq::fev x, y;
    if (!g2v::to_affine(P, x, y)) return false;
    const fq::fev xc = fq::fev_to_canonical(x), yc = fq::fev_to_canonical(y);
    return eq4(xc.l, gx) && eq4(yc.l, gy);
}
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
        z[7] = fp::fe_mul(z[2], z[3]); z[5] = fp::fe_mul(z[4], z[4]);
        z[6] = fp::fe_mul(z[5], z[5]);
        return z; };
    mfold::Relaxed U = mfold::fresh(wit(3,4,5,6), golden::MF_ROWS);
    mfold::Relaxed J = mfold::fresh(wit(2,1,3,4), golden::MF_ROWS);
    cfold::CommittedInstance CU = cfold::commit_instance(U, golden::CF_RHO_U.data(), golden::VESTA_PED_ORDER);
    cfold::CommittedInstance CJ = cfold::commit_instance(J, golden::CF_RHO_1.data(), golden::VESTA_PED_ORDER);
    CHECK(pt_eq(CU.W, golden::CF_CW_U_X, golden::CF_CW_U_Y), "C_WU parity");
    CHECK(pt_eq(CJ.W, golden::CF_CW_1_X, golden::CF_CW_1_Y), "C_W1 parity");
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,U,{J});
    CHECK(eq4(can(M1.r[0]).l, golden::MF_R1), "r1 (cross-file, mfold golden)");
    CHECK(eq4(can(M1.folded.u).l, golden::MF_F1_U), "u' (cross-file)");
    {   std::uint64_t tp[8][4];
        for (unsigned i = 0; i < 8; ++i) for (int k = 0; k < 4; ++k) tp[i][k] = 0;
        for (unsigned i = 0; i < M1.T[0].size() && i < 8; ++i) {
            fp::fe c = fp::fe_to_canonical(M1.T[0][i]);
            for (int k = 0; k < 4; ++k) tp[i][k] = c.l[k]; }
        g2v::PtV CT = pedv::commit(tp, golden::CF_RHO_T.data(), golden::VESTA_PED_ORDER);
        CHECK(pt_eq(CT, golden::CF_CT_1_X, golden::CF_CT_1_Y), "C_T1 parity");
    }
    g2v::PtV Wfo = cfold::fold_commitments(CU, {CJ}, M1.r);
    CHECK(pt_eq(Wfo, golden::CF_WP_X, golden::CF_WP_Y), "W' fold parity");
    CHECK(cfold::commitment_consistent(CU, {CJ}, M1, golden::VESTA_PED_ORDER), "recommit == fold (the binding identity)");
    CHECK(pt_eq(Wfo, golden::CF_WRE_X, golden::CF_WRE_Y), "Wre golden parity");
    {   cfold::CommittedInstance Bad = CJ;
        std::uint64_t m[8][4]; cfold::to_batches(Bad.rel.z, m); m[0][0] += 1;
        Bad.W = pedv::commit(m, Bad.rho, golden::VESTA_PED_ORDER);
        fq::fev x1, y1, x2, y2;
        g2v::to_affine(Bad.W, x1, y1); g2v::to_affine(CJ.W, x2, y2);
        CHECK(!(x1.l == x2.l), "neg: witness binding");
    }
    {   std::vector<fp::fe> rb = M1.r;
        rb[0] = fp::fe_add(rb[0], fp::fe_one());
        g2v::PtV Wb = cfold::fold_commitments(CU, {CJ}, rb);
        fq::fev x1, y1, x2, y2;
        g2v::to_affine(Wb, x1, y1); g2v::to_affine(Wfo, x2, y2);
        CHECK(!(x1.l == x2.l), "neg: challenge binding");
    }
    if (failures == 0)
        std::printf("step32 conformance: ALL GREEN - commitment folding: C_W/C_T parity, recommit==fold identity, binding + challenge-binding negatives\n");
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}
