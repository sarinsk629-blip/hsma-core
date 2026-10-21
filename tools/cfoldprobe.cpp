#include <hsma/cfold.hpp>
#include "cfold_golden.hpp"
#include "pedersen_golden.hpp"
#include "mfold_golden.hpp"
#include <cstdio>
#include <cstring>
using namespace hsma;
static void put(const char* tag, const fq::fev& v) {
    fq::fev c = fq::fev_to_canonical(v);
    std::printf("%s %016llx%016llx%016llx%016llx\n", tag,
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
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
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,U,{J});

    // 1. rho' through commitment_consistent's exact path
    fp::fe rho_p = fp::fe_mul(cfold::mk_fe(golden::CF_RHO_U.data()), cfold::mont_R());
    {   const fp::fe rho = fp::fe_mul(cfold::mk_fe(golden::CF_RHO_1.data()), cfold::mont_R());
        rho_p = fp::fe_add(rho_p, fp::fe_mul(M1.r[0], rho)); }
    fp::fe rpc = fp::fe_to_canonical(rho_p);
    std::printf("rr  %016llx%016llx%016llx%016llx   (py: 3f06503325e02cafcab3fff519a3af3a5c67c4c74523fb13873f6b63598b3a4e)\n",
        (unsigned long long)rpc.l[3], (unsigned long long)rpc.l[2],
        (unsigned long long)rpc.l[1], (unsigned long long)rpc.l[0]);
    // also the ORIGINAL path (fe_from_canonical_limbs) for comparison
    fp::fe rho_p2 = fp::fe_from_canonical_limbs(std::array<std::uint64_t,4>{
        golden::CF_RHO_U[0], golden::CF_RHO_U[1], golden::CF_RHO_U[2], golden::CF_RHO_U[3]});
    {   const fp::fe rj  = fp::fe_to_canonical(M1.r[0]);
        const fp::fe rho = fp::fe_from_canonical_limbs(std::array<std::uint64_t,4>{
            golden::CF_RHO_1[0], golden::CF_RHO_1[1], golden::CF_RHO_1[2], golden::CF_RHO_1[3]});
        rho_p2 = fp::fe_add(rho_p2, fp::fe_mul(rj, rho)); }
    fp::fe rpc2 = fp::fe_to_canonical(rho_p2);
    std::printf("rr2 %016llx%016llx%016llx%016llx   (via fe_from_canonical_limbs)\n",
        (unsigned long long)rpc2.l[3], (unsigned long long)rpc2.l[2],
        (unsigned long long)rpc2.l[1], (unsigned long long)rpc2.l[0]);

    // 2. mm[0] (the folded z's first coordinate) vs the mfold golden (proven)
    std::uint64_t mm[cfold::NCOLS][4];
    cfold::to_batches(M1.folded.z, mm);
    std::printf("mm0 %016llx%016llx%016llx%016llx\n",
        (unsigned long long)mm[0][3], (unsigned long long)mm[0][2],
        (unsigned long long)mm[0][1], (unsigned long long)mm[0][0]);
    std::printf("g00 %016llx%016llx%016llx%016llx   (MF_F1_Z[0])\n",
        (unsigned long long)golden::MF_F1_Z[0][3], (unsigned long long)golden::MF_F1_Z[0][2],
        (unsigned long long)golden::MF_F1_Z[0][1], (unsigned long long)golden::MF_F1_Z[0][0]);

    // 3. the two points
    g2v::PtV Wre = pedv::commit(mm, rpc.l.data(), golden::VESTA_PED_ORDER);
    g2v::PtV Wfo = cfold::fold_commitments(CU, {CJ}, M1.r);
    put("Wre", Wre.x); put("Wfo", Wfo.x);
    std::printf("golden WP_X %016llx%016llx%016llx%016llx\n",
        (unsigned long long)golden::CF_WP_X[3], (unsigned long long)golden::CF_WP_X[2],
        (unsigned long long)golden::CF_WP_X[1], (unsigned long long)golden::CF_WP_X[0]);
    return 0;
}
