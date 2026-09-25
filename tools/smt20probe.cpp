// HSMA :: smt20probe.cpp - P1-20 (DEC-260): verify the P1-15b artifact.
// [G+]    depth-1 build_smt_opening: R1CS SAT (the artifact's real behavior)
// [G-sem] gadget output == independent mirror of the reduced permutation
// [G-dir] direction bit flipped -> IDENTICAL root (DEF-192: channel dead)
// [G-any] different leaf -> still SAT, different root (DEF-193: no binding)
// [G-coll] depth-2: output == mirror with IV overridden by sibling[1] (DEF-195)
// [G-meta] R.n_rows stale vs actual rows (DEF-194)
#include <hsma/smt_r1cs.hpp>
#include <hsma/poseidon.hpp>
#include "poseidon_params_gen.hpp"
#include "pallas_params_gen.hpp"
#include <cstdio>
#include <vector>
using namespace hsma;

static fp::fe limbs(const std::array<std::uint64_t,4>& c) {
    fp::fe x{}; for (int k = 0; k < 4; ++k) x.l[k] = c[k]; return x;
}
// independent mirror of pr1cs::build's reduced permutation (values only) -
// line-faithful to [S3]: ARK -> sbox -> MDS; partial rounds sbox lane 0 only;
// consumes rc[0..7] per call (rf_half=1, rp=2).
static fp::fe reduced_perm(const fp::fe& s0, const fp::fe& s1, const fp::fe& s2,
                           const std::vector<std::array<std::uint64_t,4>>& rc,
                           const std::vector<std::array<std::array<std::uint64_t,4>,3>>& mds) {
    fp::fe st[3] = {s0, s1, s2};
    unsigned idx = 0;
    auto sbox = [](fp::fe x){ fp::fe x2 = fp::fe_mul(x,x); fp::fe x4 = fp::fe_mul(x2,x2); return fp::fe_mul(x,x4); };
    auto mdsr = [&](const fp::fe in[3], fp::fe out[3]) {
        for (int i = 0; i < 3; ++i) {
            fp::fe acc = fp::fe_zero();
            for (int j = 0; j < 3; ++j) acc = fp::fe_add(acc, fp::fe_mul(limbs(mds[i][j]), in[j]));
            out[i] = acc;
        }
    };
    for (unsigned r = 0; r < 1; ++r) {
        for (int l = 0; l < 3; ++l) st[l] = fp::fe_add(st[l], limbs(rc[idx++]));
        fp::fe sb[3]; for (int l = 0; l < 3; ++l) sb[l] = sbox(st[l]);
        fp::fe o[3]; mdsr(sb, o); for (int l = 0; l < 3; ++l) st[l] = o[l];
    }
    for (unsigned r = 0; r < 2; ++r) {
        st[0] = fp::fe_add(st[0], limbs(rc[idx++]));
        fp::fe sb0 = sbox(st[0]);
        fp::fe in[3] = {sb0, st[1], st[2]};
        fp::fe o[3]; mdsr(in, o); st[0]=o[0]; st[1]=o[1]; st[2]=o[2];
    }
    for (unsigned r = 0; r < 1; ++r) {
        for (int l = 0; l < 3; ++l) st[l] = fp::fe_add(st[l], limbs(rc[idx++]));
        fp::fe sb[3]; for (int l = 0; l < 3; ++l) sb[l] = sbox(st[l]);
        fp::fe o[3]; mdsr(sb, o); for (int l = 0; l < 3; ++l) st[l] = o[l];
    }
    return st[0];
}
static bool sat_check(const mfold::SparseMat& A, const mfold::SparseMat& B,
                      const mfold::SparseMat& C, const std::vector<fp::fe>& w,
                      unsigned* actual) {
    const unsigned n = (unsigned)A.row.size();
    if (actual) *actual = n;
    std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
    for (unsigned t = 0; t < A.row.size(); ++t)
        az[A.row[t]] = fp::fe_add(az[A.row[t]], fp::fe_mul(A.val[t], w[A.col[t]]));
    for (unsigned t = 0; t < B.row.size(); ++t)
        bz[B.row[t]] = fp::fe_add(bz[B.row[t]], fp::fe_mul(B.val[t], w[B.col[t]]));
    for (unsigned t = 0; t < C.row.size(); ++t)
        cz[C.row[t]] = fp::fe_add(cz[C.row[t]], fp::fe_mul(C.val[t], w[C.col[t]]));
    for (unsigned i = 0; i < n; ++i) {
        fp::fe l = fp::fe_to_canonical(fp::fe_mul(az[i], bz[i]));
        fp::fe r = fp::fe_to_canonical(cz[i]);
        if (!(l.l == r.l)) return false;
    }
    return true;
}
int main() {
    std::vector<std::array<std::uint64_t,4>> rc;
    for (unsigned i = 0; i < 8 && i < p3_gen::RC_COUNT; ++i) rc.push_back(p3_gen::RC_CANON[i]);
    std::vector<std::array<std::array<std::uint64_t,4>,3>> mds;
    for (unsigned i = 0; i < 3; ++i) {
        std::array<std::array<std::uint64_t,4>,3> row;
        for (unsigned j = 0; j < 3; ++j) row[j] = p3_gen::MDS_CANON[i][j];
        mds.push_back(row);
    }
    const fp::fe iv_fe = fp::iv_of(dom::Dom::IV_STATE_NODE);
    const std::uint64_t iv[4] = {iv_fe.l[0], iv_fe.l[1], iv_fe.l[2], iv_fe.l[3]};
    bool all = true;

    {   // [G+] + [G-sem] + [G-dir]
        mfold::SparseMat A, B, C; std::vector<fp::fe> w;
        w.push_back(fp::fe_one());
        w.push_back(fp::fe_from_u64(100));
        w.push_back(fp::fe_from_u64(200));
        w.push_back(iv_fe);
        auto R = smtr1::build_smt_opening(A, B, C, w, 1, {2}, {1}, rc, mds, 1, 2, 1, iv);
        unsigned actual = 0;
        const bool sat = sat_check(A, B, C, w, &actual);
        std::printf("[G+] depth-1 dir=1: SAT %s | R.n_rows=%u actual=%u (DEF-194 stale=%s)\n",
                    sat?"YES":"NO", R.n_rows, actual, (R.n_rows!=actual)?"YES":"no");
        fp::fe m = reduced_perm(w[1], w[2], w[3], rc, mds);
        fp::fe g = fp::fe_to_canonical(w[R.output_var]);
        fp::fe mm = fp::fe_to_canonical(m);
        const bool sem = (g.l == mm.l);
        std::printf("[G-sem] mirror == gadget output: %s\n", sem?"YES":"NO");
        all = all && sat && sem && (R.n_rows != actual);

        mfold::SparseMat A2, B2, C2; std::vector<fp::fe> w2;
        w2.push_back(fp::fe_one()); w2.push_back(fp::fe_from_u64(100));
        w2.push_back(fp::fe_from_u64(200)); w2.push_back(iv_fe);
        auto R2 = smtr1::build_smt_opening(A2, B2, C2, w2, 1, {2}, {0}, rc, mds, 1, 2, 1, iv);
        unsigned a2 = 0; const bool sat2 = sat_check(A2, B2, C2, w2, &a2);
        fp::fe g2 = fp::fe_to_canonical(w2[R2.output_var]);
        const bool dead = (g.l == g2.l);
        std::printf("[G-dir] dir=0: SAT %s | root IDENTICAL to dir=1: %s (DEF-192 channel dead=%s)\n",
                    sat2?"YES":"NO", dead?"YES":"NO", dead?"CONFIRMED":"no");
        all = all && sat2 && dead;
    }
    {   // [G-any]
        mfold::SparseMat A, B, C; std::vector<fp::fe> w;
        w.push_back(fp::fe_one()); w.push_back(fp::fe_from_u64(101));
        w.push_back(fp::fe_from_u64(200)); w.push_back(iv_fe);
        auto R = smtr1::build_smt_opening(A, B, C, w, 1, {2}, {1}, rc, mds, 1, 2, 1, iv);
        unsigned actual = 0;
        const bool sat = sat_check(A, B, C, w, &actual);
        fp::fe m100 = reduced_perm(fp::fe_from_u64(100), fp::fe_from_u64(200), iv_fe, rc, mds);
        fp::fe g = fp::fe_to_canonical(w[R.output_var]);
        fp::fe mm = fp::fe_to_canonical(m100);
        const bool differs = !(g.l == mm.l);
        std::printf("[G-any] leaf=101: SAT %s | root differs from leaf=100: %s (DEF-193 any-leaf=%s)\n",
                    sat?"YES":"NO", differs?"YES":"no", sat?"CONFIRMED":"no");
        all = all && sat && differs;
    }
    {   // [G-coll]
        mfold::SparseMat A, B, C; std::vector<fp::fe> w;
        w.push_back(fp::fe_one()); w.push_back(fp::fe_from_u64(100));
        w.push_back(fp::fe_from_u64(200)); w.push_back(fp::fe_from_u64(300));
        auto R = smtr1::build_smt_opening(A, B, C, w, 1, {2,3}, {1,1}, rc, mds, 1, 2, 2, iv);
        unsigned actual = 0;
        const bool sat = sat_check(A, B, C, w, &actual);
        fp::fe l0 = reduced_perm(w[1], w[2], w[3], rc, mds);   // s2 = sib1 (overridden IV)
        fp::fe l1 = reduced_perm(l0, w[3], w[3], rc, mds);
        fp::fe g = fp::fe_to_canonical(w[R.output_var]);
        fp::fe mm = fp::fe_to_canonical(l1);
        const bool coll = (g.l == mm.l);
        std::printf("[G-coll] depth-2: SAT %s | rows=%u | output == mirror-with-IV-OVERRIDDEN-by-sib1: %s (DEF-195 collision=%s)\n",
                    sat?"YES":"NO", actual, coll?"YES":"NO", coll?"CONFIRMED":"no");
        all = all && sat && coll;
    }
    std::printf("\n[P1-20] %s\n", all ? "GREEN - artifact verified; 4 defects demonstrated" : "RED");
    return all ? 0 : 1;
}
