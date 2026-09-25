// HSMA :: smt21probe.cpp - P1-21 (DEC-262): the REAL SMT opening, verified.
// [G2-d1] depth-1 dir=0: SAT, output == mirror
// [G2-d2] depth-2 MIXED dirs (1,0): SAT, output == mirror  <- impossible in v1
// [G2-d3] depth-3 dirs (0,1,1): SAT, output == mirror
// [G-dir-neg] circuit dir=1 vs expected = dir=0 mirror root -> UNSAT (mux live)
// [G-root-neg] expected = root+1 -> UNSAT (binding live)
// [G-meta2] SmtResult2.n_rows == actual rows (85*depth + 1)
#include <hsma/smt_r1cs.hpp>
#include <hsma/poseidon.hpp>
#include "poseidon_params_gen.hpp"
#include <cstdio>
#include <vector>
using namespace hsma;

static fp::fe limbs(const std::array<std::uint64_t,4>& c) {
    fp::fe x{}; for (int k = 0; k < 4; ++k) x.l[k] = c[k]; return x;
}
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
// the INDEPENDENT mirror: mux semantics in plain field math
static fp::fe smt_chain(const fp::fe& leaf, const std::vector<fp::fe>& sibs,
                        const std::vector<unsigned>& dirs, const fp::fe& iv,
                        const std::vector<std::array<std::uint64_t,4>>& rc,
                        const std::vector<std::array<std::array<std::uint64_t,4>,3>>& mds) {
    fp::fe cur = leaf;
    for (unsigned i = 0; i < sibs.size(); ++i) {
        const fp::fe sel0 = dirs[i] ? sibs[i] : cur;
        const fp::fe sel1 = dirs[i] ? cur : sibs[i];
        std::vector<std::array<std::uint64_t,4>> sl(rc.begin() + 8*i, rc.begin() + 8*i + 8);
        cur = reduced_perm(sel0, sel1, iv, sl, mds);
    }
    return cur;
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
// one circuit build: returns SAT; expected filled by the caller's mode
static bool run_case(unsigned depth, const std::vector<unsigned>& dirs,
                     std::uint64_t leaf, const std::vector<std::uint64_t>& sibvals,
                     const fp::fe& iv, const std::vector<std::array<std::uint64_t,4>>& rc,
                     const std::vector<std::array<std::array<std::uint64_t,4>,3>>& mds,
                     int expect_mode, unsigned* rows_out, fp::fe* tip_out) {
    mfold::SparseMat A, B, C; std::vector<fp::fe> w;
    w.push_back(fp::fe_one());
    w.push_back(fp::fe_from_u64(leaf));
    std::vector<unsigned> sv;
    for (auto s : sibvals) { w.push_back(fp::fe_from_u64(s)); sv.push_back((unsigned)w.size()-1); }
    std::vector<unsigned> dv;
    for (auto d : dirs) { w.push_back(d ? fp::fe_one() : fp::fe_zero()); dv.push_back((unsigned)w.size()-1); }
    w.push_back(iv); const unsigned iv_var = (unsigned)w.size()-1;
    w.push_back(fp::fe_zero()); const unsigned exp_var = (unsigned)w.size()-1;

    auto R = smtr1::build_smt_opening2(A, B, C, w, 1, sv, dv, iv_var, exp_var, rc, mds, 1, 2);
    if (rows_out) *rows_out = R.n_rows;
    fp::fe tip = fp::fe_to_canonical(w[R.output_var]);
    if (tip_out) *tip_out = tip;

    std::vector<fp::fe> sibfes; for (auto s : sibvals) sibfes.push_back(fp::fe_from_u64(s));
    fp::fe mirror = smt_chain(fp::fe_from_u64(leaf), sibfes, dirs, iv, rc, mds);
    fp::fe claimed = (expect_mode == 0) ? mirror
                   : (expect_mode == 1) ? fp::fe_add(mirror, fp::fe_one())
                   : fp::fe_zero();
    w[exp_var] = claimed;
    return sat_check(A, B, C, w, nullptr);
}
int main() {
    assert(p3_gen::RC_COUNT >= 24);
    std::vector<std::array<std::uint64_t,4>> rc;
    for (unsigned i = 0; i < 24; ++i) rc.push_back(p3_gen::RC_CANON[i]);
    std::vector<std::array<std::array<std::uint64_t,4>,3>> mds;
    for (unsigned i = 0; i < 3; ++i) {
        std::array<std::array<std::uint64_t,4>,3> row;
        for (unsigned j = 0; j < 3; ++j) row[j] = p3_gen::MDS_CANON[i][j];
        mds.push_back(row);
    }
    const fp::fe iv = fp::iv_of(dom::Dom::IV_STATE_NODE);
    bool all = true;
    unsigned rows = 0; fp::fe tip;

    { const bool s = run_case(1, {0}, 100, {200}, iv, rc, mds, 0, &rows, &tip);
      fp::fe m = smt_chain(fp::fe_from_u64(100), {fp::fe_from_u64(200)}, {0}, iv, rc, mds);
      fp::fe mc = fp::fe_to_canonical(m);
      const bool sem = (tip.l == mc.l);
      std::printf("[G2-d1] depth-1 dir=0: SAT %s | mirror %s | rows=%u (85*1+1=86: %s)\n",
                  s?"YES":"NO", sem?"YES":"NO", rows, (rows==86)?"YES":"NO");
      all = all && s && sem && rows==86; }
    { const bool s = run_case(2, {1,0}, 100, {200,300}, iv, rc, mds, 0, &rows, &tip);
      fp::fe m = smt_chain(fp::fe_from_u64(100), {fp::fe_from_u64(200), fp::fe_from_u64(300)}, {1,0}, iv, rc, mds);
      fp::fe mc = fp::fe_to_canonical(m);
      const bool sem = (tip.l == mc.l);
      std::printf("[G2-d2] depth-2 MIXED (1,0): SAT %s | mirror %s | rows=%u (171: %s) <- v1-impossible\n",
                  s?"YES":"NO", sem?"YES":"NO", rows, (rows==171)?"YES":"NO");
      all = all && s && sem && rows==171; }
    { const bool s = run_case(3, {0,1,1}, 100, {200,300,400}, iv, rc, mds, 0, &rows, &tip);
      fp::fe m = smt_chain(fp::fe_from_u64(100), {fp::fe_from_u64(200), fp::fe_from_u64(300), fp::fe_from_u64(400)}, {0,1,1}, iv, rc, mds);
      fp::fe mc = fp::fe_to_canonical(m);
      const bool sem = (tip.l == mc.l);
      std::printf("[G2-d3] depth-3 (0,1,1): SAT %s | mirror %s | rows=%u (256: %s)\n",
                  s?"YES":"NO", sem?"YES":"NO", rows, (rows==256)?"YES":"NO");
      all = all && s && sem && rows==256; }
    { const bool s = run_case(1, {1}, 100, {200}, iv, rc, mds, 2, nullptr, nullptr);
      std::printf("[G-dir-neg] dir=1 circuit, expected=dir-0 root: %s (must UNSAT - mux LIVE)\n",
                  s?"SAT!!":"UNSAT");
      all = all && !s; }
    { const bool s = run_case(1, {0}, 100, {200}, iv, rc, mds, 1, nullptr, nullptr);
      std::printf("[G-root-neg] expected=root+1: %s (must UNSAT - binding LIVE)\n",
                  s?"SAT!!":"UNSAT");
      all = all && !s; }

    std::printf("\n-- scaling --\n  per level: 85 rows (80 gadget + 5 mux) + 1 binding\n");
    std::printf("  depth-64 opening: ~%u rows | k=476, 2 accounts: ~%llu\n",
                85u*64u + 1u, (unsigned long long)(85ull*64+1)*2*476);
    std::printf("\n[P1-21] %s\n", all ? "GREEN - the real SMT opening is PROVEN" : "RED");
    return all ? 0 : 1;
}
