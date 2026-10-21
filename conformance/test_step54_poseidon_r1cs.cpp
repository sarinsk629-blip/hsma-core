// HSMA :: test_step54 - Phase 6.17 v2 s3: the Poseidon R1CS semantic bridge
// (DEF-375) — the test that did not exist when it mattered.
//
// History: pr1cs::build was always "R1CS SAT: YES", but SAT alone is
// representation-blind — the witness is computed by the same helpers that
// emit the rows, so a domain-mangled gadget (the old mk_fe stored canonical
// constants RAW into a Montgomery witness system) satisfies its own rows
// while computing a DIFFERENT function than fp::poseidon3. No golden ever
// crossed the gadget<->perm boundary. This test IS that boundary:
//
//   P1 rows    : full parameters (rf_half=4, rp=56) emit EXACTLY 1088 rows
//                (8 full rounds x 24 + 56 partial rounds x 16)
//   P2 SAT     : every one of the 1088 rows holds on the computed witness
//   P3 BRIDGE  : gadget output == fp::poseidon3(dom, l, r) — Montgomery-exact,
//                same {l, r, IV} lane layout, same RC consumption order
//   P4 sound   : perturbing ONE intermediate witness value breaks SAT
//                (the system genuinely constrains the permutation, it is not
//                a rubber stamp)
//   P5 inputs  : the bridge holds for multiple domains and non-trivial inputs
//                (domain separation enters the R1CS through the IV witness —
//                the constants stay domain-free)
#include <hsma/poseidon_r1cs.hpp>
#include <hsma/poseidon.hpp>
#include "poseidon_params_gen.hpp"
#include "pallas_params_gen.hpp"
#include <cstdio>
#include <vector>
using namespace hsma;

static bool sat_check(const mfold::SparseMat& A, const mfold::SparseMat& B,
                      const mfold::SparseMat& C, const std::vector<fp::fe>& w) {
    const unsigned n = (unsigned)A.row.size();
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

// one full build + bridge check; returns the gadget output witness
static fp::fe bridge(std::uint64_t l, std::uint64_t r, dom::Dom d, bool* sat_out,
                     unsigned* rows_out) {
    std::vector<std::array<std::uint64_t, 4>> rc;
    for (unsigned i = 0; i < p3_gen::RC_COUNT; ++i) rc.push_back(p3_gen::RC_CANON[i]);
    std::vector<std::array<std::array<std::uint64_t, 4>, 3>> mds;
    for (unsigned i = 0; i < 3; ++i) {
        std::array<std::array<std::uint64_t, 4>, 3> row;
        for (unsigned j = 0; j < 3; ++j) row[j] = p3_gen::MDS_CANON[i][j];
        mds.push_back(row);
    }
    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    w.push_back(fp::fe_one());                       // z[0] = ONE (Montgomery 1)
    w.push_back(fp::fe_from_u64(l));                 // z[1] = s0
    w.push_back(fp::fe_from_u64(r));                 // z[2] = s1
    w.push_back(fp::iv_of(d));                       // z[3] = s2 = the domain IV
    auto G = pr1cs::build(A, B, C, w, 1, 2, 3, rc, mds, p3_gen::RF / 2, p3_gen::RP);
    *rows_out = G.n_rows;
    *sat_out = sat_check(A, B, C, w);
    return w[G.output_var];
}

int main() {
    int fails = 0;
    auto chk = [&](bool ok, const char* what) {
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
        if (!ok) ++fails;
    };

    // P1+P2+P3: the full bridge at the production domain
    {
        bool sat = false; unsigned rows = 0;
        fp::fe got = bridge(1, 2, dom::Dom::IV_STATE_NODE, &sat, &rows);
        chk(rows == 1088u, "P1 full R1CS emits EXACTLY 1088 rows (8x24 + 56x16)");
        chk(sat, "P2 all 1088 rows SAT on the computed witness");
        fp::fe want = fp::poseidon3(dom::Dom::IV_STATE_NODE, fp::fe_from_u64(1), fp::fe_from_u64(2));
        chk(got.l == want.l, "P3 BRIDGE: gadget output == fp::poseidon3 (Montgomery-exact)");
    }

    // P4: the system genuinely constrains — perturb ONE sbox intermediate
    {
        std::vector<std::array<std::uint64_t, 4>> rc;
        for (unsigned i = 0; i < p3_gen::RC_COUNT; ++i) rc.push_back(p3_gen::RC_CANON[i]);
        std::vector<std::array<std::array<std::uint64_t, 4>, 3>> mds;
        for (unsigned i = 0; i < 3; ++i) {
            std::array<std::array<std::uint64_t, 4>, 3> row;
            for (unsigned j = 0; j < 3; ++j) row[j] = p3_gen::MDS_CANON[i][j];
            mds.push_back(row);
        }
        mfold::SparseMat A, B, C;
        std::vector<fp::fe> w;
        w.push_back(fp::fe_one());
        w.push_back(fp::fe_from_u64(1));
        w.push_back(fp::fe_from_u64(2));
        w.push_back(fp::iv_of(dom::Dom::IV_STATE_NODE));
        auto G = pr1cs::build(A, B, C, w, 1, 2, 3, rc, mds, p3_gen::RF / 2, p3_gen::RP);
        // the first full-round lane-0 ARK output sits at w[5] (w[4] is its RC
        // constant): perturbing it must break BOTH its linear row and every
        // downstream sbox row that consumes it
        w[5] = fp::fe_add(w[5], fp::fe_one());   // tamper the ARK output
        chk(!sat_check(A, B, C, w), "P4 perturbed ARK witness -> SAT BROKEN (system is sound)");
    }

    // P5: the bridge holds across domains (domain separation rides the IV witness)
    {
        bool ok = true;
        const dom::Dom doms[] = {dom::Dom::IV_STATE_LEAF, dom::Dom::IV_DECREE,
                                 dom::Dom::IV_STATE_NODE};
        for (dom::Dom d : doms) {
            bool sat = false; unsigned rows = 0;
            fp::fe got = bridge(77, 913, d, &sat, &rows);
            fp::fe want = fp::poseidon3(d, fp::fe_from_u64(77), fp::fe_from_u64(913));
            ok = ok && sat && (rows == 1088u) && (got.l == want.l);
        }
        chk(ok, "P5 bridge holds across 3 domains, non-trivial inputs");
    }

    std::printf(fails ? "step54: %d FAIL\n" : "step54: ALL PASS (%d fails)\n", fails);
    return fails ? 1 : 0;
}
