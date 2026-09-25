// HSMA :: smt_r1cs.hpp - P1-15b (GAP-07 SMT, DEC-237).
// The SMT opening chain as R1CS - STATUS (P1-20/DEC-260): depth-1 VERIFIED
// (SAT, output matches independent mirror); the four gaps below are OWNED.
// Each level: hash(cur, sib, IV) via the Poseidon-3 R1CS gadget (reduced perm).
// The Poseidon-2 gadget reuses poseidon_r1cs.hpp's build() with a 2-input state.
// DEF-192: FIXED in v2 - boolean-constrained direction mux (5 rows/level); v1 inert.
// DEF-193: FIXED in v2 (build_smt_opening2, P1-21) - in-circuit binding row; v1 remains depth-1 legacy.
// DEF-194: sketch metadata - iv param used only in an always-3 ternary; n_rows stale.
// DEF-195: depth>=2 BROKEN - s2_var=3 collides with sibling lane z[3]; depth-1 only.
// HONEST BOUNDARY: depth parameterized (golden depth-1 verified; 64 = P1-21).
// The full 64-depth unroll = 64 * ~363 = ~23,232 constraints per opening.
// At k=476 entries * 2 accounts: ~22M constraints (production hardware needed).
#pragma once
#include <hsma/poseidon_r1cs.hpp>
#include <cstdint>

namespace hsma::smtr1 {

using pr1cs::SparseMat;
using pr1cs::Result;

// build the SMT opening circuit: verify that hashing the leaf with the
// siblings bottom-up produces the expected root.
// 
// witness layout:
//   z[0] = ONE wire
//   z[1] = leaf_hash (the account leaf being opened)
//   z[2..2+depth] = sibling hashes (one per level)
//   z[...] = intermediate hashes (computed by the Poseidon gadgets)
//   z[last] = the computed root (must match the expected root)
//
// direction_bits: for each level, 0 = sibling is LEFT, 1 = sibling is RIGHT
//   left:  parent = Poseidon(sib, cur)  — sibling first
//   right: parent = Poseidon(cur, sib)  — current first
//
// the expected_root is the FINAL constraint: computed_root == expected_root
inline Result build_smt_opening(
    SparseMat& A, SparseMat& B, SparseMat& C,
    std::vector<fp::fe>& w,
    unsigned leaf_var,
    const std::vector<unsigned>& sibling_vars,
    const std::vector<unsigned>& direction_vars,  // 0 or 1 per level
    const std::vector<std::array<std::uint64_t,4>>& rc,
    const std::vector<std::array<std::array<std::uint64_t,4>,3>>& mds,
    unsigned rf_half, unsigned rp,
    unsigned depth,
    const std::uint64_t iv[4]
) noexcept {
    unsigned row = (unsigned)A.row.size();
    Result R;
    
    // the current hash starts at the leaf
    unsigned cur = leaf_var;
    
    for (unsigned level = 0; level < depth; ++level) {
        unsigned sib = sibling_vars[level];
        unsigned dir = direction_vars[level];
        
        // Poseidon-2: hash(cur, sib) or hash(sib, cur) depending on direction
        // For simplicity, always call with (cur, sib) and use the direction
        // as a selector: the final output is checked against the expected root
        // (the direction bit selects which ordering produces the correct root)
        
        // for the golden scale, use the simplified approach:
        // parent = Poseidon(cur, sib) regardless of direction
        // (the direction affects which sibling is provided, not the ordering)
        
        auto G = pr1cs::build(A, B, C, w, cur, sib, iv[0] != 0 ? 3 : 3, rc, mds, rf_half, rp);
        // NOTE: s2 (the third input) is the IV — for the probe, use a fixed value
        
        cur = G.output_var;
    }
    
    // the final constraint: computed_root == expected_root
    // This is a linear constraint: computed_root - expected_root = 0
    // expressed as: (computed_root - expected_root) * ONE = 0
    // But we don't know expected_root as a variable — the CALLER provides it.
    // For now, the root is the OUTPUT of the last Poseidon gadget.
    // The caller checks it against the expected root outside the circuit.
    
    R.output_var = cur;
    R.n_rows = row;
    R.n_vars = (unsigned)w.size();
    return R;
}


// ---- P1-21 (DEC-262): the REAL SMT opening ------------------------------
// Repairs, in-circuit: DEF-192 (direction mux: dir=1 -> sibling-first,
// dir=0 -> current-first; boolean-constrained), DEF-193 (root binding:
// w[expected] = w[chain_tip] as a constraint), DEF-195 (explicit iv_var,
// no lane collision - any depth), DEF-194 (n_rows = ACTUAL appended rows).
// Caller layout: z[0]=ONE, leaf, siblings[depth], dirs[depth] (0/1
// witness values), IV var, expected_root var (caller-allocated; its
// witness value may be set AFTER the call - SAT is checked last).
struct SmtResult2 {
    unsigned n_rows{};     // actual appended rows
    unsigned n_vars{};
    unsigned output_var{};
};

inline SmtResult2 build_smt_opening2(
    mfold::SparseMat& A, mfold::SparseMat& B, mfold::SparseMat& C,
    std::vector<fp::fe>& w,
    unsigned leaf_var,
    const std::vector<unsigned>& sibling_vars,
    const std::vector<unsigned>& direction_vars,
    unsigned iv_var,
    unsigned expected_root_var,
    const std::vector<std::array<std::uint64_t,4>>& rc,
    const std::vector<std::array<std::array<std::uint64_t,4>,3>>& mds,
    unsigned rf_half, unsigned rp
) noexcept {
    SmtResult2 R;
    const unsigned depth = (unsigned)sibling_vars.size();
    const fp::fe ONE = fp::fe_one();
    const fp::fe NEG = fp::fe_sub(fp::fe_zero(), fp::fe_one());
    auto prow = [&](unsigned a, unsigned b, unsigned c) {
        const unsigned row = (unsigned)A.row.size();
        A.row.push_back(row); A.col.push_back(a); A.val.push_back(ONE);
        B.row.push_back(row); B.col.push_back(b); B.val.push_back(ONE);
        C.row.push_back(row); C.col.push_back(c); C.val.push_back(ONE);
    };
    auto lrow = [&](unsigned out, const std::vector<std::pair<unsigned, fp::fe>>& terms) {
        const unsigned row = (unsigned)A.row.size();
        A.row.push_back(row); A.col.push_back(out); A.val.push_back(ONE);
        B.row.push_back(row); B.col.push_back(0);   B.val.push_back(ONE);
        for (const auto& [v, co] : terms) {
            C.row.push_back(row); C.col.push_back(v); C.val.push_back(co);
        }
    };

    unsigned cur = leaf_var;
    const unsigned rc_per_level = rf_half * 3 + rp + rf_half * 3;

    for (unsigned level = 0; level < depth; ++level) {
        const unsigned dir = direction_vars[level];
        const unsigned sib = sibling_vars[level];
        // boolean: w[dir]^2 = w[dir]
        prow(dir, dir, dir);
        // t = dir*sib ; u = dir*cur
        const unsigned t = (unsigned)w.size();
        w.push_back(fp::fe_mul(w[dir], w[sib]));
        prow(dir, sib, t);
        const unsigned u = (unsigned)w.size();
        w.push_back(fp::fe_mul(w[dir], w[cur]));
        prow(dir, cur, u);
        // sel0 = t - u + cur ; sel1 = u - t + sib
        const unsigned sel0 = (unsigned)w.size();
        w.push_back(fp::fe_add(fp::fe_sub(w[t], w[u]), w[cur]));
        lrow(sel0, {{t, ONE}, {u, NEG}, {cur, ONE}});
        const unsigned sel1 = (unsigned)w.size();
        w.push_back(fp::fe_add(fp::fe_sub(w[u], w[t]), w[sib]));
        lrow(sel1, {{u, ONE}, {t, NEG}, {sib, ONE}});
        // the level hash at the SELECTED order
        std::vector<std::array<std::uint64_t,4>> rcs(
            rc.begin() + level * rc_per_level,
            rc.begin() + (level + 1) * rc_per_level);
        auto G = pr1cs::build(A, B, C, w, sel0, sel1, iv_var, rcs, mds, rf_half, rp);
        cur = G.output_var;
    }

    // root binding: w[expected] = w[chain_tip]
    lrow(expected_root_var, {{cur, ONE}});

    R.output_var = cur;
    R.n_rows = (unsigned)A.row.size();
    R.n_vars = (unsigned)w.size();
    return R;
}

} // namespace hsma::smtr1
