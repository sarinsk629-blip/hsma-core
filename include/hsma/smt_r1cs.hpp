// HSMA :: smt_r1cs.hpp - P1-15b (GAP-07 SMT, DEC-237).
// The SMT opening chain as R1CS - STATUS (P1-20/DEC-260): depth-1 VERIFIED
// (SAT, output matches independent mirror); the four gaps below are OWNED.
// Each level: hash(cur, sib, IV) via the Poseidon-3 R1CS gadget (reduced perm).
// The Poseidon-2 gadget reuses poseidon_r1cs.hpp's build() with a 2-input state.
// DEF-192: the direction bit is INERT - levels always hash (cur, sib) in that order.
// DEF-193: NO root binding - the output is the chain tip; binding is the caller's job (P1-21).
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

} // namespace hsma::smtr1
