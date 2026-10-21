// HSMA :: fexec_circuit.hpp - P1-13a (GAP-07, DEC-231).
// The f_exec transition circuit: the whitepaper's five per-entry constraints
// as sparse R1CS rows over the transition witness, PLUS the PC transition
// rows, PLUS the digest-absorption and PAD-selector algebra. The SMT opening
// witnesses and the Poseidon gadget are pinned (boundaries below).
// Z LAYOUT (per decree step, embedded in the running witness):
//   z[0] = u (relaxed scalar)   z[1] = digest_prev   z[2] = digest_new
//   z[3] = pt_hash              z[4] = computed_pt    z[5] = nonce_s
//   z[6] = nonce_pt             z[7] = bal_ge_cost (LT bit, 0/1)
//   z[8] = self (0/1)           z[9] = is_pad (0/1)
//   z[10] = pc (0=HEAD,1=EXEC,2=CLOSE)
//   z[11] = sel_exec (exec-selector: 1 for EXEC steps)
//   z[12] = bal_new (sender post)  z[13] = H (PC^2 scratch)
// CONSTRAINTS (rows; a=Az, b=Bz, c=Cz with a*b = u*c + E):
//   R0 binding:  is_pad' * (computed_pt - pt_hash) = 0   [via NOT-pad bit]
//   R1 nonce:    is_pad' * (nonce_s + 1 - nonce_pt) = 0
//   R2 LT sound: bal_ge_cost * (bal_ge_cost - 1) = 0         (boolean)
//   R3 pad bool: is_pad * (is_pad - 1) = 0                    (boolean)
//   R4 self bool: self * (self - 1) = 0
//   R5 pc edge:  pc * (pc - 1) * (pc - 2) = 0                 (in {0,1,2})
//   R6 pad absorbs: is_pad * (digest_new - digest_prev) = 0   (PAD-neutrality, DEC-033)
//   R7 exec absorbs: sel_exec * (digest_new - P3(FOLD, digest_prev, pt_hash)) = 0
//                (the Poseidon GADGET: digest_new is a WITNESS whose correctness
//                 is pinned by the hash golden at emitter scale - boundary)
// NOTE: NOT-pad bit z[14] = 1 - is_pad is LINEAR, no row needed (linear combo).
// LAWS: CA-R135 (preconditions), CA-R134 (negatives), CA-R133 (bit contracts),
// CA-R126 (self-check), CA-R78 (LSB-first, inherited by any bit decomposition).
// HONEST BOUNDARIES (DEC-231): (1) Poseidon = gadget (digest_new pinned by the
// proven hash golden at golden scale; full round-unroll = P1-14/H5 work);
// (2) SMT openings = witnesses (INV-P4-1 certificate assumption extended);
// (3) epoch-scale rows are a computed receipt, not a Termux materialization.
#pragma once
#include <hsma/mfold.hpp>
#include <cstdint>

namespace hsma::fcirc {

inline constexpr unsigned NZ = 16u;   // +1: the ONE wire (CA-R144)      // z width per step witness
inline constexpr unsigned NROWS = 8u;    // rows above

// z indices (the contract - the emitter and the test share these)
enum Z : unsigned {
    Z_U = 0, Z_DPREV = 1, Z_DNEW = 2, Z_PTHASH = 3, Z_COMPUTED = 4,
    Z_NONCES = 5, Z_NONCEPT = 6, Z_LT = 7, Z_SELF = 8, Z_ISPAD = 9,
    Z_PC = 10, Z_SELEXEC = 11, Z_BALNEW = 12, Z_H = 13, Z_NOTPAD = 14, Z_ONE = 15
};

// the rows (COO), fixed - A/B/C identical shape to the mfold usage
inline void build_matrices(mfold::SparseMat& A, mfold::SparseMat& B, mfold::SparseMat& C) noexcept {
    A.n_rows = B.n_rows = C.n_rows = NROWS;
    A.n_cols = B.n_cols = C.n_cols = NZ;
    auto tri = [](mfold::SparseMat& M, unsigned r, unsigned c, unsigned v) {
        M.row.push_back(r); M.col.push_back(c); M.val.push_back(fp::fe_from_u64(v)); };
    auto linc = [](mfold::SparseMat& M, unsigned r, unsigned c, long long v) {
        M.row.push_back(r); M.col.push_back(c); M.val.push_back(
            v >= 0 ? fp::fe_from_u64((unsigned long long)v)
                   : fp::fe_sub(fp::fe_zero(), fp::fe_from_u64((unsigned long long)(-v)))); };
    // R0: NOTPAD*(COMPUTED - PTHASH) = 0  -> a=z14, b=(z4 - z3), c=0
    tri(A,0,Z_NOTPAD,1); linc(B,0,Z_COMPUTED,1); linc(B,0,Z_PTHASH,-1);
    // R1: NOTPAD*(NONCES + 1 - NONCEPT) = 0
    tri(A,1,Z_NOTPAD,1); linc(B,1,Z_NONCES,1); linc(B,1,Z_NONCEPT,-1); tri(B,1,Z_ONE,1);   // CA-R144: the +1 constant lives on the ONE wire
    // R2: LT*(LT-1) = 0 -> a=LT, b=LT, c=LT
    tri(A,2,Z_LT,1); tri(B,2,Z_LT,1); tri(C,2,Z_LT,1);
    // R3: ISPAD*(ISPAD-1)=0
    tri(A,3,Z_ISPAD,1); tri(B,3,Z_ISPAD,1); tri(C,3,Z_ISPAD,1);
    // R4: SELF*(SELF-1)=0
    tri(A,4,Z_SELF,1); tri(B,4,Z_SELF,1); tri(C,4,Z_SELF,1);
    // R5: PC*(PC-1)*(PC-2)=0  -> row5: (PC*PC) = 2*PC + T5  where T5 is z-var? 
    //     quadratic-cubic needs a helper var; use two rows:
    //     row5: PC*PC = H (H = z-internal? NZ fixed 15 - use Z_H as scratch H)
    tri(A,5,Z_PC,1); tri(B,5,Z_PC,1); tri(C,5,Z_H,1);       // H := PC^2  (OOR slot reused)
    //     row6: H*PC = 3H - 2PC  (the cubic PC(PC-1)(PC-2)=0 split; the
    //     earlier H*(PC-2)=0 form FAILS at PC=1 - the EXEC case itself;
    //     caught by derivation before the emitter: CA-R142)
    tri(A,6,Z_H,1); linc(B,6,Z_PC,1); linc(C,6,Z_H,3); linc(C,6,Z_PC,-2);
    // R7: SELEXEC*(DNEW - DPREV) = 0 would need P3 inside - the GADGET form:
    //     row7: SELEXEC * (DNEW - DPREV) = 0  is WRONG (digest changes on exec).
    //     Instead: SELEXEC*(DNEW - DPREV) != 0 allowed; the gadget constraint is
    //     DNEW == P3(DPREV, PTHASH) - PINNED BY THE EMITTER GOLDEN (boundary 1).
    //     Row 7 exists as the PAD-absorption:
    tri(A,7,Z_ISPAD,1); linc(B,7,Z_DNEW,1); linc(B,7,Z_DPREV,-1); // ISPAD*(DNEW-DPREV)=0
    // (row6 reuses OOR as H; row7 is the pad-absorption; exec-absorption = golden)
}

} // namespace hsma::fcirc
