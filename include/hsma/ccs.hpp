// HSMA :: ccs.hpp — the Phase-0 CCS constraint layer (Step 15, DEC-208).
// Named, machine-checkable constraints over the fold witness. The binding
// is a hash oracle (Poseidon input/output check); the nonce and LT gate
// are linear/range constraints. The PC matrix is enumerated and proven.
// Full CCS matrix representation lands with the folding (Step 16).
// DEC-127; DEC-090.
#pragma once
#include <hsma/fold.hpp>
#include <cstring>

namespace hsma::ccs {

// ── Constraint check functions ──

// binding: poseidon3(HSM_PT_v1, e1, e2) == pt_hash  (hash oracle)
inline bool check_binding(const fold::DecreeEntry& e) {
    const fp::fe computed = fold::pt_hash_of(e.amount, e.fee, e.nonce);
    const auto a = fp::fe_to_canonical(computed);
    const auto b = fp::fe_to_canonical(e.pt_hash);
    return a.l[0] == b.l[0] && a.l[1] == b.l[1] && a.l[2] == b.l[2] && a.l[3] == b.l[3];
}

// nonce: e.nonce == leaf_nonce + 1  (linear)
inline bool check_nonce(const fold::DecreeEntry& e, const smt::AccountState& s) {
    return e.nonce == s.nonce + 1;
}

// LT gate: bal >= amount + fee  (range — boundedness-proven by DEC-119)
inline bool check_lt(const fold::DecreeEntry& e, const smt::AccountState& s) {
    unsigned __int128 cost;
    if (__builtin_add_overflow(e.amount, e.fee, &cost)) return false;
    return !s.bal_sign && s.bal_mag >= cost;
}

// ── The PC matrix: {HEAD→EXEC, EXEC→EXEC, EXEC→CLOSE, HEAD→CLOSE} ──
// All other transitions are UNSATISFIABLE (whitepaper item 7, SAT-proof).
enum class Step : std::uint8_t { HEAD = 0, EXEC = 1, CLOSE = 2 };
inline constexpr unsigned PC_MATRIX[3][3] = {
    // to: HEAD  EXEC  CLOSE     from:
    {  0,     1,     1  },   // HEAD  (→EXEC ✓, →CLOSE ✓ for empty epoch)
    {  0,     1,     1  },   // EXEC  (→EXEC ✓, →CLOSE ✓)
    {  0,     0,     0  },   // CLOSE (terminal — nothing follows)
};
inline constexpr unsigned PC_VALID_COUNT = 4;
inline constexpr unsigned PC_INVALID_COUNT = 5;

inline bool pc_valid(Step from, Step to) {
    return PC_MATRIX[static_cast<unsigned>(from)][static_cast<unsigned>(to)] != 0;
}

// ── The constraint trace (per entry) ──
struct EntryConstraints {
    unsigned entry_index;
    unsigned count;           // number of constraints that fired
    bool all_satisfied;
};

// Evaluate all constraints for one entry (given the PRE-state)
inline EntryConstraints evaluate(const fold::DecreeEntry& e,
                                const smt::AccountState& sender) {
    EntryConstraints r{0, 0, true};
    if (e.status == fold::Status::PAD) {
        r.count = 1;  // pad_selector
        return r;
    }
    if (!check_binding(e)) { r.all_satisfied = false; r.count = 1; return r; }
    r.count = 1;
    if (!check_nonce(e, sender)) { r.all_satisfied = false; r.count = 2; return r; }
    r.count = 2;
    if (e.status == fold::Status::EXEC) {
        r.count = 3;
        if (!check_lt(e, sender)) { r.all_satisfied = false; return r; }
        r.count = 5;  // + debit + credit
    } else if (e.status == fold::Status::SKIP_USER) {
        r.count = 3;  // binding + nonce + skip_burn (LT gate = trigger, not violation)
    }
    return r;
}

} // namespace hsma::ccs
