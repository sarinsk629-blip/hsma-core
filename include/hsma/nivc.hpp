// HSMA :: nivc.hpp — the NIVC fold accumulator (Step 16, DEC-209).
// A bounded-size proof carrier: {digest(32B) + count(8B) + pc(1B)} = 41 bytes,
// CONSTANT regardless of entry count. This is the succinctness mechanism:
// π_E's representation is O(1) in the number of folded entries.
// The fold machinery (Step 14) and constraints (Step 15) are delegated to.
// DEC-127; DEC-090.
#pragma once
#include <hsma/fold.hpp>
#include <hsma/ccs.hpp>

namespace hsma::nivc {

// The accumulator: 41 bytes, never grows
struct Accumulator {
    fp::fe digest;               // 32 bytes (4 limbs × 8)
    std::uint64_t count;         // 8 bytes
    std::uint8_t pc;             // 1 byte (0=HEAD, 1=EXEC, 2=CLOSE)
};

inline constexpr std::size_t ACC_SIZE = 41;  // sizeof(Accumulator) equivalent

// The NIVC fold step: absorbs an entry, updates the bounded accumulator
inline fold::Verdict fold_step(smt::Vault& vault, Accumulator& acc,
                               smt::Handle& root, const fold::DecreeEntry& e) {
    fold::FoldState fs{root, acc.digest};
    const auto v = fold::f_exec(vault, fs, e);
    root = fs.state_root;
    acc.digest = fs.digest;
    if (v == fold::Verdict::OK_EXEC || v == fold::Verdict::OK_SKIP) {
        acc.count++;
    }
    return v;
}

// The NIVC head: absorbs prev_digest + decree_root
inline void fold_head(Accumulator& acc, const fp::fe& prev, const fp::fe& droot) {
    acc.digest = fold::f_head(prev, droot);
    acc.count = 0;
    acc.pc = 1;  // EXEC (ready to process entries)
}

// The NIVC close: seals the epoch, transitions PC to CLOSE
inline void fold_close(Accumulator& acc) {
    acc.digest = fold::f_close(acc.digest, acc.count);
    acc.pc = 2;  // CLOSE
}

} // namespace hsma::nivc
