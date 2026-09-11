// HSMA :: epoch.hpp — the epoch pipeline driver (Step 17, DEC-210).
// Connects the M2 ordering (Step 12) to the fold (Steps 14-16):
// φ₂ ordering → φ₅-φ₆ fold execution → φ₇ NIVC close.
// The order_root feeds the fold's decree_root input — the M2→fold bridge.
// DEC-127; DEC-090.
#pragma once
#include <hsma/nivc.hpp>
#include <hsma/threshold/m2.hpp>
#include <hsma/fold.hpp>

namespace hsma::epoch {

// The epoch pipeline result
struct EpochResult {
    nivc::Accumulator acc;         // 41 bytes — the succinct proof carrier
    smt::Handle final_root;       // the SMT state root after processing
    fp::fe order_root;           // the M2 ordering root (MEV freeze)
    unsigned processed_count;     // entries actually folded
};

// The full pipeline: M2 ordering → fold → NIVC close
// order_root feeds the fold's decree_root — the M2→fold bridge.
inline EpochResult run(smt::Vault& vault, smt::Handle initial_root,
                      const fp::fe& prev_digest,
                      const std::uint8_t* beacon, // 32 bytes (real HSM_BEACON_V1)
                      const std::vector<fold::DecreeEntry>& entries,
                      const std::vector<threshold::g2::G2Pt>& Rs, // the KEM ciphertext points
                      const std::vector<std::vector<std::uint8_t>>& cts) {
    EpochResult result{};

    // φ₂: compute ct_hashes and sort_keys (the MEV freeze)
    std::vector<std::array<std::uint8_t, 32>> cths(Rs.size());
    std::vector<std::array<std::uint8_t, 32>> keys(Rs.size());
    for (std::size_t i = 0; i < Rs.size(); ++i) {
        std::uint8_t rs[192];
        threshold::m2::ser_g2(Rs[i], rs);
        threshold::m2::ct_hash(cths[i].data(), rs, cts[i].data(), cts[i].size());
        threshold::m2::sort_key(keys[i].data(), beacon, cths[i].data());
    }

    // sort by keys (byte-lex ascending)
    std::vector<unsigned> order(Rs.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = unsigned(i);
    for (std::size_t a = 0; a < order.size(); ++a)
        for (std::size_t b = a + 1; b < order.size(); ++b)
            if (std::memcmp(keys[order[b]].data(), keys[order[a]].data(), 32) < 0)
                { unsigned t = order[a]; order[a] = order[b]; order[b] = t; }

    // compute order_root
    std::uint8_t sorted_hashes[4][32];
    for (unsigned i = 0; i < 4; ++i)
        std::memcpy(sorted_hashes[i], cths[order[i]].data(), 32);
    std::uint8_t oroot[32];
    threshold::m2::order_root(oroot, sorted_hashes, 4);
    result.order_root = fp::fe_from_canonical_limbs(
        {*(const std::uint64_t*)oroot, *(const std::uint64_t*)(oroot+8),
         *(const std::uint64_t*)(oroot+16), *(const std::uint64_t*)(oroot+24)});

    // φ₅-φ₇: the fold processes the entries
    smt::Handle root = initial_root;
    nivc::fold_head(result.acc, prev_digest, result.order_root);
    for (const auto& e : entries) {
        nivc::fold_step(vault, result.acc, root, e);
    }
    result.processed_count = result.acc.count;
    nivc::fold_close(result.acc);
    result.final_root = root;

    return result;
}

} // namespace hsma::epoch
