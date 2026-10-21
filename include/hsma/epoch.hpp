// HSMA :: epoch.hpp — the epoch pipeline driver (Step 17, DEC-210).
// Connects the M2 ordering (Step 12) to the fold (Steps 14-16):
// φ₂ ordering → φ₅-φ₆ fold execution → φ₇ NIVC close.
// The order_root feeds the fold's decree_root input — the M2→fold bridge.
// DEC-127; DEC-090.
#pragma once
#include <algorithm>
#include <cstdio>
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

    // sort by keys (byte-lex ascending). DEF-389: std::sort — the O(n^2)
    // exchange sort was the ceremony's second-oldest constant-cost relic.
    std::vector<unsigned> order(Rs.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = unsigned(i);
    std::sort(order.begin(), order.end(), [&](unsigned a, unsigned b) {
        return std::memcmp(keys[a].data(), keys[b].data(), 32) < 0;
    });

    // compute order_root — over ALL envelopes. DEF-389: the old code copied
    // exactly 4 cths into a fixed [4][32] and committed the root of the FIRST
    // FOUR: fewer than 4 envelopes read out of bounds (UB), more than 4 let
    // the tail be reordered WITHOUT changing the order root — the MEV freeze
    // did not bind the full order at production volume. The commitment is
    // size-exact: allocation, fill, and hash share ONE size expression.
    std::vector<std::array<std::uint8_t, 32>> sorted(Rs.size());
    for (std::size_t i = 0; i < sorted.size(); ++i)
        std::memcpy(sorted[i].data(), cths[order[i]].data(), 32);
    std::uint8_t oroot[32];
    threshold::m2::order_root(oroot,
        reinterpret_cast<const std::uint8_t (*)[32]>(sorted.data()), sorted.size());
    // DEF-399: the root is an arbitrary 256-bit hash; pallas p is ~2^254.18,
    // so a raw limb load is NON-canonical ~65% of the time — and the SOS
    // Montgomery kernel's operand law (a, b < p) makes that load corrupt the
    // value (a reduction carry escapes T[7]). The field element of the root
    // is its canonical REDUCTION: c mod p (at most 3 conditional subtractions),
    // then the standard RR-lift. Same law whir.hpp's digest_scalar already
    // runs for the same reason; the order freeze now runs it too.
    std::array<std::uint64_t, 4> rl{};
    for (int k = 0; k < 4; ++k)
        for (int b = 0; b < 8; ++b)
            rl[k] |= std::uint64_t(oroot[k*8 + b]) << (8*b);
    {   fp::fe raw{{{rl[0], rl[1], rl[2], rl[3]}}};
        for (int t = 0; t < 8 && !fp::is_canonical(raw); ++t)
            fp::sub_assumed(raw.l.data(), raw.l.data(), fp::MOD.data());
        for (int k = 0; k < 4; ++k) rl[k] = raw.l[k];
    }
    result.order_root = fp::fe_from_canonical_limbs(rl);
    {   std::fprintf(stderr, "[dbgE] n=%zu sorted0=", sorted.size());
        for (int i = 0; i < 8; ++i) std::fprintf(stderr, "%02x", sorted[0][i]);
        std::fprintf(stderr, " oroot0=");
        for (int i = 0; i < 8; ++i) std::fprintf(stderr, "%02x", oroot[i]);
        std::fprintf(stderr, "\n");
    }

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
