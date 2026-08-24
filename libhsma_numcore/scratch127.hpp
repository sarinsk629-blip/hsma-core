// ═══════════════════════════════════════════════════════════════════════════
//  HSMA :: scratch127.hpp — 127-bit scratch accumulator + RNTE engine
//  Doctrine: DEC-090 (integer-only), DEC-007/PF-4 (zero tie discretion),
//            DEC-104 (clamp-with-counter, symmetric ±(2³¹−1) saturation).
//  Layering: depends on NOTHING (not even libhsma_fp) — CA-64 resolution.
// ═══════════════════════════════════════════════════════════════════════════
#pragma once
#include <cstdint>

namespace hsma::numcore {

#ifdef __SIZEOF_INT128__
using i128 = __int128;
using u128 = unsigned __int128;
#else
#error "HSMA requires __int128 (clang/gcc on ARM64: supported)"
#endif

// Saturation counters — POD only. Folding into fidelity_report_root happens
// in consuming layers via libhsma_fp (CA-64: numeric core stays field-blind).
struct SatCounters {
    std::uint64_t sat_events       = 0;  // post-requant width breaches (DEC-003)
    std::uint64_t clamp_hi         = 0;  // scratch-domain upper clamps
    std::uint64_t clamp_lo         = 0;  // scratch-domain lower clamps
    std::uint64_t scratch_overflow = 0;  // u128 wraparound (defense-in-depth)
};

class ScratchAcc {
public:
    // Legal domain: [−2¹²⁶, 2¹²⁶−1] — the L' = 127 scratch class.
    static constexpr i128 LO_BOUND = -(i128(1) << 126);
    static constexpr i128 HI_BOUND =  (i128(1) << 126) - 1;

    void accumulate(i128 product, SatCounters& sc) noexcept {
        if (__builtin_add_overflow(v_, product, &v_)) {       // u128 exhausted
            sc.scratch_overflow++;
            v_ = (product >= 0) ? HI_BOUND : LO_BOUND;
            return;
        }
        if (v_ > HI_BOUND)      { sc.clamp_hi++; v_ = HI_BOUND; }
        else if (v_ < LO_BOUND) { sc.clamp_lo++; v_ = LO_BOUND; }
    }
    /// Canonical GEMM entry: |w·a| ≤ (2⁶³−1)(2³¹−1) < 2⁹⁴ — Thm 2.4 domain.
    void accumulate(std::int64_t w, std::int32_t a, SatCounters& sc) noexcept {
        accumulate(i128(w) * i128(a), sc);
    }

    i128  raw()   const noexcept { return v_; }
    void  reset()       noexcept { v_ = 0; }

private:
    i128 v_ = 0;
};

struct Requant32 {
    std::int32_t value;
    bool         saturated;
};

/// RNTE shift-right by 2^s of a signed magnitude (mag, neg) — EXACT ties-to-even.
/// Preconditions: s ∈ [1, 63]; mag < 2¹²⁷. Zero floating point, zero branches
/// on secret-free public data; bit-exact on every architecture by construction.
inline Requant32 rnte_shift32(u128 mag, bool neg, unsigned s) noexcept {
    const u128 half = u128(1) << (s - 1);
    const u128 mask = (u128(1) << s) - 1;
    u128  q   = mag >> s;
    u128  r   = mag & mask;
    const bool gt  = (r > half);
    const bool eq  = (r == half);
    const bool odd = (q & 1U) != 0;
    q += (gt || (eq && odd)) ? u128(1) : u128(0);      // ← THE tie-breaker

    constexpr u128 SAT = u128(2147483647);             // ±(2³¹−1), symmetric
    if (q > SAT) [[unlikely]] {
        return { neg ? -2147483647 : 2147483647, true };
    }
    const auto qi = static_cast<std::int64_t>(q);
    return { static_cast<std::int32_t>(neg ? -qi : qi), false };
}

} // namespace hsma::numcore
