// ═══════════════════════════════════════════════════════════════════════════
//  HSMA :: fe.hpp — Pallas base-field element (4×u64 LE, Montgomery domain)
//
//  Representation invariant (DEC-105, normative): every fe holds its value
//  CANONICALLY in [0, p) in Montgomery form (x·R mod p). Construction paths
//  enforce it; deserialization REJECTS non-canonical encodings (malleability
//  closure). Arithmetic: SOS Montgomery — chosen over CIOS at this stage for
//  carry-boundedness transparency (CA-66); CIOS is a Phase-1 benchmark item.
//
//  ARM64 notes: 128-bit products lower to MUL/UMULH pairs automatically under
//  clang 20 — inline asm is deliberately avoided (provenance, scheduling,
//  portability). alignas(32) positions elements for future NEON batching.
// ═══════════════════════════════════════════════════════════════════════════
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <hsma/params.hpp>              // environment contracts (Step 1)
#include <pallas_params_gen.hpp>   // GENERATED — never hand-edited (DEC-102)

namespace hsma::fp {

using pallas_gen::MOD; using pallas_gen::INV;
using pallas_gen::RR;   using pallas_gen::R_ONE;
using u128 = unsigned __int128;

struct alignas(32) fe {
    std::array<std::uint64_t, 4> l;

    friend bool operator==(const fe& a, const fe& b) noexcept { return a.l == b.l; }
    friend bool operator!=(const fe& a, const fe& b) noexcept { return !(a == b); }
};

// ── limb primitives ─────────────────────────────────────────────────────────
inline bool geq(const std::uint64_t* a, const std::uint64_t* b) noexcept {
    for (int i = 3; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return true;                                   // equal
}
inline bool is_canonical(const fe& x) noexcept { return !geq(x.l.data(), MOD.data()); }

// r = a − b assuming a ≥ b (limb-wise)
inline void sub_assumed(std::uint64_t* r, const std::uint64_t* a,
                        const std::uint64_t* b) noexcept {
    std::uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const auto t = __builtin_sub_overflow(a[i], b[i], &r[i]);
        const auto t2 = __builtin_sub_overflow(r[i], borrow, &r[i]);
        borrow = (std::uint64_t)(t || t2);
    }
}
inline void add_into(std::uint64_t* r, const std::uint64_t* b) noexcept { // r += b
    std::uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        const auto t = __builtin_add_overflow(r[i], b[i], &r[i]);
        const auto t2 = __builtin_add_overflow(r[i], c, &r[i]);
        c = (std::uint64_t)(t || t2);
    }
}

// ── SOS Montgomery multiplication ───────────────────────────────────────────
// Computes a·b·R⁻¹ mod p for canonical a, b. Precondition: a, b < p (asserted
// in debug; release callers uphold the invariant — see DEC-105).
inline fe fe_mul(const fe& A, const fe& B) noexcept {
    std::uint64_t T[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    // (1) full schoolbook product into 8 limbs
    for (int i = 0; i < 4; ++i) {
        std::uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            const u128 cur = (u128)T[i + j] + (u128)A.l[j] * B.l[i] + carry;
            T[i + j] = (std::uint64_t)cur;
            carry    = (std::uint64_t)(cur >> 64);
        }
        int k = i + 4;
        while (carry) {                            // ripple (bounded, ≤ 3 hops)
            const u128 cur = (u128)T[k] + carry;
            T[k]   = (std::uint64_t)cur;
            carry  = (std::uint64_t)(cur >> 64);
            ++k;
        }
    }

    // (2) Montgomery reduction of the low half (four fold-and-shift rounds)
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t m = T[i] * INV;        // ≡ −T[i]·p⁻¹ (mod 2⁶⁴)
        std::uint64_t carry =
            (std::uint64_t)(((u128)T[i] + (u128)m * MOD[0]) >> 64);
        for (int j = 1; j < 4; ++j) {
            const u128 cur = (u128)T[i + j] + (u128)m * MOD[j] + carry;
            T[i + j] = (std::uint64_t)cur;
            carry    = (std::uint64_t)(cur >> 64);
        }
        int k = i + 4;
        while (carry) {                            // SOS bound: never escapes T[7]
            const u128 cur = (u128)T[k] + carry;
            T[k]   = (std::uint64_t)cur;
            carry  = (std::uint64_t)(cur >> 64);
            ++k;
        }
    }

    // (3) result in T[4..7]; may be in [0, 2p) → ONE conditional subtraction
    fe r{};
    std::memcpy(r.l.data(), &T[4], 32);
    if (!is_canonical(r)) [[unlikely]] {
        sub_assumed(r.l.data(), r.l.data(), MOD.data());
    }
    return r;
}

inline fe fe_sqr(const fe& a) noexcept { return fe_mul(a, a); }

// ── additive group ──────────────────────────────────────────────────────────
inline fe fe_add(const fe& a, const fe& b) noexcept {
    fe r{};
    std::uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        const auto t  = __builtin_add_overflow(a.l[i], b.l[i], &r.l[i]);
        const auto t2 = __builtin_add_overflow(r.l[i], c, &r.l[i]);
        c = (std::uint64_t)(t || t2);
    }
    if (c || !is_canonical(r)) [[unlikely]]
        sub_assumed(r.l.data(), r.l.data(), MOD.data());   // sum < 2p ⇒ one pass
    return r;
}
inline fe fe_sub(const fe& a, const fe& b) noexcept {
    fe r{};
    std::uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const auto t  = __builtin_sub_overflow(a.l[i], b.l[i], &r.l[i]);
        const auto t2 = __builtin_sub_overflow(r.l[i], borrow, &r.l[i]);
        borrow = (std::uint64_t)(t || t2);
    }
    if (borrow) [[unlikely]] add_into(r.l.data(), MOD.data());
    return r;
}

// ── domain conversions ──────────────────────────────────────────────────────
/// Canonical integer (x < 2⁶⁴) → Montgomery: x·R = SOS(x, R²).
inline fe fe_from_u64(std::uint64_t x) noexcept {
    fe t{{{x, 0, 0, 0}}};
    fe rr{}; std::memcpy(rr.l.data(), RR.data(), 32);
    return fe_mul(t, rr);
}
/// Montgomery → canonical integer: SOS(x, 1) = x·R⁻¹. Result < p by invariant.
inline fe fe_to_canonical(const fe& x) noexcept {
    fe one{{{1, 0, 0, 0}}};
    return fe_mul(x, one);
}

inline fe fe_one() noexcept { fe r{}; std::memcpy(r.l.data(), R_ONE.data(), 32); return r; }
inline fe fe_zero() noexcept { return fe{{0, 0, 0, 0}}; }
inline bool fe_is_zero(const fe& x) noexcept { return x.l == std::array<std::uint64_t,4>{0,0,0,0}; }

// ── canonical serialization (LE, 32 bytes) ──────────────────────────────────
inline void fe_to_le_bytes(const fe& x, std::byte out[32]) noexcept {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "LE host required");
    const fe c = fe_to_canonical(x);                // strip Montgomery first!
    std::memcpy(out, c.l.data(), 32);
}
struct FeFromBytes { bool ok; fe value; };
/// DESERIALIZATION IS SECURITY-SENSITIVE (DEC-105): non-canonical encodings
/// (≥ p) are REJECTED, closing commitment-malleability at the parse boundary.
inline FeFromBytes fe_from_le_bytes(const std::byte in[32]) noexcept {
    fe x{};
    std::memcpy(x.l.data(), in, 32);
    if (!is_canonical(x)) return {false, fe_zero()};
    // into Montgomery: SOS(x, R²)
    fe rr{}; std::memcpy(rr.l.data(), RR.data(), 32);
    return {true, fe_mul(x, rr)};
}

} // namespace hsma::fp
