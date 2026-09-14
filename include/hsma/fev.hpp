// HSMA :: fev.hpp — Vesta base-field element (P1-03, DEC-222, GAP-03a).
// Mirror of fe.hpp over F_q (Vesta): 4×u64 LE, Montgomery domain (x·R mod q).
// Constants from vesta_params_gen.hpp (DEC-102 — zero hand transcription;
// the two static_asserts in the header are the compile-time proof).
// CANONICALLY in [0, q) in Montgomery form; construction enforces it;
// deserialization REJECTS non-canonical encodings (DEC-105).
// Integer-only (DEC-090); no inline asm (provenance, per fe.hpp's law).
// HONEST DEVIATION: arithmetic is schoolbook+REDC (fe.hpp uses SOS per CA-66)
// — equally correct, simpler to audit; the 512-case golden set arbitrates
// every limb. Unification is a Phase-1 cleanup note, not a silent choice.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vesta_params_gen.hpp>

namespace hsma::fq {

using vesta_gen::MOD; using vesta_gen::INV;
using vesta_gen::RR;  using vesta_gen::R_ONE;
using u128 = unsigned __int128;

struct alignas(32) fev { std::array<std::uint64_t, 4> l; };

inline bool geqv(const std::uint64_t* a, const std::uint64_t* b) noexcept {
    for (int i = 3; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return true;  // equal
}
inline bool fev_is_canonical(const fev& x) noexcept { return !geqv(x.l.data(), MOD.data()); }
inline bool fev_eq(const fev& a, const fev& b) noexcept { return a.l == b.l; }

// CIOS Montgomery multiplication (Coarsely Integrated Operands Scanning).
// Proven algorithm; no wide intermediate to fold. INV = -q^-1 mod 2^64.
inline fev fev_mul(const fev& A, const fev& B) noexcept {
    // CIOS Montgomery multiplication — the EXACT code from d24e2.cpp that
    // matched Python bit-for-bit. No overflow detection, no complexity.
    std::uint64_t T[6] = {};
    for (int i = 0; i < 4; ++i) {
        u128 C = 0;
        for (int j = 0; j < 4; ++j) {
            u128 prod = (u128)A.l[i] * B.l[j];
            u128 sum = prod + (u128)T[j] + C;
            T[j] = (std::uint64_t)sum;
            C = sum >> 64;
        }
        u128 t4 = (u128)T[4] + C;
        T[4] = (std::uint64_t)t4;
        T[5] = (std::uint64_t)(t4 >> 64);
        u128 m = (u128)T[0] * INV;
        std::uint64_t m_lo = (std::uint64_t)m;
        C = 0;
        for (int j = 0; j < 4; ++j) {
            u128 prod2 = (u128)m_lo * MOD[j];
            u128 sum2 = prod2 + (u128)T[j] + C;
            T[j] = (std::uint64_t)sum2;
            C = sum2 >> 64;
        }
        u128 t4b = (u128)T[4] + C;
        T[4] = (std::uint64_t)t4b;
        T[5] = (std::uint64_t)(t4b >> 64);
        for (int j = 0; j < 5; ++j) T[j] = T[j+1];
        T[5] = 0;
    }
    fev r{};
    bool geq = T[4] != 0;
    if (!geq) {
        for (int i = 3; i >= 0; --i) {
            if (T[i] != MOD[i]) { geq = T[i] > MOD[i]; break; }
            if (i == 0) geq = true;
        }
    }
    if (geq) {
        std::uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            std::uint64_t bi = MOD[i] + borrow;
            if (T[i] >= bi) { T[i] -= bi; borrow = 0; }
            else { T[i] -= bi; borrow = 1; }
        }
    }
    for (int k = 0; k < 4; ++k) r.l[k] = T[k];
    return r;
}
inline fev fev_sqr(const fev& a) noexcept { return fev_mul(a, a); }
inline fev fev_add(const fev& a, const fev& b) noexcept {
    fev r{};
    u128 carry = 0;
    for (int i = 0; i < 4; ++i) {
        u128 s = (u128)a.l[i] + b.l[i] + carry;
        r.l[i] = (std::uint64_t)s;
        carry = s >> 64;
    }
    for (int i = 3; i >= 0; --i) {
        if (r.l[i] != MOD[i]) { if (r.l[i] > MOD[i]) { std::uint64_t borrow = 0;
            for (int k = 0; k < 4; ++k) { std::uint64_t bi = MOD[k] + borrow;
                if (r.l[k] >= bi) { r.l[k] -= bi; borrow = 0; }
                else { r.l[k] -= bi; borrow = 1; } } } break; }
    }
    return r;
}
inline fev fev_sub(const fev& a, const fev& b) noexcept {
    fev r{};
    std::uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        u128 s = (u128)a.l[i] - b.l[i] - borrow;
        r.l[i] = (std::uint64_t)s;
        borrow = (s >> 64) & 1;  // 1 if underflow
    }
    if (borrow) {
        // a < b: add q to wrap around (result = a - b + q)
        u128 carry = 0;
        for (int i = 0; i < 4; ++i) {
            u128 s = (u128)r.l[i] + MOD[i] + carry;
            r.l[i] = (std::uint64_t)s;
            carry = s >> 64;
        }
    }
    return r;
}
inline fev fev_one() noexcept { fev r{}; std::memcpy(r.l.data(), R_ONE.data(), 32); return r; }
inline fev fev_zero() noexcept { return fev{{0, 0, 0, 0}}; }
inline bool fev_is_zero(const fev& x) noexcept { return x.l == std::array<std::uint64_t, 4>{0, 0, 0, 0}; }
inline fev fev_from_u64(std::uint64_t x) noexcept {
    fev t{}; t.l[0] = x;
    fev rr{}; std::memcpy(rr.l.data(), RR.data(), 32);
    return fev_mul(t, rr);                       // x·R²·R⁻¹ = x·R ✓ Montgomery
}
inline fev fev_to_canonical(const fev& x) noexcept {
    fev one_c = fev{{1, 0, 0, 0}};               // CANONICAL one: mmul(vR, 1) = v ✓
    return fev_mul(x, one_c);
}
inline void fev_to_le_bytes(const fev& x, std::byte out[32]) noexcept {
    const fev c = fev_to_canonical(x);           // strip Montgomery first
    for (int k = 0; k < 4; ++k)
        for (int b = 0; b < 8; ++b)
            out[8*k + b] = std::byte(c.l[k] >> (8*b));
}
struct FevFromBytes { bool ok; fev value; };
inline FevFromBytes fev_from_le_bytes(const std::byte in[32]) noexcept {
    fev x{};
    for (int k = 0; k < 4; ++k)
        for (int b = 0; b < 8; ++b)
            x.l[k] |= std::uint64_t(std::to_integer<std::uint8_t>(in[8*k + b])) << (8*b);
    if (!fev_is_canonical(x)) return {false, fev_zero()};   // DEC-105 rejection
    fev rr{}; std::memcpy(rr.l.data(), RR.data(), 32);
    return {true, fev_mul(x, rr)};               // canonical → Montgomery
}
inline FevFromBytes fev_from_limbs_canonical(const std::uint64_t g[4]) noexcept {
    fev x{}; for (int k = 0; k < 4; ++k) x.l[k] = g[k];
    if (!fev_is_canonical(x)) return {false, fev_zero()};
    fev rr{}; std::memcpy(rr.l.data(), RR.data(), 32);
    return {true, fev_mul(x, rr)};
}
// inverse via Fermat: a^(q-2). Exponent DERIVED (MOD-2 at runtime — CA-R86:
// never hand-written limbs). Montgomery domain throughout: mont(a^(q-2)).
inline fev fev_inv(const fev& a) noexcept {
    std::uint64_t e[4];
    for (int i = 0; i < 4; ++i) e[i] = MOD[i];
    std::uint64_t borrow = 2;
    for (int i = 0; i < 4 && borrow; ++i) {
        if (e[i] >= borrow) { e[i] -= borrow; borrow = 0; }
        else { e[i] -= borrow; borrow = 1; }
    }
    fev R = fev_one();                           // mont(1)
    fev base = a;
    for (int limb = 3; limb >= 0; --limb)
        for (int bit = 63; bit >= 0; --bit) {
            R = fev_mul(R, R);
            if ((e[limb] >> bit) & 1ull) R = fev_mul(R, base);
        }
    return R;
}
} // namespace hsma::fq
