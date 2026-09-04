// HSMA :: threshold/scalar_r.hpp - BLS12-377 scalar field F_r (Step 7, DEC-181..184)
// 4x64 limbs, Montgomery domain, canonical [0, r) (DEC-105 mirror). CIOS multiply
// with conditional subtraction; t[4] != 0 is a tripwire. Constants exclusively from
// bls_params_gen.hpp (DEC-182). DEC-127 aggregate-init only; DEC-090 integer-only.
#pragma once
#include <cstdint>
#include <cstring>
#include <bls_params_gen.hpp>

namespace hsma::threshold {

struct Fr {
    std::uint64_t d[4] = {};
    bool operator==(const Fr& o) const { return std::memcmp(d, o.d, sizeof d) == 0; }
    bool operator!=(const Fr& o) const { return !(*this == o); }
    bool is_zero() const { return (d[0] | d[1] | d[2] | d[3]) == 0; }
};

namespace detail {

inline Fr mk(const std::uint64_t v[4]) {
    Fr f{};
    f.d[0] = v[0]; f.d[1] = v[1]; f.d[2] = v[2]; f.d[3] = v[3];
    return f;
}
inline const Fr& r2()      { static const Fr v = mk(bls::R_R2);  return v; }
inline const Fr& one_mont(){ static const Fr v = mk(bls::R_ONE); return v; }

inline int cmp4(const std::uint64_t a[4], const std::uint64_t b[4]) {
    for (int i = 3; i >= 0; --i)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
inline Fr sub_r(const Fr& a) {                 // a - r; requires a >= r
    Fr out{};
    std::uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const unsigned __int128 t = (unsigned __int128)a.d[i] - bls::R_MOD[i] - borrow;
        out.d[i] = static_cast<std::uint64_t>(t);
        borrow = static_cast<std::uint64_t>(t >> 64) & 1ull;
    }
    return out;
}
// Montgomery CIOS: (a * b * 2^-256) mod r; inputs/outputs canonical limbs.
inline Fr mont_mul(const Fr& a, const Fr& b) {
    std::uint64_t t[6] = {};
    for (int i = 0; i < 4; ++i) {
        std::uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            const unsigned __int128 p = (unsigned __int128)a.d[j] * b.d[i] + t[j] + carry;
            t[j] = static_cast<std::uint64_t>(p);
            carry = static_cast<std::uint64_t>(p >> 64);
        }
        {   const unsigned __int128 s = (unsigned __int128)t[4] + carry;
            t[4] = static_cast<std::uint64_t>(s);
            t[5] = static_cast<std::uint64_t>(s >> 64);
        }
        const std::uint64_t m = t[0] * bls::R_INV0;
        {   const unsigned __int128 q = (unsigned __int128)t[0] + (unsigned __int128)m * bls::R_MOD[0];
            carry = static_cast<std::uint64_t>(q >> 64);
        }
        for (int j = 1; j < 4; ++j) {
            const unsigned __int128 u = (unsigned __int128)bls::R_MOD[j] * m + t[j] + carry;
            t[j - 1] = static_cast<std::uint64_t>(u);
            carry = static_cast<std::uint64_t>(u >> 64);
        }
        {   const unsigned __int128 v = (unsigned __int128)t[4] + carry;
            t[3] = static_cast<std::uint64_t>(v);
            t[4] = t[5] + static_cast<std::uint64_t>(v >> 64);
        }
    }
    Fr out = mk(t);
    if (t[4] != 0 || cmp4(out.d, bls::R_MOD) >= 0) out = sub_r(out);
    return out;
}

} // namespace detail

inline bool fr_from_limbs(Fr& out, const std::uint64_t v[4]) {
    if (detail::cmp4(v, bls::R_MOD) >= 0) return false;     // DEC-105 canonical only
    out = detail::mont_mul(detail::mk(v), detail::r2());
    return true;
}
inline bool fr_from_u64(Fr& out, std::uint64_t v) {         // v < r always (r > 2^64)
    const std::uint64_t t[4] = { v, 0, 0, 0 };
    return fr_from_limbs(out, t);
}
inline Fr fr_one() { return detail::one_mont(); }

inline Fr fr_add(const Fr& a, const Fr& b) {
    Fr out{};
    std::uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        const unsigned __int128 s = (unsigned __int128)a.d[i] + b.d[i] + carry;
        out.d[i] = static_cast<std::uint64_t>(s);
        carry = static_cast<std::uint64_t>(s >> 64);
    }
    // carry == 0 provably: a, b < r < 2^253 => a + b < 2^254 (width invariant)
    if (detail::cmp4(out.d, bls::R_MOD) >= 0) out = detail::sub_r(out);
    return out;
}
inline Fr fr_neg(const Fr& a) {
    if (a.is_zero()) return a;                              // -0 = 0
    Fr out{};
    std::uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const unsigned __int128 t = (unsigned __int128)bls::R_MOD[i] - a.d[i] - borrow;
        out.d[i] = static_cast<std::uint64_t>(t);
        borrow = static_cast<std::uint64_t>(t >> 64) & 1ull;
    }
    return out;                                             // r - a in (0, r)
}
inline Fr fr_sub(const Fr& a, const Fr& b) {
    if (detail::cmp4(a.d, b.d) >= 0) {
        Fr out{};
        std::uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            const unsigned __int128 t = (unsigned __int128)a.d[i] - b.d[i] - borrow;
            out.d[i] = static_cast<std::uint64_t>(t);
            borrow = static_cast<std::uint64_t>(t >> 64) & 1ull;
        }
        return out;
    }
    return fr_neg(fr_sub(b, a));                            // a - b = r - (b - a)
}
inline Fr fr_mul(const Fr& a, const Fr& b) { return detail::mont_mul(a, b); }
inline bool fr_inv(Fr& out, const Fr& a) {                 // Fermat: a^(r-2) mod r
    if (a.is_zero()) return false;
    Fr res = detail::one_mont();
    for (int b = 255; b >= 0; --b) {
        res = detail::mont_mul(res, res);
        if ((bls::R_M2[b >> 6] >> (b & 63)) & 1ull)
            res = detail::mont_mul(res, a);
    }
    out = res;
    return true;
}

} // namespace hsma::threshold
