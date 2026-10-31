// HSMA :: pcompress.hpp — GAP-08: the compressed point wire codec (P5).
// Three fields, one law family:
//   Pasta 32-B  : Pallas (g1p, F_p) and Vesta (g2v, F_q) — x canonical LE,
//                 parity of y in bit 7 of byte 31. Infinity = 32 zero bytes.
//   BLS G1 48-B : threshold::g1 (F_q377) — x canonical LE (6 limbs, q < 2^377
//                 so byte47 bit0 is the last x bit), parity of y in bit 7 of
//                 byte 47. Infinity = 48 zero bytes.
// sqrt: Tonelli-Shanks. Pasta 2-adicity EXACTLY 32 (t = (p-1)>>32 odd —
// static-asserted on the generated moduli); the non-residue is found by the
// deterministic Euler scan (bounded, trip-checked). BLS Fq: g1::tonelli_q
// (canonical in/out) — the decompressor runs the Euler residue gate FIRST so
// the abort path inside tonelli_q is unreachable from wire input.
// LAWS: DEC-105 canonical-value rejection at the parse boundary (fe_from_le_
// bytes / fev_from_le_bytes reject non-canonical x; the 48-B form checks
// x < q explicitly via bn_cmp); CA-R132 le_bytes canonicalizes internally.
// TRANSPORT-ONLY: DEC-192's digest law stays over the 96-B affine form — the
// compressed form never feeds a transcript or a commitment.
#pragma once
#include <hsma/fe.hpp>
#include <hsma/fev.hpp>
#include <hsma/g1p.hpp>
#include <hsma/g2v.hpp>
#include "pallas_params_gen.hpp"
#include "vesta_params_gen.hpp"
#include <hsma/threshold/mont384.hpp>
#include <hsma/threshold/g1.hpp>
#include <array>
#include <cstdint>
#include <cstring>

namespace hsma::pcompress {

namespace tg1   = ::hsma::threshold::g1;     // the BLS12-377 G1 (Step 8)
namespace tmont = ::hsma::threshold::mont;

// ---- 256-bit constexpr helpers (canonical-limb domain, LE) ----
inline constexpr std::array<std::uint64_t, 4> _dec1(const std::array<std::uint64_t, 4>& v) noexcept {
    std::array<std::uint64_t, 4> r = v;
    for (int i = 0; i < 4; ++i)
        if (r[i]-- != 0) break;          // borrow only while limb was 0
    return r;
}
inline constexpr std::array<std::uint64_t, 4> _shr(const std::array<std::uint64_t, 4>& v, unsigned n) noexcept {
    std::array<std::uint64_t, 4> r{};
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t lo = v[i] >> n;
        const std::uint64_t hi = (i + 1 < 4) ? (v[i + 1] << (64 - n)) : 0ull;
        r[i] = n ? (lo | hi) : v[i];
    }
    return r;
}
inline constexpr std::array<std::uint64_t, 4> _add1(const std::array<std::uint64_t, 4>& v) noexcept {
    std::array<std::uint64_t, 4> r = v;
    for (int i = 0; i < 4; ++i)
        if (++r[i] != 0) break;          // carry only while limb wrapped
    return r;
}

// ---- Pasta field parameters (canonical limbs, from the generated goldens) ----
inline constexpr std::array<std::uint64_t, 4> P_P1   = _dec1(pallas_gen::MOD);   // p-1
inline constexpr std::array<std::uint64_t, 4> P_HALF = _shr(P_P1, 1);            // (p-1)/2
inline constexpr std::array<std::uint64_t, 4> P_T    = _shr(P_P1, 32);           // odd part
inline constexpr std::array<std::uint64_t, 4> P_TH   = _shr(_add1(P_T), 1);      // (t+1)/2
static_assert((P_T[0] & 1ull) == 1ull, "Pallas 2-adicity is not exactly 32");
inline constexpr std::array<std::uint64_t, 4> Q_P1   = _dec1(vesta_gen::MOD);    // q-1
inline constexpr std::array<std::uint64_t, 4> Q_HALF = _shr(Q_P1, 1);
inline constexpr std::array<std::uint64_t, 4> Q_T    = _shr(Q_P1, 32);
inline constexpr std::array<std::uint64_t, 4> Q_TH   = _shr(_add1(Q_T), 1);
static_assert((Q_T[0] & 1ull) == 1ull, "Vesta 2-adicity is not exactly 32");

// ---- square-and-multiply (MSB-first), one per field type ----
inline fp::fe _pow_fp(const fp::fe& a, const std::array<std::uint64_t, 4>& e) noexcept {
    fp::fe r = fp::fe_one();
    for (int i = 3; i >= 0; --i)
        for (int b = 63; b >= 0; --b) {
            r = fp::fe_mul(r, r);
            if ((e[i] >> b) & 1ull) r = fp::fe_mul(r, a);
        }
    return r;
}
inline fq::fev _pow_fev(const fq::fev& a, const std::array<std::uint64_t, 4>& e) noexcept {
    fq::fev r = fq::fev_from_u64(1);
    for (int i = 3; i >= 0; --i)
        for (int b = 63; b >= 0; --b) {
            r = fq::fev_mul(r, r);
            if ((e[i] >> b) & 1ull) r = fq::fev_mul(r, a);
        }
    return r;
}
inline bool _eq_fp(const fp::fe& a, const std::array<std::uint64_t, 4>& canon) noexcept {
    return fp::fe_to_canonical(a).l == canon;
}
inline fp::fe _neg_one_fp() noexcept { return fp::fe_sub(fp::fe_zero(), fp::fe_one()); }
inline fq::fev _neg_one_fev() noexcept { return fq::fev_sub(fq::fev_zero(), fq::fev_from_u64(1)); }

// ---- Tonelli-Shanks over the Pasta fields (s = 32, t odd) ----
struct SqrtFp { bool ok{}; fp::fe v{}; };
inline SqrtFp fp_sqrt(const fp::fe& a) noexcept {
    if (fp::fe_is_zero(a)) return {true, fp::fe_zero()};
    if (!_eq_fp(_pow_fp(a, P_HALF), std::array<std::uint64_t, 4>{1, 0, 0, 0}))
        return {false, fp::fe_zero()};                      // non-residue: no sqrt
    fp::fe z{};
    {   bool found = false;
        for (std::uint64_t c = 2; c < 2 + 64; ++c) {        // deterministic Euler scan
            if (_eq_fp(_pow_fp(fp::fe_from_u64(c), P_HALF), std::array<std::uint64_t, 4>{
                    P_P1[0], P_P1[1], P_P1[2], P_P1[3]})) { // c^half == p-1  (i.e. -1)
                z = fp::fe_from_u64(c); found = true; break;
            }
        }
        if (!found) return {false, fp::fe_zero()};          // unreachable (trip-check)
    }
    fp::fe c = _pow_fp(z, P_T);
    fp::fe t = _pow_fp(a, P_T);
    fp::fe R = _pow_fp(a, P_TH);
    unsigned m = 32;
    unsigned guard = 0;
    while (!_eq_fp(t, std::array<std::uint64_t, 4>{1, 0, 0, 0})) {
        if (++guard > 64) return {false, fp::fe_zero()};    // unreachable for a QR
        unsigned i = 0;
        fp::fe t2 = t;
        while (!_eq_fp(t2, std::array<std::uint64_t, 4>{1, 0, 0, 0})) {
            t2 = fp::fe_mul(t2, t2);
            if (++i >= m) return {false, fp::fe_zero()};    // order violation
        }
        fp::fe b = c;
        for (unsigned k = 0; k < m - i - 1; ++k) b = fp::fe_mul(b, b);
        m = i;
        c = fp::fe_mul(b, b);
        t = fp::fe_mul(t, c);
        R = fp::fe_mul(R, b);
    }
    return {true, R};
}
struct SqrtFev { bool ok{}; fq::fev v{}; };
inline SqrtFev fev_sqrt(const fq::fev& a) noexcept {
    if (fq::fev_is_zero(a)) return {true, fq::fev_zero()};
    const fq::fev one = fq::fev_from_u64(1);
    if (!fq::fev_eq(_pow_fev(a, Q_HALF), one)) return {false, fq::fev_zero()};
    fq::fev z{};
    {   bool found = false;
        for (std::uint64_t c = 2; c < 2 + 64; ++c) {
            if (fq::fev_eq(_pow_fev(fq::fev_from_u64(c), Q_HALF), _neg_one_fev())) {
                z = fq::fev_from_u64(c); found = true; break;
            }
        }
        if (!found) return {false, fq::fev_zero()};
    }
    fq::fev c = _pow_fev(z, Q_T);
    fq::fev t = _pow_fev(a, Q_T);
    fq::fev R = _pow_fev(a, Q_TH);
    unsigned m = 32;
    unsigned guard = 0;
    while (!fq::fev_eq(t, one)) {
        if (++guard > 64) return {false, fq::fev_zero()};
        unsigned i = 0;
        fq::fev t2 = t;
        while (!fq::fev_eq(t2, one)) {
            t2 = fq::fev_mul(t2, t2);
            if (++i >= m) return {false, fq::fev_zero()};
        }
        fq::fev b = c;
        for (unsigned k = 0; k < m - i - 1; ++k) b = fq::fev_mul(b, b);
        m = i;
        c = fq::fev_mul(b, b);
        t = fq::fev_mul(t, c);
        R = fq::fev_mul(R, b);
    }
    return {true, R};
}

// ---- Pasta 32-B compressed form ----
inline bool compress_p(const g1p::PtP& P, std::uint8_t out[32]) noexcept {
    if (!g1p::on_curve(P)) return false;
    if (g1p::is_inf(P)) { std::memset(out, 0, 32); return true; }
    fp::fe x{}, y{};
    if (!g1p::to_affine(P, x, y)) return false;
    std::byte b[32];
    fp::fe_to_le_bytes(x, b);                               // canonicalizes internally
    for (int i = 0; i < 32; ++i) out[i] = std::to_integer<std::uint8_t>(b[i]);
    out[31] = (std::uint8_t)((out[31] & 0x7F) |
             (std::uint8_t)((fp::fe_to_canonical(y).l[0] & 1ull) << 7));
    return true;
}
inline bool decompress_p(const std::uint8_t in[32], g1p::PtP& P) noexcept {
    bool allz = true;
    for (int i = 0; i < 32; ++i) if (in[i]) { allz = false; break; }
    if (allz) { P = g1p::PtP{}; return true; }              // infinity (z=0)
    const bool want_odd = (in[31] >> 7) & 1u;
    std::byte xb[32];
    for (int i = 0; i < 32; ++i) {
        const std::uint8_t v = (i == 31) ? (std::uint8_t)(in[31] & 0x7F) : in[i];
        xb[i] = std::byte{v};
    }
    const auto r = fp::fe_from_le_bytes(xb);                // DEC-105: canonical only
    if (!r.ok) return false;
    const fp::fe x3  = fp::fe_mul(fp::fe_mul(r.value, r.value), r.value);
    const fp::fe rhs = fp::fe_add(x3, g1p::curve_b());      // y^2 = x^3 + 5
    const auto sq = fp_sqrt(rhs);
    if (!sq.ok) return false;                               // x is not on the curve
    fp::fe y = sq.v;
    if ((fp::fe_to_canonical(y).l[0] & 1ull) != (want_odd ? 1ull : 0ull))
        y = fp::fe_sub(fp::fe_zero(), y);
    P = g1p::from_affine(r.value, y);
    return true;
}
inline bool compress_v(const g2v::PtV& P, std::uint8_t out[32]) noexcept {
    if (!g2v::on_curve(P)) return false;
    if (g2v::is_inf(P)) { std::memset(out, 0, 32); return true; }
    fq::fev x{}, y{};
    if (!g2v::to_affine(P, x, y)) return false;
    std::byte b[32];
    fq::fev_to_le_bytes(x, b);
    for (int i = 0; i < 32; ++i) out[i] = std::to_integer<std::uint8_t>(b[i]);
    out[31] = (std::uint8_t)((out[31] & 0x7F) |
             (std::uint8_t)((fq::fev_to_canonical(y).l[0] & 1ull) << 7));
    return true;
}
inline bool decompress_v(const std::uint8_t in[32], g2v::PtV& P) noexcept {
    bool allz = true;
    for (int i = 0; i < 32; ++i) if (in[i]) { allz = false; break; }
    if (allz) { P = g2v::PtV{}; return true; }
    const bool want_odd = (in[31] >> 7) & 1u;
    std::byte xb[32];
    for (int i = 0; i < 32; ++i) {
        const std::uint8_t v = (i == 31) ? (std::uint8_t)(in[31] & 0x7F) : in[i];
        xb[i] = std::byte{v};
    }
    const auto r = fq::fev_from_le_bytes(xb);               // DEC-105: canonical only
    if (!r.ok) return false;
    const fq::fev x3  = fq::fev_mul(fq::fev_mul(r.value, r.value), r.value);
    const fq::fev rhs = fq::fev_add(x3, g2v::curve_b());    // y^2 = x^3 + 5
    const auto sq = fev_sqrt(rhs);
    if (!sq.ok) return false;
    fq::fev y = sq.v;
    if ((fq::fev_to_canonical(y).l[0] & 1ull) != (want_odd ? 1ull : 0ull))
        y = fq::fev_sub(fq::fev_zero(), y);
    P = g2v::from_affine(r.value, y);
    return true;
}

// ---- BLS12-377 G1 48-B compressed form (the sigma wire, GAP-08) ----
// to_affine already returns CANONICAL limbs; tonelli_q takes/returns canonical.
// The Euler gate (rhs^halfq == 1) runs BEFORE tonelli_q so the abort path
// inside it is unreachable from wire input — a hostile x rejects cleanly.
inline bool g1_compress48(const tg1::Pt& P, std::uint8_t out[48]) noexcept {
    const tg1::Ctx& CX = tg1::ctx();
    (void)CX;
    if (tg1::PisInf(P)) { std::memset(out, 0, 48); return true; }
    std::uint64_t xa[6], ya[6];
    if (!tg1::to_affine(P, xa, ya)) return false;
    std::memset(out, 0, 48);
    for (int l = 0; l < 6; ++l)
        for (int b = 0; b < 8; ++b)
            out[8 * l + b] = (std::uint8_t)(xa[l] >> (8 * b));
    out[47] = (std::uint8_t)((out[47] & 0x01) | (std::uint8_t)((ya[0] & 1ull) << 7));
    return true;
}
inline bool g1_decompress48(const std::uint8_t in[48], tg1::Pt& P) noexcept {
    const tg1::Ctx& CX = tg1::ctx();
    const tmont::MCtx& QC = CX.m;
    bool allz = true;
    for (int i = 0; i < 48; ++i) if (in[i]) { allz = false; break; }
    if (allz) { P = tg1::Pt{}; return true; }
    const bool want_odd = (in[47] >> 7) & 1u;
    std::uint8_t xb[48];
    for (int i = 0; i < 48; ++i) xb[i] = (i == 47) ? (std::uint8_t)(in[47] & 0x7F) : in[i];
    std::uint64_t xa[6]{};
    for (int l = 0; l < 6; ++l)
        for (int b = 0; b < 8; ++b)
            xa[l] |= (std::uint64_t)xb[8 * l + b] << (8 * b);
    if (tmont::bn_cmp(xa, CX.m.m.data(), 6) >= 0) return false;   // x >= q: non-canonical
    tmont::fe6 Mx{};
    tmont::bn_cpy(Mx.data(), xa, 6);
    Mx = tmont::mfrom(QC, Mx);
    const tmont::fe6 x3  = tmont::mmul(QC, tmont::mmul(QC, Mx, Mx), Mx);
    const tmont::fe6 rhs = tmont::madd(QC, x3, CX.b);              // y^2 = x^3 + 1
    const tmont::fe6 res  = tmont::mpow(QC, rhs, CX.halfq);        // Euler gate
    tmont::fe6 one{}; one[0] = 1;
    if (tmont::mto(QC, res) != one) return false;                 // non-residue: reject
    tmont::fe6 y = tg1::tonelli_q(tmont::mto(QC, rhs));           // canonical out
    if ((y[0] & 1ull) != (want_odd ? 1ull : 0ull)) {
        const tmont::fe6 yc = tmont::mfrom(QC, y);
        y = tmont::mto(QC, tmont::msub(QC, tmont::fe6{}, yc));      // y = -y mod q
    }
    P = tg1::from_affine(xa, y.data());
    return true;
}

} // namespace hsma::pcompress
