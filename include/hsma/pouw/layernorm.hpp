#pragma once
// HSMA :: pouw/layernorm.hpp - Phase 6.15 (DEC-s5): LayerNorm, the honest rung.
//
// THE ROADMAP'S HONEST ROUTE, TAKEN. LayerNorm's mean/variance need division
// and a sqrt — both non-expressible in the float-free field core directly.
// This header is the "table+fixup approximation" the roadmap registered as
// the honest alternative:
//   mean     mu_q7 = (sum_q7 · rcp[n]) >> 14        (RCP table, step49)
//   variance v_q14 = (sum c_i^2 · rcp[n]) >> 14     (RCP again)
//   rsqrt    inv = 2^21 / sqrt(v)                    (the certified rsqrt
//            table: 8-bit mantissa window + linear interpolation + exact
//            power-of-2 exponent handling, 0-LSB-grid certified in
//            logup_ref.hpp — worst chord error MEASURED and pinned)
//   y_i      = ((c_i · inv) >> 14 · gamma) >> 7 + beta   (identity-affine
//            rung: gamma=128, beta=0 is plain LayerNorm)
// The epsilon rides v as EPS_Q14 = 1638 (~1e-4 in real units), so a
// constant row (variance 0) takes the epsilon floor instead of dividing
// by zero.
//
// HONEST BOUNDARY (registered, not hidden):
//   * The approximation error vs the real-valued oracle is MEASURED by
//     test_step61 and pinned — LayerNorm here is q7/q14 fixed-point, and
//     the error budget is part of the contract.
//   * The RCP lookups (the two divisions per row) ride the LogUp batch
//     (SoftmaxBatch-style audit). The rsqrt lookups are certified at table
//     construction (grid receipt); per-lookup LogUp binding for the
//     interpolated reader lands with circuit instantiation (P1-13) — the
//     same registration the roadmap makes for exact LayerNorm.
//   * Inputs are q7 fixed-point canonical field values < 2^15 (contract,
//     enforced per entry); outputs are q7 SIGNED integers with a
//     documented field mapping (fe_from_s64 — negatives ride p-|y|).
#include <hsma/fe.hpp>
#include <hsma/pouw/logup.hpp>
#include <hsma/pouw/softmax.hpp>   // the shared canonical->u64 extractor (fe_u64)
#include <cstdint>
#include <cstddef>
#include <vector>

namespace hsma::pouw::ln {

using logup::RCP_MAX;

static constexpr std::uint64_t EPS_Q14 = 2;             // ~1.22e-4 (round(2^14 · 1e-4))
static constexpr std::uint64_t INV_SQRT2_Q21 = 1482910; // round(2^21/√2)
static constexpr std::uint64_t SQRT2_Q21     = 2965821; // round(2^21·√2)
static constexpr std::uint64_t LN_INPUT_MAX  = 1ull << 15;  // q7 input contract
static constexpr std::uint64_t LN_V_MAX      = 1ull << 40; // variance contract

// signed <-> field helpers (the documented boundary).
inline fp::fe fe_from_s64(std::int64_t v) noexcept {
    if (v >= 0) return fp::fe_from_u64((std::uint64_t)v);
    return fp::fe_sub(fp::fe_zero(), fp::fe_from_u64((std::uint64_t)(-v)));
}
struct FeS64 { bool ok; std::int64_t v; };
inline FeS64 fe_to_s64(const fp::fe& x) noexcept {
    const auto e = softmax::fe_u64(x);
    if (e.ok) return {true, (std::int64_t)e.v};
    // value >= 2^64: the only legal shape in this rung is p - small (negative)
    const fp::fe m = fp::fe_sub(fp::fe_zero(), x);   // p - x = |v|
    const auto a = softmax::fe_u64(m);
    if (!a.ok || a.v >= (1ull << 62)) return {false, 0};
    return {true, -(std::int64_t)a.v};
}

// bit length (v > 0, contract v < 2^40)
inline unsigned bitlen_u64(std::uint64_t v) noexcept {
    unsigned b = 0; while (v) { ++b; v >>= 1; } return b;
}

// THE RSQRT READER. v in (0, 2^40); returns round(2^21 / sqrt(v)).
// Normalization: v = w · 2^e' with w in [2^20, 2^21), e' = bitlen(v) - 21;
// table+interpolation on w's (m8, frac); exact power-of-2 exponent fixup,
// odd e' rides the SQRT2/INV_SQRT2 constants.
inline std::uint64_t rsqrt_q14(const logup::Tables& T, std::uint64_t v) noexcept {
    const auto& RT = T.rsqrt;
    const int e32 = (int)bitlen_u64(v) - 21;
    std::uint64_t w;
    if (e32 >= 0) w = v >> e32; else w = v << (-e32);
    // w in [2^20, 2^21) now; m8 = top 8 bits, frac = low 13
    unsigned m8 = (unsigned)(w >> 13);
    unsigned frac = (unsigned)(w & 8191u);
    if (m8 < 128u) { m8 = 128u; frac = 0u; }
    if (m8 > 255u) { m8 = 255u; frac = 8191u; }
    const int t0 = RT[m8 - 128u], t1 = RT[m8 - 128u + 1u];
    const std::uint64_t t = (std::uint64_t)t0
        + (((std::int64_t)(t1 - t0) * (std::int64_t)frac) >> 13);
    const unsigned ep = (unsigned)e32 >= 0u ? (unsigned)e32 : 0u;
    const unsigned en = e32 < 0 ? (unsigned)(-e32) : 0u;
    if ((ep & 1u) == 0u)                                    // even exponent
        return (e32 >= 0) ? (t >> (ep >> 1)) : (t << (en >> 1));
    // odd exponent: exact sqrt2/inv-sqrt2 fixup. The constants are 2^21-scaled,
    // so the product must come back down >> 21 before the power-of-two shift
    // (caught by test_step61 P2: the missing >>21 blew inv up by 2^21).
    if (e32 >= 1)
        return ((t * INV_SQRT2_Q21) >> 21) >> ((ep - 1u) >> 1); // 2^(-e'/2) = inv_sqrt2 · 2^((1-e')/2)
    return ((t * SQRT2_Q21) >> 21) << ((en - 1u) >> 1);         // e' <= -1: sqrt2 · 2^((-1-e')/2)
}

struct LayerNormResult {
    bool ok = false;
    std::vector<std::int64_t> y;      // q7 signed, rows*n
    std::size_t bad_entry = 0;
};

// THE PRODUCER. X is rows*n q7 field entries (row-major); n <= RCP_MAX is
// the division contract. audit (optional) receives the RCP lookup trace
// (two per row: the mean division and the variance division).
inline LayerNormResult layernorm_rows(const std::vector<fp::fe>& X,
                                      unsigned rows, unsigned n,
                                      const logup::Tables& T,
                                      int gamma_q7 = 128, int beta_q7 = 0,
                                      logup::LogUpBatch* audit = nullptr) noexcept {
    LayerNormResult R;
    if (rows == 0 || n == 0 || n > RCP_MAX || X.size() != (std::size_t)rows * n) return R;
    const auto& RCPT = T.rcp;
    const int rc_n = logup::rcp_lookup(RCPT, n);
    if (rc_n <= 0) return R;
    R.y.assign((std::size_t)rows * n, 0);
    for (unsigned r = 0; r < rows; ++r) {
        if (audit) audit->add_lookup(n, rc_n);   // the mean division
        const std::size_t base = (std::size_t)r * n;
        std::uint64_t sum = 0;
        std::vector<std::uint64_t> xq(n, 0);
        for (unsigned j = 0; j < n; ++j) {
            const auto e = softmax::fe_u64(X[base + j]);
            if (!e.ok || e.v >= LN_INPUT_MAX) { R.bad_entry = base + j; return R; }
            xq[j] = e.v; sum += e.v;
        }
        const std::uint64_t mu = (sum * (std::uint64_t)rc_n) >> 14;      // q7 mean
        std::uint64_t var_sum = 0;
        std::vector<std::int64_t> c(n, 0);
        for (unsigned j = 0; j < n; ++j) {
            c[j] = (std::int64_t)xq[j] - (std::int64_t)mu;               // signed
            var_sum += (std::uint64_t)(c[j] * c[j]);                     // q14
        }
        if (audit) audit->add_lookup(n, rc_n);   // the variance division
        // PARENTHESIS DISCIPLINE: >> binds LOOSER than + — the un-parenthesized
        // form parsed as >> (14 + EPS) and shifted by 1652 (test_step61 caught
        // it: v collapsed, inv exploded, drift hit 620).
        const std::uint64_t v = ((var_sum * (std::uint64_t)rc_n) >> 14) + EPS_Q14;
        if (v >= LN_V_MAX) { R.bad_entry = base; return R; }
        const std::uint64_t inv = rsqrt_q14(T, v);
        for (unsigned j = 0; j < n; ++j) {
            std::int64_t y = ((c[j] * (std::int64_t)inv) >> 14);   // C++20: floor shift
            y = ((y * (std::int64_t)gamma_q7) >> 7) + (std::int64_t)beta_q7;
            R.y[base + j] = y;
        }
    }
    R.ok = true;
    return R;
}

} // namespace hsma::pouw::ln
