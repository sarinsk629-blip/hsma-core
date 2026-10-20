#pragma once
// HSMA :: pouw/logup_ref.hpp - P5-F ORACLE header (double-precision reference).
// DEC-090-ORACLE-EXEMPT (CA-R231): construction-time oracle — floats are the measuring stick, not the core. // DEC-090 EXEMPTION, justified: this is the ORACLE — the same class as the
// Python golden generators. It runs at TABLE-CONSTRUCTION time only, offline,
// never in the consensus path. The numeric core (logup.hpp) is integer-only
// and provable; this header is the measuring stick it was built against.
// CA-R230: every std header named is included explicitly.
#include <cmath>
#include <cstdint>
#include <vector>
#include "logup.hpp"  // the integer core — constants inherited

namespace hsma::pouw::logup {


inline double gelu_ref(double x) {
    return 0.5 * x * (1.0 + std::tanh(0.7978845608028654 * (x + 0.044715 * x * x * x)));
}
inline double sigmoid_ref(double x) { return 1.0 / (1.0 + std::exp(-x)); }
inline double tanh_ref(double x)    { return std::tanh(x); }
// exp_shifted: exp(x - 4) — the softmax primitive. For x in [-4,4]:
// output in [exp(-8), 1.0] = [0.000335, 1.0]. The softmax usage shifts by
// the row max first, so arguments land in [-inf, 0] -> table covers [-4, 4]
// with the softmax-relevant half [0, -4] mapping to [1.0, 0.0183].
// q7 clamp handles the sub-q7 tail (values below ~0.0078 quantize to 0).
inline double exp_shifted_ref(double x) { return std::exp(x - 4.0); }
inline double idx_to_x(unsigned i)  { return (double(i) / double(1u << FRAC_IN)) - 4.0; }
inline int to_q7(double y) {
    if (y < -4.0) return OUT_MIN;
    if (y >=  4.0) return OUT_MAX;
    const double scaled = y * OUT_ONE;
    return (scaled >= 0) ? int(scaled + 0.5) : -int(-scaled + 0.5);
}
inline unsigned x_to_idx(double x) {
    if (x < -4.0) return 0;
    const double scaled = (x + 4.0) * double(1u << FRAC_IN);
    unsigned i = (scaled < 0) ? 0 : unsigned(scaled);
    return (i >= N_ENTRIES) ? N_ENTRIES - 1 : i;
}


// ---- construction-time table machinery (oracle domain) ----

template <typename Fn>
std::vector<int> build_table(Fn ref_fn) {
    std::vector<int> t(N_ENTRIES);
    for (unsigned i = 0; i < N_ENTRIES; ++i) t[i] = to_q7(ref_fn(idx_to_x(i)));
    return t;
}
struct CertReport { bool ok; unsigned worst_index; int worst_err; };
template <typename Fn>
CertReport certify(const std::vector<int>& table, Fn ref_fn) {
    CertReport rep{true, 0, 0};
    if (table.size() != N_ENTRIES) { rep.ok = false; rep.worst_err = 9999; return rep; }
    for (unsigned i = 0; i < N_ENTRIES; ++i) {
        const int expect = to_q7(ref_fn(idx_to_x(i)));
        int err = table[i] - expect;
        const int aerr = (err < 0) ? -err : err;
        if (aerr > rep.worst_err) { rep.worst_err = aerr; rep.worst_index = i; }
        if (aerr > 1) rep.ok = false;
    }
    return rep;
}
// Tables (the container) lives in logup.hpp — the provable core; the
// builders + certification below are the construction-time oracle.
// ---- Phase 6.15: the rsqrt table (mantissa window + interpolation) ----
// LayerNorm needs 1/sqrt(sigma^2). The honest rung (the roadmap's
// "table+fixup approximation"): normalize sigma^2 (q14 integer) into the
// mantissa window w in [2^20, 2^21) by EVEN power-of-2 shifts (sigma^2 =
// w * 2^shift, shift even -> rsqrt(2^shift) is an exact power of two),
// index the window's top 8 bits (m8 in [128,256]), LINEARLY interpolate
// the low 13 bits, halve the exponent. Certified below on the
// (m8, frac) grid against the double oracle — the interpolation chord
// bound is MEASURED and pinned (worst_err in the report), not assumed.
inline constexpr unsigned RSQ_M8_MIN = 128;
inline constexpr unsigned RSQ_M8_MAX = 256;   // +1 interpolation sentinel
// rsqrt_win(w) = round(2^21 / sqrt(w)) for w in [2^20, 2^21] — the q21-domain
// inverse sqrt of the windowed mantissa (sqrt(w) in [2^10, 2^11)), so the
// window maps to [1448, 2048]. Consumer: inv(σ²) = f(w) >> (shift/2), then
// y_q7 = (c_q7 · inv) >> 14 — see pouw/layernorm.hpp.
inline double rsqrt_win_ref(double w) { return 2097152.0 / std::sqrt(w); }
inline std::vector<int> build_rsqrt_table() {
    std::vector<int> t(RSQ_M8_MAX - RSQ_M8_MIN + 1, 0);
    for (unsigned m8 = RSQ_M8_MIN; m8 <= RSQ_M8_MAX; ++m8)
        t[m8 - RSQ_M8_MIN] = int(rsqrt_win_ref(double(m8) * 8192.0) + 0.5);
    return t;
}
// certify the INTERPOLATED reader on the (m8, frac) grid. frac in
// {0, 2048, 4096, 6144, 8191} — the endpoints pin the table itself, the
// midpoints pin the chord. Bound: the interpolation chord error of sqrt
// on a 2^13 window (~0.4% relative worst-case) + 1 q21 rounding unit.
inline CertReport certify_rsqrt(const std::vector<int>& t) {
    CertReport rep{true, 0, 0};
    if (t.size() != std::size_t(RSQ_M8_MAX - RSQ_M8_MIN + 1)) {
        rep.ok = false; rep.worst_err = 9999; return rep;
    }
    const unsigned fracs[5] = {0, 2048, 4096, 6144, 8191};
    for (unsigned m8 = RSQ_M8_MIN; m8 <= RSQ_M8_MAX - 1; ++m8) {
        for (const unsigned fr : fracs) {
            const double w = double(m8) * 8192.0 + double(fr);
            const int expect = int(rsqrt_win_ref(w) + 0.5);
            const int t0 = t[m8 - RSQ_M8_MIN], t1 = t[m8 - RSQ_M8_MIN + 1];
            const int got = t0 + int((double(t1 - t0) * double(fr)) / 8192.0);
            int err = got - expect;
            const int aerr = (err < 0) ? -err : err;
            if (aerr > rep.worst_err) { rep.worst_err = aerr; rep.worst_index = m8; }
            if (aerr > 8) rep.ok = false;
        }
    }
    return rep;
}
inline Tables build_all() {
    Tables T{};
    T.gelu = build_table(gelu_ref);
    T.sigmoid = build_table(sigmoid_ref);
    T.tanh = build_table(tanh_ref);
    T.exp_shifted = build_table(exp_shifted_ref);
    T.rcp = build_rcp_table();
    T.rsqrt = build_rsqrt_table();
    const auto c1 = certify(T.gelu, gelu_ref);
    const auto c2 = certify(T.sigmoid, sigmoid_ref);
    const auto c3 = certify(T.tanh, tanh_ref);
    const auto c4 = certify(T.exp_shifted, exp_shifted_ref);
    const auto c6 = certify_rsqrt(T.rsqrt);
    T.certified = c1.ok && c2.ok && c3.ok && c4.ok && c6.ok;
    std::printf("[logup] certification: gelu %s (worst %d LSB @%u) | sigmoid %s (worst %d) | tanh %s (worst %d) | exp_shifted %s (worst %d) | rsqrt %s (worst %d @m8=%u)\n",
        c1.ok?"PASS":"FAIL", c1.worst_err, c1.worst_index,
        c2.ok?"PASS":"FAIL", c2.worst_err,
        c3.ok?"PASS":"FAIL", c3.worst_err,
        c4.ok?"PASS":"FAIL", c4.worst_index,
        c6.ok?"PASS":"FAIL", c6.worst_err, c6.worst_index);
    return T;
}
inline int lookup_by_double(const std::vector<int>& t, double x) {
    return lookup_by_index(t, x_to_idx(x));
}

} // namespace hsma::pouw::logup
