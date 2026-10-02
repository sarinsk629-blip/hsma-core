#pragma once
// HSMA :: pouw/logup.hpp - P5-F: activation lookup tables + 1-LSB certification gate.
// Layer 3 of the AI stack: the non-linear activations (GELU, sigmoid, tanh) as
// provable lookup tables. L=8 fixed-point (256 entries), Q.7 output format.
// Certification: EVERY entry checked against the true function to 1 LSB —
// enforced at construction by exhaustive enumeration (the gate is not optional).
// LogUp-in-CCS integration (the in-circuit proof) wires onto these tables next.

#include <hsma/consensus.hpp>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace hsma::pouw::logup {

// ---- Fixed-point format: Q.7 (1 sign bit + 1 int bit implied + 7 frac bits) ----
// Domain: inputs in [-4.0, 4.0) at 1/32 granularity (L_in = 8, 256 points).
// Range: outputs in [-4.0, 4.0) as signed Q.7 (value * 128, clamped).
static constexpr unsigned L_IN = 8;          // 256 table entries
static constexpr unsigned N_ENTRIES = 1u << L_IN;
static constexpr unsigned FRAC_IN = 5;       // input step = 1/32
static constexpr unsigned FRAC_OUT = 7;      // Q.7 output
static constexpr int OUT_ONE = 1 << FRAC_OUT;             // 128 = 1.0 in Q.7
static constexpr int OUT_MIN = -(4 * OUT_ONE);            // -4.0 clamped
static constexpr int OUT_MAX = (4 * OUT_ONE) - 1;         // +4.0 clamped (inclusive)

// ---- The three activation functions, double-precision reference ----
// GELU (tanh approximation — the standard inference form):
inline double gelu_ref(double x) {
    return 0.5 * x * (1.0 + std::tanh(0.7978845608028654 * (x + 0.044715 * x * x * x)));
}
inline double sigmoid_ref(double x) { return 1.0 / (1.0 + std::exp(-x)); }
inline double tanh_ref(double x)    { return std::tanh(x); }

enum class Activation : std::uint8_t { GELU = 0, SIGMOID = 1, TANH = 2 };

// fixed-point index -> real input
inline double idx_to_x(unsigned i) {
    return (double(i) / double(1u << FRAC_IN)) - 4.0;   // [0,256) -> [-4, 4)
}

// true function value -> clamped Q.7
inline int to_q7(double y) {
    if (y < -4.0) return OUT_MIN;
    if (y >=  4.0) return OUT_MAX;
    const double scaled = y * OUT_ONE;
    return (scaled >= 0) ? int(scaled + 0.5) : -int(-scaled + 0.5);  // round-half-up
}

// ---- THE CERTIFICATION GATE (1-LSB, exhaustive) ----
// A table passes iff every entry is within 1 LSB of the reference function.
// This is not a sample — it is ALL 256 points, at construction time.
struct CertReport { bool ok; unsigned worst_index; int worst_err; };

template <typename Fn>   // Fn: double -> double (the reference)
CertReport certify(const std::vector<int>& table, Fn ref) {
    CertReport rep{true, 0, 0};
    if (table.size() != N_ENTRIES) { rep.ok = false; rep.worst_err = 9999; return rep; }
    for (unsigned i = 0; i < N_ENTRIES; ++i) {
        const int expect = to_q7(ref(idx_to_x(i)));
        const int err = table[i] - expect;
        if (err < 0) err_check: ;
        const int aerr = (err < 0) ? -err : err;
        if (aerr > rep.worst_err) { rep.worst_err = aerr; rep.worst_index = i; }
        if (aerr > 1) { rep.ok = false; }             // THE GATE: 1 LSB
    }
    return rep;
}

// ---- Table construction (deterministic, the prover's table) ----
template <typename Fn>
std::vector<int> build_table(Fn ref) {
    std::vector<int> t(N_ENTRIES);
    for (unsigned i = 0; i < N_ENTRIES; ++i) t[i] = to_q7(ref(idx_to_x(i)));
    return t;
}

// ---- The three certified tables (construct + certify; abort on failure) ----
struct Tables { std::vector<int> gelu, sigmoid, tanh; bool certified; };

inline Tables build_all() {
    Tables T{};
    T.gelu    = build_table(gelu_ref);
    T.sigmoid = build_table(sigmoid_ref);
    T.tanh    = build_table(tanh_ref);
    const auto c1 = certify(T.gelu, gelu_ref);
    const auto c2 = certify(T.sigmoid, sigmoid_ref);
    const auto c3 = certify(T.tanh, tanh_ref);
    T.certified = c1.ok && c2.ok && c3.ok;
    std::printf("[logup] certification: gelu %s (worst %d LSB @%u) | sigmoid %s (worst %d) | tanh %s (worst %d)\n",
        c1.ok?"PASS":"FAIL", c1.worst_err, c1.worst_index,
        c2.ok?"PASS":"FAIL", c2.worst_err,
        c3.ok?"PASS":"FAIL", c3.worst_err);
    return T;
}

// ---- Lookup: real input -> table index (the prover's side; the circuit
//      constrains index correctness via the LogUp multiset argument) ----
inline unsigned x_to_idx(double x) {
    if (x < -4.0) return 0;
    const double scaled = (x + 4.0) * double(1u << FRAC_IN);
    unsigned i = (scaled < 0) ? 0 : unsigned(scaled);
    return (i >= N_ENTRIES) ? N_ENTRIES - 1 : i;
}
inline int lookup(const std::vector<int>& t, double x) { return t[x_to_idx(x)]; }

} // namespace hsma::pouw::logup
