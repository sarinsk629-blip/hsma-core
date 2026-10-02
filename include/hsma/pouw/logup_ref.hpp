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
struct Tables { std::vector<int> gelu, sigmoid, tanh; bool certified; };
inline Tables build_all() {
    Tables T{};
    T.gelu = build_table(gelu_ref);
    T.sigmoid = build_table(sigmoid_ref);
    T.tanh = build_table(tanh_ref);
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
inline int lookup_by_double(const std::vector<int>& t, double x) {
    return lookup_by_index(t, x_to_idx(x));
}

} // namespace hsma::pouw::logup
