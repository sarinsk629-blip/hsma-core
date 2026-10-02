#pragma once
// HSMA :: pouw/logup.hpp - P5-F CORE: the LogUp multiset argument + integer tables.
// DEC-090: INTEGER-ONLY. All double-precision reference machinery lives in
// logup_ref.hpp (the construction-time oracle). This header is provable core.
#include <hsma/consensus.hpp>
#include <cstdint>
#include <cstdio>
#include <map>
#include <vector>

namespace hsma::pouw::logup {

static constexpr unsigned L_IN = 8;
static constexpr unsigned N_ENTRIES = 1u << L_IN;
static constexpr unsigned FRAC_IN = 5;
static constexpr unsigned FRAC_OUT = 7;
static constexpr int OUT_ONE = 1 << FRAC_OUT;
static constexpr int OUT_MIN = -(4 * OUT_ONE);
static constexpr int OUT_MAX = (4 * OUT_ONE) - 1;

enum class Activation : std::uint8_t { GELU = 0, SIGMOID = 1, TANH = 2 };

// integer-domain lookup: index in, table value out. THE core operation —
// the circuit constrains THIS relation via the LogUp argument.
inline int lookup_by_index(const std::vector<int>& t, unsigned idx) {
    return (idx < t.size()) ? t[idx] : 0;
}

// ---- Mersenne-61 field ops (testnet proof-prime; production: Pallas F_p) ----
static constexpr std::uint64_t LP = (1ull << 61) - 1;
inline std::uint64_t lp_add(std::uint64_t a, std::uint64_t b){ std::uint64_t r = a + b; if (r >= LP) r -= LP; return r; }
inline std::uint64_t lp_sub(std::uint64_t a, std::uint64_t b){ return lp_add(a, LP - b); }
inline std::uint64_t lp_mul(std::uint64_t a, std::uint64_t b){
    __uint128_t r = (__uint128_t)a * b; return (std::uint64_t)(r % LP);
}
inline std::uint64_t lp_inv(std::uint64_t a){
    std::uint64_t r = 1, e = LP - 2, base = a % LP;
    while (e) { if (e & 1) r = lp_mul(r, base); base = lp_mul(base, base); e >>= 1; }
    return r;
}
inline std::uint64_t lp_denom(std::uint64_t alpha, std::uint64_t idx, std::uint64_t val) {
    std::uint64_t t = lp_add(alpha % LP, LP - lp_mul(alpha % LP, val % LP));
    return lp_add(t, idx % LP);
}

struct LogUpBatch {
    std::uint64_t alpha = 0;
    std::uint64_t lookup_sum = 0;
    std::map<std::uint64_t, std::uint64_t> multiplicity;
    unsigned n_lookups = 0;
    explicit LogUpBatch(std::uint64_t alpha_) : alpha(alpha_ ? alpha_ : 7) {}
    void add_lookup(unsigned idx, int val_q7) {
        const std::uint64_t uv = (std::uint64_t)(val_q7 < 0 ? -val_q7 : val_q7);
        lookup_sum = lp_add(lookup_sum, lp_inv(lp_denom(alpha, idx, uv)));
        multiplicity[idx]++;
        n_lookups++;
    }
};

template <typename ValAt>   // ValAt: unsigned idx -> int q7 (INTEGER callable)
std::uint64_t table_side_sum(const LogUpBatch& b, ValAt val_at) {
    std::uint64_t s = 0;
    for (const auto& [idx, m] : b.multiplicity) {
        const int v = val_at((unsigned)idx);
        const std::uint64_t uv = (std::uint64_t)(v < 0 ? -v : v);
        s = lp_add(s, lp_mul(m % LP, lp_inv(lp_denom(b.alpha, idx, uv))));
    }
    return s;
}
inline bool balanced(const LogUpBatch& b, std::uint64_t table_sum) {
    return b.lookup_sum == table_sum;
}

} // namespace hsma::pouw::logup
