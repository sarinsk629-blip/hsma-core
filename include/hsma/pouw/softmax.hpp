#pragma once
// HSMA :: pouw/softmax.hpp - Phase 6.14 CLOSE (DEC-s5): the P_h producer.
//
// THE FENCE, CLOSED. attention.hpp (6.19 rung-1) took P_h — the post-softmax
// weights — as a raw INPUT. This header is the certified producer the fence
// was waiting for: an integer-domain (DEC-090) softmax whose every table
// lookup rides the LogUp multiset argument (P5-F core), so a fake table
// value is detectable, not just wrong.
//
// THE Q-DOMAIN CONTRACT (in writing, enforced where it can be):
//   * Q_h, K_h entries are q7 fixed-point (real*128), canonical field
//     values < 2^15. Then S_h = Q_h·K_h^T entries are q14 with true
//     integer value < seq·2^30 ≪ p — NO modular wraparound, the canonical
//     representative IS the fixed-point integer. softmax_rows checks
//     every entry < 2^52 and fails loudly otherwise (contract, not hope;
//     u64-safe headroom over the q14 domain).
//   * Row-max shift: diff = max - s >= 0 in TRUE integers. The exp window:
//     table[i] = exp(i/32 - 8) covers exp(-y) for y = diff/2^14 in (0, 8];
//     index i = 256 - (diff >> 9) clamped to [0, 255]. The row-max itself
//     (diff == 0) takes the IDENTITY exp(0) = 1 -> q7 128 — the one exact
//     point the 256-entry table cannot sample (its domain edge), documented
//     since step48.
//   * Division rides RCP (step49): D = sum of the row's q7 exp values;
//     D <= RCP_MAX(1024) is the EXACT rung -> seq <= 8 for worst-case rows
//     (every row sums to <= 128·seq). The node's mint rung (n=8) fits
//     exactly. Larger seq = scale work, registered (P1-13 class), not
//     claimed here.
//   * P_i = (E_i · rcp[D]) >> 14 — q7 out, row sums ~ 128 (q7 of 1.0)
//     with bounded quantization drift (test_step59 pins it vs the oracle).
//
// THE EXTENDED BATCH TYPE (the 6.14 roadmap item): SoftmaxBatch — ONE
// softmax's full lookup trace as TWO LogUp sides (exp table + RCP table),
// balanced against both certified tables. A softmax is only certified when
// BOTH sides balance; anything else is a rejected batch.
#include <hsma/fe.hpp>
#include <hsma/pouw/logup.hpp>
#include <cstdint>
#include <cstddef>
#include <vector>

namespace hsma::pouw::softmax {

using logup::OUT_ONE;
using logup::RCP_MAX;

// canonical field -> true u64 (the q-domain extractor). Values >= 2^64 or
// non-representable return with ok=false — the caller's contract check.
struct FeU64 { bool ok; std::uint64_t v; };
inline FeU64 fe_u64(const fp::fe& x) noexcept {
    const fp::fe c = fp::fe_to_canonical(x);
    if (c.l[1] != 0 || c.l[2] != 0 || c.l[3] != 0) return {false, 0};
    return {true, c.l[0]};
}

// THE EXTENDED BATCH TYPE (6.14): one softmax's trace, two certified sides.
struct SoftmaxBatch {
    logup::LogUpBatch exp;   // exp_shifted-table lookups
    logup::LogUpBatch rcp;   // RCP-table lookups (one per row)
    explicit SoftmaxBatch(std::uint64_t alpha)
        : exp(alpha * 2 + 1), rcp(alpha * 2 + 2) {}
    void add_exp(unsigned idx, int val) { exp.add_lookup(idx, val); }
    void add_rcp(unsigned idx, int val) { rcp.add_lookup(idx, val); }
    template <typename ExpAt, typename RcpAt>
    bool balanced(ExpAt exp_at, RcpAt rcp_at) const {
        return logup::balanced(exp, logup::table_side_sum(exp, exp_at))
            && logup::balanced(rcp, logup::table_side_sum(rcp, rcp_at));
    }
};

struct SoftmaxResult {
    bool ok = false;
    std::vector<int> P;               // q7 post-softmax weights (seq*seq)
    std::size_t bad_entry = 0;        // first contract violation (u64 extract)
    std::uint64_t denom = 0;          // D, the q7 exp sum (the RCP argument)
};

// THE PRODUCER. S is seq*seq row-major over the Pallas field (the proven
// score-leg outputs). Tables come from logup_ref::build_all() — certified
// 0-LSB at construction. audit (optional) receives the full lookup trace.
inline SoftmaxResult softmax_rows(const std::vector<fp::fe>& S, unsigned seq,
                                  const logup::Tables& T,
                                  SoftmaxBatch* audit = nullptr) noexcept {
    SoftmaxResult R;
    if (seq == 0 || S.size() != (std::size_t)seq * seq) return R;
    const auto& E = T.exp_shifted;
    const auto& RCPT = T.rcp;
    std::vector<std::uint64_t> sq((std::size_t)seq * seq, 0);
    for (unsigned k = 0; k < seq * seq; ++k) {
        const auto e = fe_u64(S[k]);
        if (!e.ok || e.v >= (1ull << 52)) { R.bad_entry = k; return R; }  // contract
        sq[k] = e.v;
    }
    R.P.assign((std::size_t)seq * seq, 0);
    for (unsigned r = 0; r < seq; ++r) {
        const std::size_t base = (std::size_t)r * seq;
        std::uint64_t m = 0;
        for (unsigned j = 0; j < seq; ++j) if (sq[base + j] > m) m = sq[base + j];
        std::uint64_t D = 0;
        std::vector<int> Er(seq, 0);
        for (unsigned j = 0; j < seq; ++j) {
            const std::uint64_t diff = m - sq[base + j];       // true integer, >= 0
            std::uint64_t i256 = 256 - (diff >> 9);            // exp(-diff/2^14)
            if (i256 > 255) i256 = 0;                          // past the window (u64 wrap-safe)
            const int ev = (diff == 0) ? OUT_ONE                // identity exp(0)=1
                                       : logup::lookup_by_index(E, (unsigned)i256);
            if (audit) audit->add_exp(diff == 0 ? 256u : (unsigned)i256, ev);
            Er[j] = ev;
            D += (std::uint64_t)ev;
        }
        if (D == 0 || D > RCP_MAX) return R;                    // exact-rung contract
        const int rc = logup::rcp_lookup(RCPT, (unsigned)D);
        if (rc == 0) return R;
        if (audit) audit->add_rcp((unsigned)D, rc);
        // P_i = (E_i · rcp[D]) >> 7 — the q7 factors of E and D cancel in the
        // quotient, so ONE extra 2^7 must survive: P_q7 = (E/D)·2^7. The >>14
        // form would yield the dimensionless real and quantize a uniform row
        // to 0 (caught in test_step59's row-sum law).
        for (unsigned j = 0; j < seq; ++j)
            R.P[base + j] = (int)(((std::uint64_t)Er[j] * (std::uint64_t)rc) >> 7);
    }
    R.ok = true;
    return R;
}

// the audit-batch table accessors (pass to SoftmaxBatch::balanced).
inline int exp_at(const logup::Tables& T, unsigned idx) {
    return (idx == 256u) ? OUT_ONE
                         : logup::lookup_by_index(T.exp_shifted, idx);
}
inline int rcp_at(const logup::Tables& T, unsigned idx) {
    return logup::rcp_lookup(T.rcp, idx);
}

} // namespace hsma::pouw::softmax
