// HSMA :: sumcheck.hpp — the sum-check engine (Step 19, DEC-212).
// Dense MLEs over the Pallas field; degree d in {1,2} (single MLE / product).
// Round i binds variable i (LSB-first: variable v <=> bit v, CA-R78).
// d=1: p0 = sum A[2j], p1 = sum A[2j+1]. d=2: p0 = sum A[2j]B[2j],
// p1 = sum A[2j+1]B[2j+1] (CA-R79); p2 = sum (2A[2j+1]-A[2j])(2B[2j+1]-B[2j]) = g(2) (CA-R80).
// FS transcript = chained Poseidon over the registry domain HSM_SUMCHECK_v1:
//   t = P3(p0,p1) [+ P3(t,p2) for d=2]; r_i = P3(t, claim_i).
// Verifier: p0+p1 == claim_i; claim_{i+1} = Lagrange@{0,1,2} (INV2 golden-pinned,
// DEC-102); final fa (d=1) / fa*fb (d=2) == claim_nv. Dual-path direct MLE eval
// is the engine's own machine check. DEC-090; DEC-127; CA-R77-compliant inputs.
#pragma once
#include <hsma/poseidon.hpp>
#include <sumcheck_golden.hpp>
#include <vector>
#include <array>
#include <cstdint>

namespace hsma::sc {

struct Transcript {
    unsigned nv{}, d{};
    std::vector<fp::fe> claims;                // nv + 1
    std::vector<std::array<fp::fe, 3>> evals;  // per round; [2] == 0 for d=1
    std::vector<fp::fe> r;                     // nv
    fp::fe fa{}, fb{};                         // final MLE evals
};

inline bool feq(const fp::fe& a, const fp::fe& b) { return a.l == b.l; }
inline fp::fe p3(const fp::fe& l, const fp::fe& r) {
    return poseidon3(dom::Dom::HSM_SUMCHECK_v1, l, r);
}
inline fp::fe chal(const fp::fe& p0, const fp::fe& p1, const fp::fe& p2,
                   unsigned d, const fp::fe& claim) {
    fp::fe t = p3(p0, p1);
    if (d == 2u) t = p3(t, p2);
    return p3(t, claim);
}
inline fp::fe inv2() {
    return fp::fe_from_canonical_limbs(std::array<std::uint64_t, 4>{
        golden::G19S_INV2[0], golden::G19S_INV2[1],
        golden::G19S_INV2[2], golden::G19S_INV2[3]});
}
inline fp::fe lag2(const fp::fe& r, const fp::fe& p0, const fp::fe& p1, const fp::fe& p2) {
    const fp::fe i2 = inv2();
    const fp::fe rm1 = fe_sub(r, fp::fe_one());
    const fp::fe rm2 = fe_sub(r, fp::fe_from_u64(2));
    const fp::fe L0 = fe_mul(fe_mul(rm1, rm2), i2);
    const fp::fe L1 = fe_mul(r, fe_sub(fp::fe_from_u64(2), r));
    const fp::fe L2 = fe_mul(fe_mul(r, rm1), i2);
    return fe_add(fe_add(fe_mul(p0, L0), fe_mul(p1, L1)), fe_mul(p2, L2));
}

inline Transcript prove_1(unsigned nv, const std::vector<fp::fe>& a_in) {
    Transcript T; T.nv = nv; T.d = 1;
    fp::fe c = fp::fe_zero();
    for (const auto& v : a_in) c = fe_add(c, v);
    T.claims.push_back(c);
    std::vector<fp::fe> a = a_in;
    for (unsigned i = 0; i < nv; ++i) {
        const std::size_t h = a.size() / 2;
        fp::fe p0 = fp::fe_zero(), p1 = fp::fe_zero();
        for (std::size_t j = 0; j < h; ++j) { p0 = fe_add(p0, a[2*j]); p1 = fe_add(p1, a[2*j+1]); }
        const fp::fe r = chal(p0, p1, fp::fe_zero(), 1u, T.claims.back());
        const fp::fe omr = fe_sub(fp::fe_one(), r);
        T.evals.push_back({p0, p1, fp::fe_zero()});
        T.r.push_back(r);
        T.claims.push_back(fe_add(fe_mul(p0, omr), fe_mul(p1, r)));
        for (std::size_t j = 0; j < h; ++j)
            a[j] = fe_add(fe_mul(a[2*j], omr), fe_mul(a[2*j+1], r));
        a.resize(h);
    }
    T.fa = a[0];
    return T;
}

inline Transcript prove_2(unsigned nv, const std::vector<fp::fe>& a_in,
                          const std::vector<fp::fe>& b_in) {
    Transcript T; T.nv = nv; T.d = 2;
    fp::fe c = fp::fe_zero();
    for (std::size_t i = 0; i < a_in.size(); ++i) c = fe_add(c, fe_mul(a_in[i], b_in[i]));
    T.claims.push_back(c);
    std::vector<fp::fe> a = a_in, b = b_in;
    for (unsigned i = 0; i < nv; ++i) {
        const std::size_t h = a.size() / 2;
        fp::fe p0 = fp::fe_zero(), p1 = fp::fe_zero(), p2 = fp::fe_zero();
        for (std::size_t j = 0; j < h; ++j) {
            p0 = fe_add(p0, fe_mul(a[2*j], b[2*j]));
            p1 = fe_add(p1, fe_mul(a[2*j+1], b[2*j+1]));
            const fp::fe a2 = fe_sub(fe_add(a[2*j+1], a[2*j+1]), a[2*j]);
            const fp::fe b2 = fe_sub(fe_add(b[2*j+1], b[2*j+1]), b[2*j]);
            p2 = fe_add(p2, fe_mul(a2, b2));
        }
        const fp::fe r = chal(p0, p1, p2, 2u, T.claims.back());
        const fp::fe omr = fe_sub(fp::fe_one(), r);
        T.evals.push_back({p0, p1, p2});
        T.r.push_back(r);
        T.claims.push_back(lag2(r, p0, p1, p2));
        for (std::size_t j = 0; j < h; ++j) {
            a[j] = fe_add(fe_mul(a[2*j], omr), fe_mul(a[2*j+1], r));
            b[j] = fe_add(fe_mul(b[2*j], omr), fe_mul(b[2*j+1], r));
        }
        a.resize(h); b.resize(h);
    }
    T.fa = a[0]; T.fb = b[0];
    return T;
}

// Returns the failing round (nv == ACCEPT); 0 = initial-claim failure.
inline unsigned verify(const Transcript& T, const fp::fe& C) {
    if (!feq(T.claims[0], C)) return 0u;
    for (unsigned i = 0; i < T.nv; ++i) {
        if (!feq(fe_add(T.evals[i][0], T.evals[i][1]), T.claims[i])) return i;
        const fp::fe re = chal(T.evals[i][0], T.evals[i][1], T.evals[i][2], T.d, T.claims[i]);
        if (!feq(re, T.r[i])) return i;
        fp::fe nc;
        if (T.d == 1u)
            nc = fe_add(fe_mul(T.evals[i][0], fe_sub(fp::fe_one(), T.r[i])),
                        fe_mul(T.evals[i][1], T.r[i]));
        else
            nc = lag2(T.r[i], T.evals[i][0], T.evals[i][1], T.evals[i][2]);
        if (!feq(nc, T.claims[i + 1])) return i;
    }
    const fp::fe fin = (T.d == 1u) ? T.fa : fe_mul(T.fa, T.fb);
    if (!feq(fin, T.claims[T.nv])) return T.nv;
    return T.nv;
}

inline fp::fe direct_eval(const std::vector<fp::fe>& arr, const std::vector<fp::fe>& r) {
    fp::fe tot = fp::fe_zero();
    const unsigned nv = unsigned(r.size());
    for (std::size_t idx = 0; idx < arr.size(); ++idx) {
        fp::fe w = fp::fe_one();
        for (unsigned v = 0; v < nv; ++v) {
            const unsigned bit = unsigned((idx >> v) & 1u);
            w = fe_mul(w, bit ? r[v] : fe_sub(fp::fe_one(), r[v]));
        }
        tot = fe_add(tot, fe_mul(arr[idx], w));
    }
    return tot;
}

} // namespace hsma::sc
