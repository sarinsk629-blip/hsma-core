// HSMA :: pcs.hpp — the Phase-0 multilinear PCS (Step 20, DEC-213).
// Commit C = Sponge(HSM_SUMCHECK_v1, evals).squeeze() — bit-exact with the
// Python sponge_ref (poseidon_golden-proven across 19 steps). Point
// derivation r_i = P3(SC, C, i) — verifier-derivable from C alone. Open =
// the Step-19 fold machinery at the FIXED r (LSB-first, CA-R78; d=2 products,
// CA-R79; p2 = g(2), CA-R80). Verify = Step-19 round checks + Lagrange@{0,1,2}
// (INV2 golden-pinned). NOT homomorphic, NOT hiding — the production dual-layer
// (Pedersen homomorphic + WHIR wrap, DEC-063/071) is deferred; this layer's
// transcript machinery and check structure are production-faithful.
// DEC-090; DEC-127; CA-R77-compliant.
#pragma once
#include <hsma/poseidon.hpp>
#include <hsma/sumcheck.hpp>
#include <vector>
#include <array>
#include <cstdint>

namespace hsma::pcs {

inline fp::fe commit(const std::vector<fp::fe>& evals) {
    fp::Sponge sp(dom::Dom::HSM_SUMCHECK_v1);
    for (const auto& e : evals) sp.absorb(e);
    return sp.squeeze();
}
inline std::vector<fp::fe> derive_points(const fp::fe& C, unsigned nv) {
    std::vector<fp::fe> r;
    r.reserve(nv);
    for (unsigned i = 0; i < nv; ++i)
        r.push_back(poseidon3(dom::Dom::HSM_SUMCHECK_v1, C, fp::fe_from_u64(i)));
    return r;
}

struct Opening {
    unsigned nv{}, d{};
    std::vector<fp::fe> claims;                // nv + 1
    std::vector<std::array<fp::fe, 3>> evals;  // per round; [2] == 0 for d=1
    fp::fe fa{}, fb{};                         // final MLE evals
    // the fixed point is recomputed from C by the verifier — not stored
};

inline Opening open_1(const std::vector<fp::fe>& a_in) {
    Opening O; O.nv = unsigned(a_in.size() == 0 ? 0 : 0);
    const fp::fe C = commit(a_in);
    const auto r = derive_points(C, a_in.empty() ? 0u
                          : unsigned(a_in.size() == 1 ? 0 : 31 - __builtin_clz(a_in.size())));
    O.nv = unsigned(r.size()); O.d = 1;
    fp::fe c = fp::fe_zero();
    for (const auto& v : a_in) c = fe_add(c, v);
    O.claims.push_back(c);
    std::vector<fp::fe> a = a_in;
    for (unsigned i = 0; i < O.nv; ++i) {
        const std::size_t h = a.size() / 2;
        fp::fe p0 = fp::fe_zero(), p1 = fp::fe_zero();
        for (std::size_t j = 0; j < h; ++j) { p0 = fe_add(p0, a[2*j]); p1 = fe_add(p1, a[2*j+1]); }
        const fp::fe omr = fe_sub(fp::fe_one(), r[i]);
        O.evals.push_back({p0, p1, fp::fe_zero()});
        O.claims.push_back(fe_add(fe_mul(p0, omr), fe_mul(p1, r[i])));
        for (std::size_t j = 0; j < h; ++j)
            a[j] = fe_add(fe_mul(a[2*j], omr), fe_mul(a[2*j+1], r[i]));
        a.resize(h);
    }
    O.fa = a.empty() ? fp::fe_zero() : a[0];
    return O;
}

inline Opening open_2(const std::vector<fp::fe>& a_in, const std::vector<fp::fe>& b_in) {
    std::vector<fp::fe> corpus = a_in;
    corpus.insert(corpus.end(), b_in.begin(), b_in.end());
    const fp::fe C = commit(corpus);
    const unsigned nv = unsigned(a_in.size() == 1 ? 0 : 31 - __builtin_clz(a_in.size()));
    const auto r = derive_points(C, nv);
    Opening O; O.nv = nv; O.d = 2;
    fp::fe c = fp::fe_zero();
    for (std::size_t i = 0; i < a_in.size(); ++i) c = fe_add(c, fe_mul(a_in[i], b_in[i]));
    O.claims.push_back(c);
    std::vector<fp::fe> a = a_in, b = b_in;
    for (unsigned i = 0; i < nv; ++i) {
        const std::size_t h = a.size() / 2;
        fp::fe p0 = fp::fe_zero(), p1 = fp::fe_zero(), p2 = fp::fe_zero();
        for (std::size_t j = 0; j < h; ++j) {
            p0 = fe_add(p0, fe_mul(a[2*j], b[2*j]));
            p1 = fe_add(p1, fe_mul(a[2*j+1], b[2*j+1]));
            const fp::fe a2 = fe_sub(fe_add(a[2*j+1], a[2*j+1]), a[2*j]);   // A_j(2), CA-R80
            const fp::fe b2 = fe_sub(fe_add(b[2*j+1], b[2*j+1]), b[2*j]);
            p2 = fe_add(p2, fe_mul(a2, b2));
        }
        const fp::fe omr = fe_sub(fp::fe_one(), r[i]);
        O.evals.push_back({p0, p1, p2});
        O.claims.push_back(sc::lag2(r[i], p0, p1, p2));
        for (std::size_t j = 0; j < h; ++j) {
            a[j] = fe_add(fe_mul(a[2*j], omr), fe_mul(a[2*j+1], r[i]));
            b[j] = fe_add(fe_mul(b[2*j], omr), fe_mul(b[2*j+1], r[i]));
        }
        a.resize(h); b.resize(h);
    }
    O.fa = a.empty() ? fp::fe_zero() : a[0];
    O.fb = b.empty() ? fp::fe_zero() : b[0];
    return O;
}

// verify: C is recomputed by the caller (binding), r derived from C (SC law).
// Returns the failing round (nv == ACCEPT); 0 = initial-claim failure.
// Final-mismatch sentinel: distinguishes rejection-at-final (0xFFFFFFFF)
// from ACCEPT (== nv). Rounds fail at 0..nv-1. (CA-R82: C is used only for
// point derivation - claims[0] is the sum, never the commitment.)
inline constexpr unsigned PCS_REJECT_FINAL = 0xFFFFFFFFu;
inline unsigned verify(const Opening& O, const fp::fe& C) {
    if (O.claims.empty()) return 0u;
    const auto r = derive_points(C, O.nv);
    for (unsigned i = 0; i < O.nv; ++i) {
        if (!sc::feq(fe_add(O.evals[i][0], O.evals[i][1]), O.claims[i])) return i;
        fp::fe nc;
        if (O.d == 1u)
            nc = fe_add(fe_mul(O.evals[i][0], fe_sub(fp::fe_one(), r[i])),
                        fe_mul(O.evals[i][1], r[i]));
        else
            nc = sc::lag2(r[i], O.evals[i][0], O.evals[i][1], O.evals[i][2]);
        if (!sc::feq(nc, O.claims[i + 1])) return i;
    }
    const fp::fe fin = (O.d == 1u) ? O.fa : fe_mul(O.fa, O.fb);
    if (!sc::feq(fin, O.claims[O.nv])) return PCS_REJECT_FINAL;
    return O.nv;
}

} // namespace hsma::pcs
