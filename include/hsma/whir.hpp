// HSMA :: whir.hpp - P1-10 (GAP-05 Layer 2, DEC-228).
// WHIR-class wrap: T1 = pcs::open_1; K=8 OOD points tau_{j,w} =
// sha256("HSMA_WHIR_TAU|j|w" || C_canonical_le) reduced mod p; ood_j = f(tau_j);
// ood_commit = Sponge(ood); w_j = sha256("HSMA_WHIR_W|j" || ood_commit_le);
// T2 = pcs::open_2(f, Wbar), Wbar = sum_j w_j*eq(tau_j,.).
// VERIFIER (no witness): T1 chain | v==fa | ood_commit re-derive |
// T2 chain | T2.fb == sum_j w_j*eq(tau_j, r2)  (linearity: the fold of the
// batch equals the batch of folds; eq(.,r2) is O(nv) per point).
// HONEST BOUNDARY: ood-consistency with f is structural here; the final
// soundness anchor (binding f itself) lands at GAP-06's Pedersen integration
// - DEC-071's layering: Pedersen binds, WHIR wraps.
#pragma once
#include <hsma/pcs.hpp>
#include <hsma/sha256.hpp>
#include <vector>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace hsma::whir {

inline constexpr unsigned K_OOD = 8u;

// canonical-limb helpers: digest < 2^256, p ~ 2^254.4 -> <= 4 subtracts
inline bool can_geq_p(const std::array<std::uint64_t,4>& c) noexcept {
    const std::uint64_t P[4] = {0x8c46eb2100000001ull, 0x224698fc0994a8ddull, 0ull, 0x4000000000000000ull};
    for (int i = 3; i >= 0; --i) if (c[i] != P[i]) return c[i] > P[i];
    return true;
}
inline std::array<std::uint64_t,4> can_sub_p(const std::array<std::uint64_t,4>& c) noexcept {
    const std::uint64_t P[4] = {0x8c46eb2100000001ull, 0x224698fc0994a8ddull, 0ull, 0x4000000000000000ull};
    std::array<std::uint64_t,4> r{}; std::uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t bi = P[i] + borrow;
        if (c[i] >= bi) { r[i] = c[i] - bi; borrow = 0; }
        else { r[i] = c[i] - bi; borrow = 1; }
    }
    return r;
}
inline fp::fe digest_scalar(const std::uint8_t dg[32]) noexcept {
    std::array<std::uint64_t,4> l{};
    for (int b = 0; b < 4; ++b)
        for (int by = 0; by < 8; ++by) l[b] |= (std::uint64_t)dg[8*b + by] << (8*by);
    for (int t = 0; t < 8 && can_geq_p(l); ++t) l = can_sub_p(l);
    return fp::fe_from_canonical_limbs(l);
}
inline void sha_cat(const char* a, const std::byte* b32, std::uint8_t out[32]) noexcept {
    std::uint8_t msg[128];
    const std::size_t la = std::strlen(a);
    std::memcpy(msg, a, la);
    std::memcpy(msg + la, b32, 32);
    digest::sha256(msg, la + 32, out);
}
inline std::vector<fp::fe> eq_table(const std::vector<fp::fe>& tau) noexcept {
    // CA-R133 bit-order contract: tau[0] binds the HIGH bit (the emitter's
    // append-block construction pins it; the orientation probe proved it:
    // reversed == golden bit-exact). Equivalently: the LAST tau coordinate
    // occupies the LOW bit of the table index.
    std::vector<fp::fe> e{fp::fe_one()};
    for (unsigned i = 0; i < tau.size(); ++i) {
        std::vector<fp::fe> n(1u << (i + 1));
        const fp::fe t   = tau[tau.size() - 1 - i];
        const fp::fe omr = fp::fe_sub(fp::fe_one(), t);
        for (std::size_t j = 0; j < e.size(); ++j) {
            n[2*j]   = fp::fe_mul(e[j], omr);
            n[2*j+1] = fp::fe_mul(e[j], t);
        }
        e.swap(n);
    }
    return e;
}
inline fp::fe ood_eval(const std::vector<fp::fe>& f, const std::vector<fp::fe>& tau) noexcept {
    const std::vector<fp::fe> e = eq_table(tau);   // size == f.size() by construction
    fp::fe acc = fp::fe_zero();
    for (std::size_t i = 0; i < f.size(); ++i) acc = fp::fe_add(acc, fp::fe_mul(e[i], f[i]));
    return acc;
}
// eq(tau, r): the O(nv) point-evaluation of the eq MLE
inline fp::fe eq_point(const std::vector<fp::fe>& tau, const std::vector<fp::fe>& r) noexcept {
    fp::fe acc = fp::fe_one();
    for (unsigned i = 0; i < r.size(); ++i) {
        const fp::fe omr  = fp::fe_sub(fp::fe_one(), r[i]);
        const fp::fe omt  = fp::fe_sub(fp::fe_one(), tau[i]);
        acc = fp::fe_mul(acc, fp::fe_add(fp::fe_mul(omr, omt), fp::fe_mul(r[i], tau[i])));
    }
    return acc;
}

struct Proof {
    fp::fe C{}, ood_commit{}, C2{}, v{}, fb_true{};
    pcs::Opening T1{}, T2{};
    std::vector<std::vector<fp::fe>> tau;          // K_OOD x nv
    std::array<fp::fe, K_OOD> ood{};
};

inline Proof wrap_open(const std::vector<fp::fe>& evals) noexcept {
    const unsigned nv = evals.empty() ? 0u
                      : unsigned(evals.size() == 1 ? 0 : 31 - __builtin_clz(evals.size()));
    Proof P;
    P.C  = pcs::commit(evals);
    P.T1 = pcs::open_1(evals);
    P.v  = P.T1.fa;
    std::byte cb[32]; fp::fe_to_le_bytes(P.C, cb);   // CA-R132: le_bytes canonicalizes internally;
    P.tau.assign(K_OOD, {});
    for (unsigned j = 0; j < K_OOD; ++j) {
        char lab[48];
        for (unsigned w = 0; w < nv; ++w) {
            std::snprintf(lab, sizeof(lab), "HSMA_WHIR_TAU|%u|%u", j, w);
            std::uint8_t dg[32]; sha_cat(lab, cb, dg);
            P.tau[j].push_back(digest_scalar(dg));
        }
        P.ood[j] = ood_eval(evals, P.tau[j]);
    }
    {
        fp::Sponge sp(dom::Dom::HSM_SUMCHECK_v1);
        for (unsigned j = 0; j < K_OOD; ++j) sp.absorb(P.ood[j]);
        P.ood_commit = sp.squeeze();
    }
    std::byte ob[32]; fp::fe_to_le_bytes(P.ood_commit, ob);   // CA-R132: never pre-canonicalize;
    std::vector<fp::fe> w(K_OOD);
    for (unsigned j = 0; j < K_OOD; ++j) {
        char lab[48]; std::snprintf(lab, sizeof(lab), "HSMA_WHIR_W|%u", j);
        std::uint8_t dg[32]; sha_cat(lab, ob, dg);
        w[j] = digest_scalar(dg);
    }
    std::vector<fp::fe> Wbar(evals.size(), fp::fe_zero());
    for (unsigned j = 0; j < K_OOD; ++j) {
        const std::vector<fp::fe> e = eq_table(P.tau[j]);
        for (std::size_t i = 0; i < Wbar.size(); ++i)
            Wbar[i] = fp::fe_add(Wbar[i], fp::fe_mul(w[j], e[i]));
    }
    {   // CA-R132: open_2 commits the CORPUS internally; P.C2 must store the
        // SAME value or the verifier derives T2 challenges from a zero C2.
        std::vector<fp::fe> corpus(evals);
        corpus.insert(corpus.end(), Wbar.begin(), Wbar.end());
        P.C2 = pcs::commit(corpus);
    }
    P.T2 = pcs::open_2(evals, Wbar);
    {
        const std::vector<fp::fe> ch = pcs::derive_points(P.C2, nv);
        std::vector<fp::fe> Wc = Wbar;
        for (unsigned i = 0; i < nv; ++i) {
            const std::size_t h = Wc.size() / 2;
            const fp::fe omr = fp::fe_sub(fp::fe_one(), ch[i]);
            for (std::size_t j2 = 0; j2 < h; ++j2)
                Wc[j2] = fp::fe_add(fp::fe_mul(Wc[2*j2], omr), fp::fe_mul(Wc[2*j2+1], ch[i]));
            Wc.resize(h);
        }
        P.fb_true = Wc.empty() ? fp::fe_zero() : Wc[0];
    }
    return P;
}

// verifier: no witness. stage ids: 1 T1-chain, 2 v==fa, 3 ood_commit,
// 4 T2-chain, 5 the independent fb identity.
inline bool wrap_verify(const Proof& P, unsigned nv, unsigned* stage) noexcept {
    *stage = 0;
    if (pcs::verify(P.T1, P.C) != nv) { *stage = 1; return false; }
    if (!sc::feq(P.v, P.T1.fa))       { *stage = 2; return false; }
    {
        fp::Sponge sp(dom::Dom::HSM_SUMCHECK_v1);
        for (unsigned j = 0; j < K_OOD; ++j) sp.absorb(P.ood[j]);
        if (!sc::feq(sp.squeeze(), P.ood_commit)) { *stage = 3; return false; }
    }
    if (pcs::verify(P.T2, P.C2) != nv) { *stage = 4; return false; }
    {   // the independent fb: tau from C, w from ood_commit, r2 from C2 - all ours
        std::byte cb[32]; fp::fe_to_le_bytes(P.C, cb);   // CA-R132: le_bytes canonicalizes internally;
        std::byte ob[32]; fp::fe_to_le_bytes(P.ood_commit, ob);   // CA-R132: never pre-canonicalize;
        const std::vector<fp::fe> r2 = pcs::derive_points(P.C2, nv);
        fp::fe fbv = fp::fe_zero();
        for (unsigned j = 0; j < K_OOD; ++j) {
            std::vector<fp::fe> tj;
            for (unsigned w2 = 0; w2 < nv; ++w2) {
                char lab[48]; std::snprintf(lab, sizeof(lab), "HSMA_WHIR_TAU|%u|%u", j, w2);
                std::uint8_t dg[32]; sha_cat(lab, cb, dg);
                tj.push_back(digest_scalar(dg));
            }
            char lab2[48]; std::snprintf(lab2, sizeof(lab2), "HSMA_WHIR_W|%u", j);
            std::uint8_t dg2[32]; sha_cat(lab2, ob, dg2);
            fbv = fp::fe_add(fbv, fp::fe_mul(digest_scalar(dg2), eq_point(tj, r2)));
        }
        if (!sc::feq(P.T2.fb, fbv)) { *stage = 5; return false; }
    }
    return true;
}

} // namespace hsma::whir
