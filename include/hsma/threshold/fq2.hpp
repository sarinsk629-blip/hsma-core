// HSMA :: threshold/fq2.hpp — F_q2 = F_q[u]/(u²-β), β=5 (DEC-193..).
// Elements: (c0, c1) = c0 + c1·u. All ops take (QC, beta_m) explicitly.
// β discovered by generator (smallest non-square); b'=(5,1) twist coefficient.
// Mont engine reused from Step 8 (mont384). DEC-127 aggregate-init; DEC-090.
#pragma once
#include <hsma/threshold/mont384.hpp>

namespace hsma::threshold {

struct Fq2 {
    mont::fe6 c0{}, c1{};  // value = c0 + c1·u, u² = β
};

inline Fq2 fq2_add(const mont::MCtx& Q, const Fq2& a, const Fq2& b) {
    Fq2 r; r.c0 = mont::madd(Q, a.c0, b.c0); r.c1 = mont::madd(Q, a.c1, b.c1);
    return r;
}
inline Fq2 fq2_sub(const mont::MCtx& Q, const Fq2& a, const Fq2& b) {
    Fq2 r; r.c0 = mont::msub(Q, a.c0, b.c0); r.c1 = mont::msub(Q, a.c1, b.c1);
    return r;
}
inline Fq2 fq2_neg(const mont::MCtx& Q, const Fq2& a) {
    Fq2 r;
    mont::fe6 z{}; // zero
    r.c0 = mont::msub(Q, z, a.c0); r.c1 = mont::msub(Q, z, a.c1);
    return r;
}
inline Fq2 fq2_mul(const mont::MCtx& Q, const Fq2& a, const Fq2& b,
                   const mont::fe6& beta_m) {
    // (a0+a1·u)(b0+b1·u) = (a0·b0 + β·a1·b1) + (a0·b1 + a1·b0)·u
    const mont::fe6 t0 = mont::mmul(Q, a.c0, b.c0);
    const mont::fe6 t1 = mont::mmul(Q, a.c1, b.c1);
    const mont::fe6 t2 = mont::mmul(Q, a.c0, b.c1);
    const mont::fe6 t3 = mont::mmul(Q, a.c1, b.c0);
    const mont::fe6 bt1 = mont::mmul(Q, beta_m, t1);
    Fq2 r;
    r.c0 = mont::madd(Q, t0, bt1);
    r.c1 = mont::madd(Q, t2, t3);
    return r;
}
inline Fq2 fq2_sqr(const mont::MCtx& Q, const Fq2& a, const mont::fe6& beta_m) {
    return fq2_mul(Q, a, a, beta_m);
}
inline Fq2 fq2_conj(const Fq2& a) {
    Fq2 r; r.c0 = a.c0; r.c1 = mont::bn_isz(a.c1.data(), 6)
        ? a.c1 : mont::msub(mont::MCtx{}, mont::fe6{}, a.c1); // placeholder
    return r;
}
inline Fq2 fq2_conj(const mont::MCtx& Q, const Fq2& a) {
    Fq2 r; r.c0 = a.c0;
    mont::fe6 z{};
    r.c1 = mont::msub(Q, z, a.c1);
    return r;
}
inline mont::fe6 fq2_norm(const mont::MCtx& Q, const Fq2& a,
                          const mont::fe6& beta_m) {
    // N(a) = a·conj(a) = c0² - β·c1² ∈ F_q
    const mont::fe6 c0s = mont::mmul(Q, a.c0, a.c0);
    const mont::fe6 c1s = mont::mmul(Q, a.c1, a.c1);
    const mont::fe6 bc1s = mont::mmul(Q, beta_m, c1s);
    return mont::msub(Q, c0s, bc1s);
}
inline Fq2 fq2_inv(const mont::MCtx& Q, const Fq2& a, const mont::fe6& beta_m) {
    const mont::fe6 n = fq2_norm(Q, a, beta_m);
    // n is a nonzero F_q element; inverse via Fermat: n^(q-2)
    const mont::fe6 qm2 = g1::ctx().m2;  // q-2 (already canonical in g1 ctx)
    const mont::fe6 ni = mont::mpow(Q, n, qm2);
    Fq2 c = fq2_conj(Q, a);
    Fq2 r;
    r.c0 = mont::mmul(Q, c.c0, ni);
    r.c1 = mont::mmul(Q, c.c1, ni);
    return r;
}
inline bool fq2_eq(const Fq2& a, const Fq2& b) {
    return mont::bn_cmp(a.c0.data(), b.c0.data(), 6) == 0 &&
           mont::bn_cmp(a.c1.data(), b.c1.data(), 6) == 0;
}
inline bool fq2_is_zero(const Fq2& a) {
    return mont::bn_isz(a.c0.data(), 6) && mont::bn_isz(a.c1.data(), 6);
}
inline Fq2 fq2_from_canon(const mont::MCtx& Q, const std::uint64_t c0[6],
                          const std::uint64_t c1[6]) {
    Fq2 r;
    mont::fe6 a{}, b{};
    mont::bn_cpy(a.data(), c0, 6); mont::bn_cpy(b.data(), c1, 6);
    r.c0 = mont::mfrom(Q, a); r.c1 = mont::mfrom(Q, b);
    return r;
}

} // namespace hsma::threshold
