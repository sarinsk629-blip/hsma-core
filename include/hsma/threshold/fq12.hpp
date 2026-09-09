// HSMA :: threshold/fq12.hpp — F_q6 = F_q2[v]/(v^3-gamma), F_q12 = F_q6[w]/(w^2-v) (DEC-197)
// gamma = b' = (5,1) (blsq2::G2_B2); v = (0,1,0); w^6 = gamma. Mirrors the Python oracle
// EXACTLY: Fq12 = (e0,e1), Fq6 = (c0,c1,c2). Inverses: tower-norm chain (the perf law).
// DEC-127 aggregate-init; DEC-090 integer-only.
#pragma once
#include <hsma/threshold/g2.hpp>

namespace hsma::threshold {

struct Fq6  { Fq2 c0{}, c1{}, c2{}; };
struct Fq12 { Fq6  e0{}, e1{}; };

namespace fq12d {
    inline const mont::MCtx& Q() { return g1::ctx().m; }
    inline const mont::fe6&  B() { return g2::ctx().beta_m; }
    inline const Fq2&        G() { return g2::ctx().b2; }   // gamma = (5,1)
}

inline Fq2 fq2_one()      { Fq2 o{}; o.c0 = fq12d::Q().r1; return o; }
inline Fq2 fq2_from_int(std::uint64_t v) {
    mont::fe6 t{}; t[0] = v;
    return Fq2{ mont::mfrom(fq12d::Q(), t), mont::fe6{} };
}

inline Fq6 fq6_add(const Fq6& a, const Fq6& b) {
    return Fq6{ fq2_add(fq12d::Q(),a.c0,b.c0), fq2_add(fq12d::Q(),a.c1,b.c1), fq2_add(fq12d::Q(),a.c2,b.c2) };
}
inline Fq6 fq6_sub(const Fq6& a, const Fq6& b) {
    return Fq6{ fq2_sub(fq12d::Q(),a.c0,b.c0), fq2_sub(fq12d::Q(),a.c1,b.c1), fq2_sub(fq12d::Q(),a.c2,b.c2) };
}
inline Fq6 fq6_neg(const Fq6& a) {
    return Fq6{ fq2_neg(fq12d::Q(),a.c0), fq2_neg(fq12d::Q(),a.c1), fq2_neg(fq12d::Q(),a.c2) };
}
inline bool fq6_eq(const Fq6& a, const Fq6& b)
    { return fq2_eq(a.c0,b.c0) && fq2_eq(a.c1,b.c1) && fq2_eq(a.c2,b.c2); }
inline bool fq6_is_zero(const Fq6& a)
    { return fq2_is_zero(a.c0) && fq2_is_zero(a.c1) && fq2_is_zero(a.c2); }
inline Fq6 fq6_one() { return Fq6{ fq2_one(), Fq2{}, Fq2{} }; }
inline Fq6 fq6_v()   { return Fq6{ Fq2{}, fq2_one(), Fq2{} }; }   // delta = v

// (a0+a1 v+a2 v^2)(b0+b1 v+b2 v^2), v^3 = gamma  — mirrors _s12_6mul
inline Fq6 fq6_mul(const Fq6& a, const Fq6& b) {
    const mont::MCtx& Q = fq12d::Q(); const mont::fe6& B = fq12d::B(); const Fq2& G = fq12d::G();
    const Fq2 t00 = fq2_mul(Q,a.c0,b.c0,B), t01 = fq2_mul(Q,a.c0,b.c1,B), t02 = fq2_mul(Q,a.c0,b.c2,B);
    const Fq2 t10 = fq2_mul(Q,a.c1,b.c0,B), t11 = fq2_mul(Q,a.c1,b.c1,B), t12 = fq2_mul(Q,a.c1,b.c2,B);
    const Fq2 t20 = fq2_mul(Q,a.c2,b.c0,B), t21 = fq2_mul(Q,a.c2,b.c1,B), t22 = fq2_mul(Q,a.c2,b.c2,B);
    const Fq2 c0 = fq2_add(Q, t00, fq2_mul(Q, G, fq2_add(Q, t12, t21), B));
    const Fq2 c1 = fq2_add(Q, fq2_add(Q, t01, t10), fq2_mul(Q, G, t22, B));
    const Fq2 c2 = fq2_add(Q, fq2_add(Q, t02, t11), t20);
    return Fq6{c0, c1, c2};
}

// cubic adjugate inverse — mirrors the Python tower-norm chain
inline Fq6 fq6_inv(const Fq6& n) {
    const mont::MCtx& Q = fq12d::Q(); const mont::fe6& B = fq12d::B(); const Fq2& G = fq12d::G();
    const Fq2 n0sq = fq2_mul(Q,n.c0,n.c0,B), n1sq = fq2_mul(Q,n.c1,n.c1,B), n2sq = fq2_mul(Q,n.c2,n.c2,B);
    const Fq2 n1n2 = fq2_mul(Q,n.c1,n.c2,B), n0n1 = fq2_mul(Q,n.c0,n.c1,B), n0n2 = fq2_mul(Q,n.c0,n.c2,B);
    const Fq2 g2 = fq2_mul(Q, G, G, B);
    Fq2 det = fq2_add(Q, fq2_add(Q, fq2_mul(Q,n.c0,n0sq,B),
                            fq2_mul(Q, G, fq2_mul(Q,n.c1,n1sq,B), B)),
                   fq2_mul(Q, g2, fq2_mul(Q,n.c2,n2sq,B), B));
    const Fq2 trip = fq2_mul(Q, fq2_from_int(3), fq2_mul(Q, G, fq2_mul(Q,n.c0,n1n2,B), B), B);
    det = fq2_sub(Q, det, trip);
    const Fq2 di = fq2_inv(Q, det, B);
    const Fq2 m0 = fq2_sub(Q, n0sq, fq2_mul(Q, G, n1n2, B));
    const Fq2 m1 = fq2_sub(Q, fq2_mul(Q, G, n2sq, B), n0n1);
    const Fq2 m2 = fq2_sub(Q, n1sq, n0n2);
    return Fq6{ fq2_mul(Q,m0,di,B), fq2_mul(Q,m1,di,B), fq2_mul(Q,m2,di,B) };
}

inline Fq12 fq12_add(const Fq12& a, const Fq12& b) { return Fq12{ fq6_add(a.e0,b.e0), fq6_add(a.e1,b.e1) }; }
inline Fq12 fq12_sub(const Fq12& a, const Fq12& b) { return Fq12{ fq6_sub(a.e0,b.e0), fq6_sub(a.e1,b.e1) }; }
inline Fq12 fq12_neg(const Fq12& a)                { return Fq12{ fq6_neg(a.e0), fq6_neg(a.e1) }; }
inline bool fq12_eq(const Fq12& a, const Fq12& b)  { return fq6_eq(a.e0,b.e0) && fq6_eq(a.e1,b.e1); }
inline bool fq12_is_zero(const Fq12& a)            { return fq6_is_zero(a.e0) && fq6_is_zero(a.e1); }
inline Fq12 fq12_one()                             { return Fq12{ fq6_one(), Fq6{} }; }

// (e0+e1 w)(f0+f1 w) = (e0 f0 + v e1 f1) + (e0 f1 + e1 f0) w — mirrors _s12_mul
inline Fq12 fq12_mul(const Fq12& a, const Fq12& b) {
    const Fq6 t0 = fq6_mul(a.e0, b.e0);
    const Fq6 t1 = fq6_mul(fq6_v(), fq6_mul(a.e1, b.e1));
    const Fq6 t2 = fq6_mul(a.e0, b.e1);
    const Fq6 t3 = fq6_mul(a.e1, b.e0);
    return Fq12{ fq6_add(t0, t1), fq6_add(t2, t3) };
}
inline Fq12 fq12_sqr(const Fq12& a) { return fq12_mul(a, a); }

// tower-norm inverse: a^-1 = conj(a)/(e0^2 - v e1^2)
inline Fq12 fq12_inv(const Fq12& a) {
    const Fq6 e0sq = fq6_mul(a.e0, a.e0);
    const Fq6 n = fq6_sub(e0sq, fq6_mul(fq6_v(), fq6_mul(a.e1, a.e1)));
    const Fq6 ni = fq6_inv(n);
    return fq12_mul(Fq12{ a.e0, fq6_neg(a.e1) }, Fq12{ ni, Fq6{} });
}

// MSB-first square-and-multiply over little-endian limb exponent
inline Fq12 fq12_pow_limbs(const Fq12& a, const std::uint64_t* e, int n) {
    Fq12 r = fq12_one();
    bool started = false;
    for (int i = n - 1; i >= 0; --i) {
        for (int k = 63; k >= 0; --k) {
            const bool bit = ((e[i] >> k) & 1ULL) != 0;
            if (!started) {
                if (!bit) continue;
                started = true; r = a; continue;
            }
            r = fq12_sqr(r);
            if (bit) r = fq12_mul(r, a);
        }
    }
    return r;
}

} // namespace hsma::threshold
