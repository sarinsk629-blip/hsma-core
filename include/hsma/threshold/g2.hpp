// HSMA :: threshold/g2.hpp — E' twist curve: y²=x³+b' over F_q2 (DEC-193..).
// β=5, b'=(5,1), generator from bls_g2_params_gen.hpp. Jacobian over Fq2.
// Same formula structure as G1 (Pdbl/Padd/Pmul) but every field op is Fq2.
#pragma once
#include <hsma/threshold/g1.hpp>
#include <hsma/threshold/fq2.hpp>
#include <bls_g2_params_gen.hpp>
#include <cstdio>
#include <cstdlib>

namespace hsma::threshold::g2 {

using mont::fe6; using mont::u64;
using Fq2 = threshold::Fq2;

struct Ctx {
    mont::fe6 beta_m{};      // β = 5 (Montgomery)
    Fq2 b2{};                // twist coefficient (Montgomery)
    Fq2 gen_x{}, gen_y{};    // G2 generator (Montgomery, affine)
};

inline const Ctx& ctx() {
    static const Ctx c = []{
        Ctx t{};
        const mont::MCtx& Q = g1::ctx().m;
        mont::fe6 beta{}; mont::bn_cpy(beta.data(), blsq2::G2_BETA, 6);
        t.beta_m = mont::mfrom(Q, beta);
        mont::fe6 b20{}, b21{};
        mont::bn_cpy(b20.data(), blsq2::G2_B2_C0, 6);
        mont::bn_cpy(b21.data(), blsq2::G2_B2_C1, 6);
        t.b2.c0 = mont::mfrom(Q, b20); t.b2.c1 = mont::mfrom(Q, b21);
        mont::fe6 gx0{}, gx1{}, gy0{}, gy1{};
        mont::bn_cpy(gx0.data(), blsq2::G2_GEN_X_C0, 6);
        mont::bn_cpy(gx1.data(), blsq2::G2_GEN_X_C1, 6);
        mont::bn_cpy(gy0.data(), blsq2::G2_GEN_Y_C0, 6);
        mont::bn_cpy(gy1.data(), blsq2::G2_GEN_Y_C1, 6);
        t.gen_x.c0 = mont::mfrom(Q, gx0); t.gen_x.c1 = mont::mfrom(Q, gx1);
        t.gen_y.c0 = mont::mfrom(Q, gy0); t.gen_y.c1 = mont::mfrom(Q, gy1);
        return t;
    }();
    return c;
}

struct G2Pt { Fq2 x{}, y{}, z{}; };

inline bool PisInf(const G2Pt& P) {
    return threshold::fq2_is_zero(P.z);
}

// Convenience: Fq2 ops bound to g2 context
#define G2Q (g1::ctx().m)
#define G2B (ctx().beta_m)
inline Fq2 fa(const Fq2& a, const Fq2& b) { return threshold::fq2_add(G2Q, a, b); }
inline Fq2 fs(const Fq2& a, const Fq2& b) { return threshold::fq2_sub(G2Q, a, b); }
inline Fq2 fm(const Fq2& a, const Fq2& b) { return threshold::fq2_mul(G2Q, a, b, G2B); }
inline Fq2 fsq(const Fq2& a) { return threshold::fq2_sqr(G2Q, a, G2B); }
inline Fq2 finv(const Fq2& a) { return threshold::fq2_inv(G2Q, a, G2B); }
inline Fq2 fneg(const Fq2& a) { return threshold::fq2_neg(G2Q, a); }

inline G2Pt Pdbl(const G2Pt& P) {
    if (PisInf(P) || threshold::fq2_is_zero(P.y)) return G2Pt{};
    const Fq2 A = fsq(P.x);
    const Fq2 B = fsq(P.y);
    const Fq2 C = fsq(B);
    const Fq2 XB = fa(P.x, B);
    Fq2 D = fsq(XB); D = fs(D, A); D = fs(D, C); D = fa(D, D);
    const Fq2 E = fa(fa(A, A), A);
    const Fq2 X3 = fs(fsq(E), fa(D, D));
    const Fq2 C2 = fa(C, C);
    const Fq2 C4 = fa(C2, C2);
    const Fq2 C8 = fa(C4, C4);
    const Fq2 Y3 = fs(fm(E, fs(D, X3)), C8);
    const Fq2 Z3 = fm(fa(P.y, P.y), P.z);
    return G2Pt{X3, Y3, Z3};
}

inline G2Pt Padd(const G2Pt& P, const G2Pt& Q) {
    if (PisInf(P)) return Q;
    if (PisInf(Q)) return P;
    const Fq2 Z1s = fsq(P.z), Z2s = fsq(Q.z);
    const Fq2 U1 = fm(P.x, Z2s), U2 = fm(Q.x, Z1s);
    const Fq2 S1 = fm(fm(P.y, Z2s), Q.z);
    const Fq2 S2 = fm(fm(Q.y, Z1s), P.z);
    if (threshold::fq2_eq(U1, U2))
        return threshold::fq2_eq(S1, S2) ? Pdbl(P) : G2Pt{};
    const Fq2 H = fs(U2, U1);
    const Fq2 HH = fsq(H);
    Fq2 I = fa(HH, HH); I = fa(I, I);
    const Fq2 J = fm(H, I);
    Fq2 rr = fs(S2, S1); rr = fa(rr, rr);
    const Fq2 V = fm(U1, I);
    const Fq2 X3 = fs(fs(fsq(rr), J), fa(V, V));
    const Fq2 SJ = fa(fm(S1, J), fm(S1, J));
    const Fq2 Y3 = fs(fm(rr, fs(V, X3)), SJ);
    Fq2 two; two.c0 = g1::ctx().m.r1; // placeholder — fix below
    // 2 as Fq2 = (mfrom(2), mfrom(0)) — we need mfrom({2,0,...}) which is r1*2
    // Actually: 2 in Montgomery = mmul(mfrom(2), r1) — but mfrom(2) already IS 2R.
    // The simplest: 2 = add(1, 1) where 1 = r1 (Montgomery-one)
    // So: two.c0 = madd(Q, r1, r1), two.c1 = 0
    two.c0 = mont::madd(G2Q, g1::ctx().m.r1, g1::ctx().m.r1);
    two.c1 = mont::fe6{}; // zero
    const Fq2 Z3 = fm(fm(fm(P.z, Q.z), H), two);
    return G2Pt{X3, Y3, Z3};
}

inline G2Pt Pmul(const G2Pt& P, const fe6& k) {
    G2Pt r{};
    for (int i = 5; i >= 0; --i)
        for (int b = 63; b >= 0; --b) {
            r = Pdbl(r);
            if ((k[i] >> b) & 1ULL) r = Padd(r, P);
        }
    return r;
}

inline G2Pt from_affine(const std::uint64_t xa[6], const std::uint64_t xb[6],
                       const std::uint64_t ya[6], const std::uint64_t yb[6]) {
    const mont::MCtx& Q = g1::ctx().m;
    G2Pt P;
    P.x = threshold::fq2_from_canon(Q, xa, xb);
    P.y = threshold::fq2_from_canon(Q, ya, yb);
    P.z.c0 = Q.r1; P.z.c1 = mont::fe6{};  // z = 1 (Montgomery)
    return P;
}

inline bool to_affine(const G2Pt& P, std::uint64_t xa[6], std::uint64_t xb[6],
                     std::uint64_t ya[6], std::uint64_t yb[6]) {
    if (PisInf(P)) return false;
    const mont::MCtx& Q = g1::ctx().m;
    const Fq2 zi = finv(P.z);
    const Fq2 z2 = fsq(zi);
    const Fq2 z3 = fm(z2, zi);
    const Fq2 x = fm(P.x, z2);
    const Fq2 y = fm(P.y, z3);
    const fe6 xc0 = mont::mto(Q, x.c0);
    const fe6 xc1 = mont::mto(Q, x.c1);
    const fe6 yc0 = mont::mto(Q, y.c0);
    const fe6 yc1 = mont::mto(Q, y.c1);
    mont::bn_cpy(xa, xc0.data(), 6); mont::bn_cpy(xb, xc1.data(), 6);
    mont::bn_cpy(ya, yc0.data(), 6); mont::bn_cpy(yb, yc1.data(), 6);
    return true;
}

inline G2Pt gen() {
    return from_affine(blsq2::G2_GEN_X_C0, blsq2::G2_GEN_X_C1,
                      blsq2::G2_GEN_Y_C0, blsq2::G2_GEN_Y_C1);
}

inline bool on_curve_aff(const std::uint64_t xa[6], const std::uint64_t xb[6],
                        const std::uint64_t ya[6], const std::uint64_t yb[6]) {
    // y² == x³ + b2 over F_q2
    const mont::MCtx& Q = g1::ctx().m;
    const Fq2 x = threshold::fq2_from_canon(Q, xa, xb);
    const Fq2 y = threshold::fq2_from_canon(Q, ya, yb);
    const Fq2 lhs = fsq(y);
    const Fq2 x3 = fm(fsq(x), x);
    const Fq2 rhs = fa(x3, ctx().b2);
    return threshold::fq2_eq(lhs, rhs);
}

} // namespace hsma::threshold::g2
