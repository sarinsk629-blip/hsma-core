// HSMA :: threshold/pairing.hpp — twist + Miller + final exp + BLS verify (DEC-198/199)
// Reduced Tate pairing: e(P,Q) = f_{r,P}(psi(Q))^((q^12-1)/r). Mirrors the Python oracle
// line-for-line, including the final-vertical skip (i > 0 — denominator elimination,
// r | q^6+1 verified from generator constants). G12_FEXP is DEC-102-pinned. DEC-127; DEC-090.
#pragma once
#include <hsma/threshold/fq12.hpp>
#include <bls_g2_params_gen.hpp>

namespace hsma::threshold {

inline Fq12 fq12_from_int(std::uint64_t v) {
    return Fq12{ Fq6{ fq2_from_int(v), Fq2{}, Fq2{} }, Fq6{} };
}
// embed F_q canonical limbs as an Fq12 constant (x,0) — the CA-R50 law: PAIR, never raw
inline Fq12 embed_fq(const std::uint64_t x[6]) {
    mont::fe6 t{}; mont::bn_cpy(t.data(), x, 6);
    return Fq12{ Fq6{ Fq2{ mont::mfrom(fq12d::Q(), t), mont::fe6{} }, Fq2{}, Fq2{} }, Fq6{} };
}
// twist: psi(x',y') = (x'/v, y'/(v*w))
inline void twist(const Fq2& xq, const Fq2& yq, Fq12& out_x, Fq12& out_y) {
    const Fq12 vinv = fq12_inv(Fq12{ fq6_v(), Fq6{} });
    const Fq12 winv = fq12_inv(Fq12{ Fq6{}, fq6_one() });
    const Fq12 x12{ Fq6{ xq, Fq2{}, Fq2{} }, Fq6{} };
    const Fq12 y12{ Fq6{ yq, Fq2{}, Fq2{} }, Fq6{} };
    out_x = fq12_mul(x12, vinv);
    out_y = fq12_mul(fq12_mul(y12, vinv), winv);
}

struct Pt12 { Fq12 x{}, y{}; };

inline Fq12 miller(const std::uint64_t px[6], const std::uint64_t py[6],
                   const Fq12& Qx, const Fq12& Qy) {
    const mont::fe6& rmod = g1::ctx().rmod;
    int bl = 0;
    for (int i = 5; i >= 0 && bl == 0; --i) {
        if (rmod[i] == 0) continue;
        for (int k = 63; k >= 0; --k)
            if ((rmod[i] >> k) & 1ULL) { bl = i * 64 + k + 1; break; }
    }
    const Fq12 three = fq12_from_int(3);
    Pt12 T{ embed_fq(px), embed_fq(py) };
    const Fq12 Px = T.x, Py = T.y;
    Fq12 f = fq12_one();
    for (int i = bl - 2; i >= 0; --i) {
        const bool bit = ((rmod[i >> 6] >> (i & 63)) & 1ULL) != 0;
        const Fq12 num = fq12_mul(three, fq12_mul(T.x, T.x));       // tangent at T
        const Fq12 den = fq12_add(T.y, T.y);
        const Fq12 lam = fq12_mul(num, fq12_inv(den));
        const Fq12 l = fq12_sub(fq12_sub(Qy, T.y), fq12_mul(lam, fq12_sub(Qx, T.x)));
        f = fq12_mul(fq12_sqr(f), l);
        const Fq12 lam2 = fq12_sqr(lam);
        const Fq12 Tx3 = fq12_sub(fq12_sub(lam2, T.x), T.x);
        const Fq12 Ty3 = fq12_sub(fq12_mul(lam, fq12_sub(T.x, Tx3)), T.y);
        T = Pt12{ Tx3, Ty3 };
        if (bit && i > 0) {   // chord; i==0 is the VERTICAL line x-x_P (denominator elimination)
            const Fq12 cnum = fq12_sub(Py, T.y);
            const Fq12 cden = fq12_sub(Px, T.x);
            const Fq12 clam = fq12_mul(cnum, fq12_inv(cden));
            const Fq12 cl = fq12_sub(fq12_sub(Qy, T.y), fq12_mul(clam, fq12_sub(Qx, T.x)));
            f = fq12_mul(f, cl);
            const Fq12 clam2 = fq12_sqr(clam);
            const Fq12 Cx3 = fq12_sub(fq12_sub(clam2, T.x), Px);
            const Fq12 Cy3 = fq12_sub(fq12_mul(clam, fq12_sub(T.x, Cx3)), T.y);
            T = Pt12{ Cx3, Cy3 };
        }
    }
    return f;
}

inline Fq12 pairing(const std::uint64_t px[6], const std::uint64_t py[6], const g2::G2Pt& Q) {
    std::uint64_t qx0[6], qx1[6], qy0[6], qy1[6];
    if (!g2::to_affine(Q, qx0, qx1, qy0, qy1)) return fq12_one();
    const Fq2 xq = fq2_from_canon(fq12d::Q(), qx0, qx1);
    const Fq2 yq = fq2_from_canon(fq12d::Q(), qy0, qy1);
    Fq12 Qx, Qy;
    twist(xq, yq, Qx, Qy);
    return fq12_pow_limbs(miller(px, py, Qx, Qy), blsq2::G12_FEXP, int(blsq2::G12_FEXP_N));
}

// THE LAW: e(sigma, G2gen) == e(H(m), Y) — secret-free (retires DEC-191's harness-secret law)
inline bool bls_verify_aff(const std::uint64_t sx[6], const std::uint64_t sy[6],
                           const std::uint64_t hx[6], const std::uint64_t hy[6],
                           const g2::G2Pt& Y) {
    return fq12_eq(pairing(sx, sy, g2::gen()), pairing(hx, hy, Y));
}

} // namespace hsma::threshold
