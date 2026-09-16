// HSMA :: g1p.hpp — the Pallas curve operations (P1-08, DEC-226, GAP-14).
// Pallas: y^2 = x^3 + 5 over F_p. Generator: (-1, 2).
// Jacobian coordinates over fp::fe (4-limb Montgomery, F_p).
// Same dbl-2009-l formula family as the BLS G1 (with a=0 simplification).
// All constants from vesta_params_gen.hpp + the pasta-curves crate reference.
// CA-R107: fe arithmetic is REUSED (not re-derived). CA-R112: overflow-safe mul.
#pragma once
#include <hsma/fe.hpp>
#include <array>
#include <cstdint>

namespace hsma::g1p {

using fp::fe;

// Montgomery-domain field inverse via Fermat: x^(p-2) mod p.
// The exponentiation preserves the Montgomery R-factor exactly
// (R^(p-2) = R^(-1) mod p by Fermat's little theorem), so the result is
// the Montgomery inverse. The Pallas twin of fev.hpp's fev_inv
// (the CA-R86/110 Fermat approach). CA-R124: this is the callee the
// g2v->g1p map assumed existed - it did not; now it does, proven here.
inline fe fe_inv(const fe& a) noexcept {
    // e = p - 2 (limb 0 only: MOD[0] is odd and > 2, no borrow propagates)
    const std::uint64_t E[4] = { pallas_gen::MOD[0] - 2u, pallas_gen::MOD[1],
                                 pallas_gen::MOD[2], pallas_gen::MOD[3] };
    fe r{}; bool started = false;
    for (int i = 3; i >= 0; --i)
        for (int b = 63; b >= 0; --b) {
            if (started) r = fp::fe_sqr(r);
            if ((E[i] >> b) & 1ULL) { r = started ? fp::fe_mul(r, a) : a; started = true; }
        }
    return r;
}

// B = 5 (the curve coefficient, as a Montgomery element)
inline fe curve_b() noexcept {
    fe five = fp::fe_from_u64(5);
    return five;
}

// The canonical Vesta generator: (-1, 2) in affine coordinates
// In Montgomery: x = (-1)*RR mod q, y = 2*RR mod q
inline fe gen_x() noexcept {
    fe neg1 = fp::fe_sub(fp::fe_zero(), fp::fe_one());
    return neg1;
}

struct PtP {
    fe x{}, y{}, z{};  // Jacobian: (X/Z^2, Y/Z^3)
};

inline bool is_inf(const PtP& P) noexcept { return fp::fe_is_zero(P.z); }

// ---- BLOCK T-CORE: self-contained Jacobian primitives (a=0) ----
// Textbook dbl-2009-l / generic Jacobian add over the PROVEN fe ops.
// The formulas are constant-free: correct in any consistent field encoding.
inline PtP jac_dbl(const PtP& P) noexcept {
    if (fp::fe_is_zero(P.z)) return P;                  // 2*inf = inf
    fe A  = fp::fe_mul(P.x, P.x);                      // A = X1^2
    fe B  = fp::fe_mul(P.y, P.y);                      // B = Y1^2
    fe C  = fp::fe_mul(B, B);                          // C = B^2
    fe XB = fp::fe_add(P.x, B);
    fe D  = fp::fe_sub(fp::fe_mul(XB, XB), fp::fe_add(A, C));
    D      = fp::fe_add(D, D);                          // D = 2*((X1+B)^2 - A - C)
    fe E  = fp::fe_add(A, fp::fe_add(A, A));          // E = 3A
    fe F  = fp::fe_mul(E, E);                          // F = E^2
    PtP R{};
    R.x = fp::fe_sub(F, fp::fe_add(D, D));             // X3 = F - 2D
    R.y = fp::fe_sub(fp::fe_mul(E, fp::fe_sub(D, R.x)),
                      fp::fe_mul(C, fp::fe_from_u64(8)));  // Y3 = E*(D-X3) - 8C
    R.z = fp::fe_mul(fp::fe_add(P.y, P.y), P.z);       // Z3 = 2*Y1*Z1
    return R;
}

inline PtP jac_add(const PtP& P, const PtP& Q) noexcept {
    if (fp::fe_is_zero(P.z)) return Q;
    if (fp::fe_is_zero(Q.z)) return P;
    fe Z1Z1 = fp::fe_mul(P.z, P.z);
    fe Z2Z2 = fp::fe_mul(Q.z, Q.z);
    fe U1 = fp::fe_mul(P.x, Z2Z2);
    fe U2 = fp::fe_mul(Q.x, Z1Z1);
    fe S1 = fp::fe_mul(fp::fe_mul(P.y, Q.z), Z2Z2);   // Y1*Z2^3
    fe S2 = fp::fe_mul(fp::fe_mul(Q.y, P.z), Z1Z1);   // Y2*Z1^3
    fe H  = fp::fe_sub(U2, U1);
    fe r  = fp::fe_sub(S2, S1);
    if (fp::fe_is_zero(H)) {
        if (fp::fe_is_zero(r)) return jac_dbl(P);       // P == Q
        PtP I{}; return I;                               // P == -Q  =>  infinity
    }
    fe HH  = fp::fe_mul(H, H);
    fe HHH = fp::fe_mul(H, HH);
    fe V   = fp::fe_mul(U1, HH);
    PtP R{};
    R.x = fp::fe_sub(fp::fe_mul(r, r), fp::fe_add(HHH, fp::fe_add(V, V)));
    R.y = fp::fe_sub(fp::fe_mul(r, fp::fe_sub(V, R.x)),
                      fp::fe_mul(S1, HHH));
    R.z = fp::fe_mul(fp::fe_mul(P.z, Q.z), H);
    return R;
}

inline PtP from_affine(const fe& x, const fe& y) noexcept {
    PtP P{};
    P.x = x;
    P.y = y;
    P.z = fp::fe_one();
    return P;
}

inline bool to_affine(const PtP& P, fe& x, fe& y) noexcept {
    if (fp::fe_is_zero(P.z)) return false;  // point at infinity
    fe zinv = fe_inv(P.z);
    fe zinv2 = fp::fe_mul(zinv, zinv);
    fe zinv3 = fp::fe_mul(zinv2, zinv);
    x = fp::fe_mul(P.x, zinv2);
    y = fp::fe_mul(P.y, zinv3);
    return true;
}

inline bool on_curve(const PtP& P) noexcept {
    // Jacobian curve equation: Y^2 = X^3 + b*Z^6  (affine x=X/Z^2, y=Y/Z^3).
    // CA-R121: the old body's Z handling was masked by Z=1 (the only shape
    // the suite ever tested). Full Z^6 term, no inversion, proven fe ops only.
    if (fp::fe_is_zero(P.z)) return true;                 // infinity: on-curve by convention
    fe z2 = fp::fe_mul(P.z, P.z);                        // Z^2
    fe z6 = fp::fe_mul(fp::fe_mul(z2, z2), z2);         // Z^6 = (Z^2)^3
    fe lhs = fp::fe_mul(P.y, P.y);                       // Y^2
    fe x3  = fp::fe_mul(fp::fe_mul(P.x, P.x), P.x);     // X^3
    fe rhs = fp::fe_add(x3, fp::fe_mul(curve_b(), z6)); // X^3 + b*Z^6
    return fp::fe_is_zero(fp::fe_sub(lhs, rhs));
}

inline PtP Vdbl(const PtP& P) noexcept { return jac_dbl(P); }
inline PtP Vadd(const PtP& P, const PtP& Q) noexcept { return jac_add(P, Q); }
inline PtP Vmul(const PtP& P, const std::uint64_t k[4]) noexcept {
    PtP R{};                                         // z = 0 <=> point at infinity
    bool started = false;
    for (int i = 3; i >= 0; --i) {
        for (int b = 63; b >= 0; --b) {
            if (started) R = jac_dbl(R);
            if ((k[i] >> b) & 1u) {
                R = started ? jac_add(R, P) : P;
                started = true;
            }
        }
    }
    return R;
}
inline PtP generator() noexcept {
    // x = -1 mod q = q - 1
    fe x = fp::fe_sub(fp::fe_zero(), fp::fe_one());
    fe y = fp::fe_from_u64(2);
    return from_affine(x, y);
}

} // namespace hsma::g1p
