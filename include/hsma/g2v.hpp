// HSMA :: g2v.hpp — the Vesta curve operations (P1-06, DEC-224, GAP-03c).
// Vesta: y^2 = x^3 + 5 over F_q. Generator: (-1, 2).
// Jacobian coordinates over fq::fev (4-limb Montgomery, F_q).
// Same dbl-2009-l formula family as the BLS G1 (with a=0 simplification).
// All constants from vesta_params_gen.hpp + the pasta-curves crate reference.
// CA-R107: fev arithmetic is REUSED (not re-derived). CA-R112: overflow-safe mul.
#pragma once
#include <hsma/fev.hpp>
#include <array>
#include <cstdint>

namespace hsma::g2v {

using fq::fev;

// B = 5 (the curve coefficient, as a Montgomery element)
inline fev curve_b() noexcept {
    fev five = fq::fev_from_u64(5);
    return five;
}

// The canonical Vesta generator: (-1, 2) in affine coordinates
// In Montgomery: x = (-1)*RR mod q, y = 2*RR mod q
inline fev gen_x() noexcept {
    fev neg1 = fq::fev_sub(fq::fev_zero(), fq::fev_one());
    return neg1;
}

struct PtV {
    fev x{}, y{}, z{};  // Jacobian: (X/Z^2, Y/Z^3)
};

inline bool is_inf(const PtV& P) noexcept { return fq::fev_is_zero(P.z); }

// ---- BLOCK T-CORE: self-contained Jacobian primitives (a=0) ----
// Textbook dbl-2009-l / generic Jacobian add over the PROVEN fev ops.
// The formulas are constant-free: correct in any consistent field encoding.
inline PtV jac_dbl(const PtV& P) noexcept {
    if (fq::fev_is_zero(P.z)) return P;                  // 2*inf = inf
    fev A  = fq::fev_mul(P.x, P.x);                      // A = X1^2
    fev B  = fq::fev_mul(P.y, P.y);                      // B = Y1^2
    fev C  = fq::fev_mul(B, B);                          // C = B^2
    fev XB = fq::fev_add(P.x, B);
    fev D  = fq::fev_sub(fq::fev_mul(XB, XB), fq::fev_add(A, C));
    D      = fq::fev_add(D, D);                          // D = 2*((X1+B)^2 - A - C)
    fev E  = fq::fev_add(A, fq::fev_add(A, A));          // E = 3A
    fev F  = fq::fev_mul(E, E);                          // F = E^2
    PtV R{};
    R.x = fq::fev_sub(F, fq::fev_add(D, D));             // X3 = F - 2D
    R.y = fq::fev_sub(fq::fev_mul(E, fq::fev_sub(D, R.x)),
                      fq::fev_mul(C, fq::fev_from_u64(8)));  // Y3 = E*(D-X3) - 8C
    R.z = fq::fev_mul(fq::fev_add(P.y, P.y), P.z);       // Z3 = 2*Y1*Z1
    return R;
}

inline PtV jac_add(const PtV& P, const PtV& Q) noexcept {
    if (fq::fev_is_zero(P.z)) return Q;
    if (fq::fev_is_zero(Q.z)) return P;
    fev Z1Z1 = fq::fev_mul(P.z, P.z);
    fev Z2Z2 = fq::fev_mul(Q.z, Q.z);
    fev U1 = fq::fev_mul(P.x, Z2Z2);
    fev U2 = fq::fev_mul(Q.x, Z1Z1);
    fev S1 = fq::fev_mul(fq::fev_mul(P.y, Q.z), Z2Z2);   // Y1*Z2^3
    fev S2 = fq::fev_mul(fq::fev_mul(Q.y, P.z), Z1Z1);   // Y2*Z1^3
    fev H  = fq::fev_sub(U2, U1);
    fev r  = fq::fev_sub(S2, S1);
    if (fq::fev_is_zero(H)) {
        if (fq::fev_is_zero(r)) return jac_dbl(P);       // P == Q
        PtV I{}; return I;                               // P == -Q  =>  infinity
    }
    fev HH  = fq::fev_mul(H, H);
    fev HHH = fq::fev_mul(H, HH);
    fev V   = fq::fev_mul(U1, HH);
    PtV R{};
    R.x = fq::fev_sub(fq::fev_mul(r, r), fq::fev_add(HHH, fq::fev_add(V, V)));
    R.y = fq::fev_sub(fq::fev_mul(r, fq::fev_sub(V, R.x)),
                      fq::fev_mul(S1, HHH));
    R.z = fq::fev_mul(fq::fev_mul(P.z, Q.z), H);
    return R;
}

inline PtV from_affine(const fev& x, const fev& y) noexcept {
    PtV P{};
    P.x = x;
    P.y = y;
    P.z = fq::fev_one();
    return P;
}

inline bool to_affine(const PtV& P, fev& x, fev& y) noexcept {
    if (fq::fev_is_zero(P.z)) return false;  // point at infinity
    fev zinv = fq::fev_inv(P.z);
    fev zinv2 = fq::fev_mul(zinv, zinv);
    fev zinv3 = fq::fev_mul(zinv2, zinv);
    x = fq::fev_mul(P.x, zinv2);
    y = fq::fev_mul(P.y, zinv3);
    return true;
}

inline bool on_curve(const PtV& P) noexcept {
    if (fq::fev_is_zero(P.z)) return true;  // infinity is on the curve
    fev z2 = fq::fev_mul(P.z, P.z);
    fev z3 = fq::fev_mul(z2, P.z);
    fev y2 = fq::fev_mul(P.y, P.y);
    fev x3 = fq::fev_mul(fq::fev_mul(P.x, P.x), P.x);
    fev rhs = fq::fev_add(x3, fq::fev_mul(fq::fev_from_u64(5), z3));
    return fq::fev_eq(y2, rhs);
}

// Double: dbl-2009-l with a=0
// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
inline PtV Vdbl(const PtV& P) noexcept { return jac_dbl(P); }
inline PtV Vadd(const PtV& P, const PtV& Q) noexcept { return jac_add(P, Q); }
inline PtV Vmul(const PtV& P, const std::uint64_t k[4]) noexcept {
    PtV R{};                                         // z = 0 <=> point at infinity
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
inline PtV generator() noexcept {
    // x = -1 mod q = q - 1
    fev x = fq::fev_sub(fq::fev_zero(), fq::fev_one());
    fev y = fq::fev_from_u64(2);
    return from_affine(x, y);
}

} // namespace hsma::g2v
