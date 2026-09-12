// HSMA :: nifs.hpp — the NIFS fold (Step 21, DEC-214).
// Relaxed instance (z, u, E): Az⊙Bz = u·Cz + E elementwise (strict: u=1, E=0),
// diagonal constraint vectors — per-element linear maps; linearity is all the
// fold identity needs. Fold (E_B = 0, strict B):
//   r  = P3(FOLD, P3(FOLD, P3(FOLD, C_zA, C_zB), C_T), C_EA)
//   z  = zA + r*zB;   u = uA + r*uB;
//   E  = EA + r*T + r^2*EB = EA + r*T,
//   T  = AzA⊙BzB + AzB⊙BzA − uA*CzB − uB*CzA.
// The identity is polynomial in r => the folded instance satisfies EXACTLY
// for any r; soundness-negative = tampered T (claimed E fails sat), and
// transcript binding = the pinned golden r (validity is r-independent).
// Phase-0: witnesses folded directly (commitments pin the transcript; the
// homomorphic commitment fold is DEC-071's production layer). Verifier checks
// E elementwise. Zero new registry domains. DEC-090; CA-R84 (local feq).
#pragma once
#include <hsma/poseidon.hpp>
#include <vector>
#include <cstdint>

namespace hsma::nifs {

inline bool feq(const fp::fe& a, const fp::fe& b) { return a.l == b.l; }

struct Instance {
    std::vector<fp::fe> z;   // witness (N elements)
    fp::fe u{};              // scalar (1 for strict)
    std::vector<fp::fe> E;   // error vector (zeros for strict)
};

// Elementwise-satisfiability check: Az[i]*Bz[i] == u*Cz[i] + E[i].
// Returns the first failing index, or N on ACCEPT (CA-R83 lesson: unambiguous).
inline std::size_t sat(const std::vector<fp::fe>& A, const std::vector<fp::fe>& B,
                       const std::vector<fp::fe>& C, const Instance& in) {
    const std::size_t N = A.size();
    for (std::size_t i = 0; i < N; ++i) {
        const fp::fe az = fe_mul(A[i], in.z[i]);
        const fp::fe bz = fe_mul(B[i], in.z[i]);
        const fp::fe cz = fe_mul(C[i], in.z[i]);
        const fp::fe lhs = fe_mul(az, bz);
        const fp::fe rhs = fe_add(fe_mul(in.u, cz), in.E[i]);
        if (!feq(lhs, rhs)) return i;
    }
    return N;
}

// Strict-witness construction: z_i in {0, C_i/(A_i*B_i)} satisfies with u=1, E=0.
// The constructor is strict_elem_inv below (CA-R85: the use-before-declaration
// strict_elem + the dead fe_pow64 placeholder were stripped, not annotated).
// Modular inverse via Fermat: x^(MOD-2), exponent DERIVED from the field's
// own machine-generated modulus (pallas_params_gen.hpp) - never hand-written
// limbs (the CA-R64 doctrine, applied to an exponent after CA-R85's lesson).
inline fp::fe inv_fe(const fp::fe& x) {
    std::uint64_t e[4];
    for (int i = 0; i < 4; ++i) e[i] = pallas_gen::MOD[i];
    // e = MOD - 2 (MOD is odd, canonical, > 2)
    std::uint64_t borrow = 2;
    for (int i = 0; i < 4 && borrow; ++i) {
        const std::uint64_t old = e[i];
        e[i] = old - borrow;
        borrow = (old < borrow) ? 1 : 0;
    }
    fp::fe result = fp::fe_one();
    fp::fe base = x;
    for (int limb = 3; limb >= 0; --limb)          // MSB-first over p-2
        for (int bit = 63; bit >= 0; --bit) {
            result = fe_mul(result, result);
            if ((e[limb] >> bit) & 1ull) result = fe_mul(result, base);
        }
    return result;
}
inline fp::fe strict_elem_inv(const fp::fe& A, const fp::fe& Bv,
                              const fp::fe& C, bool on) {
    if (!on) return fp::fe_zero();
    return fe_mul(C, inv_fe(fe_mul(A, Bv)));
}

// The fold. Returns the folded (relaxed) instance + the transcript pins.
struct FoldResult {
    Instance out;
    std::vector<fp::fe> T;   // cross-term
    fp::fe r{};              // transcript challenge
    fp::fe czA{}, czB{}, cT{}, cEA{};  // commitment pins
};

inline FoldResult fold(const std::vector<fp::fe>& A, const std::vector<fp::fe>& B,
                       const std::vector<fp::fe>& Cv,
                       const Instance& a, const Instance& b) {
    const std::size_t N = A.size();
    FoldResult R;
    // cross-term
    R.T.resize(N);
    for (std::size_t i = 0; i < N; ++i) {
        const fp::fe azA = fe_mul(A[i], a.z[i]);
        const fp::fe bzA = fe_mul(B[i], a.z[i]);
        const fp::fe czA = fe_mul(Cv[i], a.z[i]);
        const fp::fe azB = fe_mul(A[i], b.z[i]);
        const fp::fe bzB = fe_mul(B[i], b.z[i]);
        const fp::fe czB = fe_mul(Cv[i], b.z[i]);
        fp::fe t = fe_add(fe_mul(azA, bzB), fe_mul(azB, bzA));
        t = fe_sub(t, fe_mul(a.u, czB));
        t = fe_sub(t, fe_mul(b.u, czA));
        R.T[i] = t;
    }
    // transcript commitments (Step-20 sponge) + challenge (HSM_FOLD_v1 chain)
    fp::Sponge sA(dom::Dom::HSM_SUMCHECK_v1);
    for (const auto& v : a.z) sA.absorb(v);
    R.czA = sA.squeeze();
    fp::Sponge sB(dom::Dom::HSM_SUMCHECK_v1);
    for (const auto& v : b.z) sB.absorb(v);
    R.czB = sB.squeeze();
    fp::Sponge sT(dom::Dom::HSM_SUMCHECK_v1);
    for (const auto& v : R.T) sT.absorb(v);
    R.cT = sT.squeeze();
    fp::Sponge sE(dom::Dom::HSM_SUMCHECK_v1);
    for (const auto& v : a.E) sE.absorb(v);
    R.cEA = sE.squeeze();
    const fp::fe d1 = poseidon3(dom::Dom::HSM_FOLD_v1, R.czA, R.czB);
    const fp::fe d2 = poseidon3(dom::Dom::HSM_FOLD_v1, d1, R.cT);
    R.r = poseidon3(dom::Dom::HSM_FOLD_v1, d2, R.cEA);
    // folded instance: E_B = 0 (strict B) => E = EA + r*T
    R.out.z.resize(N);
    R.out.E.resize(N);
    R.out.u = fe_add(a.u, fe_mul(R.r, b.u));
    for (std::size_t i = 0; i < N; ++i) {
        R.out.z[i] = fe_add(a.z[i], fe_mul(R.r, b.z[i]));
        R.out.E[i] = fe_add(a.E[i], fe_mul(R.r, R.T[i]));
    }
    return R;
}

} // namespace hsma::nifs
