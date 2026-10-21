// GENERATED FILE - bridge_golden.hpp (P1-02c, DEC-221). DO NOT EDIT.
// The G2 wire-map bridge: converts our F_q2 tower (u^2 = +5, b'=(5,1)) to the
// canonical BLS12-377 tower (v^2 = -5, b2 = (0, B)) via:
//   s   = sqrt(-1) mod q                    [field map: our u = s*v]
//   Phi(a,b) = (a, b*s)                     [field isomorphism F_q(u) -> F_q(v)]
//   rho = b2_spec / Phi(b')                 [the twist ratio]
//   w^6 = rho                               [the scaling element, Tonelli+cbrt]
//   psi(x,y) = (Phi(x)*w^2, Phi(y)*w^3)     [the point map: our G2 -> spec G2]
// VERIFIED: psi(our G2 gen) on spec curve + [r]psi = inf; ark gen on spec curve
// + [r]ark = inf (both directions cross-checked, 0.328s total).
// Reference: ark-bls12-377 0.6.0 (build/ref_curves_*.rs committed).
#pragma once
#include <cstdint>
namespace hsma::golden {
inline constexpr std::uint64_t BR_S[4] = {{0x6e76d5ecf1391c63ull, 0x99588459bff27d8eull, 0xbce649cf436b0f62ull, 0x400398f50ad1dec1ull}};
inline constexpr std::uint64_t BR_W_C0[4] = {{0x7a38c504cc0f79e3ull, 0xe3a18cecbd36a1c4ull, 0x2a2b44cc5597c9d3ull, 0x11d16b2b40db9892ull}};
inline constexpr std::uint64_t BR_W_C1[4] = {{0x6c89519373fb9854ull, 0xb012c6be9214b2a3ull, 0x5041892a2ba0f490ull, 0x9e45da6bdd9be16dull}};
inline constexpr std::uint64_t BR_B2_C0[4] = {{0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull}};
inline constexpr std::uint64_t BR_B2_C1[4] = {{0x1c9ed9999999999aull, 0x0dd39e5c1ccccccdull, 0x129207b63c6bf800ull, 0xdc7b4f91cd5fd889ull}};
} // namespace hsma::golden
