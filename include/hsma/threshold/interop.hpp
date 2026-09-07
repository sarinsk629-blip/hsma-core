// HSMA :: threshold/interop.hpp — Fr (4-limb Montgomery) -> canonical fe6 (Step 9).
// CANONICALIZATION LAW (kernel): multiply by RAW 1, never by R, to exit Montgomery:
//   mont_mul(v*R, 1) = v. Zero-extended to 6 limbs; canonical [0, r) < 2^253.
#pragma once
#include <hsma/threshold/scalar_r.hpp>
#include <hsma/threshold/mont384.hpp>

namespace hsma::threshold {

inline void fr_to_fe6(const Fr& a, mont::fe6& out) {
    static const std::uint64_t raw1[4] = { 1, 0, 0, 0 };
    const Fr c = detail::mont_mul(a, detail::mk(raw1));   // a * 1 * R^-1 = canonical
    out = mont::fe6{};                                    // DEC-127
    out[0] = c.d[0]; out[1] = c.d[1]; out[2] = c.d[2]; out[3] = c.d[3];
}

} // namespace hsma::threshold
