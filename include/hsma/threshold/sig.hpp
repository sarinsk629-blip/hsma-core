// HSMA :: threshold/sig.hpp — threshold BLS signing in G1 (Step 9, DEC-191).
// Partials sigma_j = [S_j]H(m); aggregate sigma = sum_j [lambda_j]sigma_j
// with lambda from the Step 7 lagrange_zero kernel. Conformance law
// (harness-secret): sigma == [S]H(m). Pairing verification (e(sigma, -G2) ==
// e(H, Y)) lands with Step 10 per DEC-032/181.
#pragma once
#include <hsma/threshold/g1.hpp>
#include <hsma/threshold/interop.hpp>
#include <hsma/threshold/poly.hpp>
#include <vector>

namespace hsma::threshold::sig {

inline g1::Pt partial(const Fr& S_j, const g1::Pt& H) {
    mont::fe6 k{}; fr_to_fe6(S_j, k);
    return g1::Pmul(H, k);
}

inline g1::Pt aggregate(const std::vector<Fr>& lam, const std::vector<g1::Pt>& parts) {
    g1::Pt s{};
    for (std::size_t i = 0; i < parts.size(); ++i) {
        mont::fe6 k{}; fr_to_fe6(lam[i], k);
        s = g1::Padd(s, g1::Pmul(parts[i], k));
    }
    return s;
}

} // namespace hsma::threshold::sig
