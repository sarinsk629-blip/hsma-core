// HSMA :: cycfold.hpp - P1-07 (GAP-03d + GAP-04, DEC-225).
// The CycleFold absorption primitive: an opaque 512-bit payload (8 canonical
// u64 limbs) -> d = Poseidon_V(CYCLEFOLD, 7-call tree) -> P_cf = [d] * G_vesta.
// CA-R117: limb-wise absorption - each limb < 2^64 < q, injective. NEVER
// mod-reduce an F_p element into F_q (p > q: x in [q,p) collides with x-q).
// CA-R118: Pasta cofactor = 1 (crate evidence) -> no cofactor clearing.
// NOTE: [d]*G is a scalar-mul encoding, not uniform h2c - sufficient for
// CycleFold absorption; try-and-increment upgrades live behind absorb().
#pragma once
#include <hsma/fev.hpp>
#include <hsma/g2v.hpp>
#include <hsma/poseidon_v.hpp>
#include <array>
#include <cstdint>
#include <cstring>

namespace hsma::cyc {
using fq::fev;

// canonical limbs -> Montgomery domain (the proven test_step26 load4 pattern)
inline fev fev_from_limbs(const std::uint64_t c[4]) noexcept {
    fev x{}; for (int i = 0; i < 4; ++i) x.l[i] = c[i];
    fev rr{}; std::memcpy(rr.l.data(), vesta_gen::RR.data(), 32);
    return fq::fev_mul(x, rr);
}

inline fev p3(const fev& l, const fev& r) noexcept {
    return vp3::poseidon3v(0, l, r);   // dom=0: CYCLEFOLD is entry 0 of vp3_iv's table (X0 evidence)
}

// d = tree-absorb the 8 raw limbs (CYCLEFOLD domain at every node)
inline fev digest(const std::uint64_t x[4], const std::uint64_t y[4]) noexcept {
    const fev h0 = p3(fq::fev_from_u64(x[0]), fq::fev_from_u64(x[1]));
    const fev h1 = p3(fq::fev_from_u64(x[2]), fq::fev_from_u64(x[3]));
    const fev h2 = p3(fq::fev_from_u64(y[0]), fq::fev_from_u64(y[1]));
    const fev h3 = p3(fq::fev_from_u64(y[2]), fq::fev_from_u64(y[3]));
    return p3(p3(h0, h1), p3(h2, h3));
}

inline g2v::PtV absorb(const std::uint64_t x[4], const std::uint64_t y[4]) noexcept {
    const fev d = digest(x, y);
    const fev dc = fq::fev_to_canonical(d);
    std::uint64_t k[4]; for (int i = 0; i < 4; ++i) k[i] = dc.l[i];
    return g2v::Vmul(g2v::generator(), k);
}
} // namespace hsma::cyc
