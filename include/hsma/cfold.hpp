// HSMA :: cfold.hpp - P1-12 (GAP-06 commitment folding, DEC-230).
// Commitments to F_p folding vectors live on the ORDER-P GROUP (Vesta,
// pedv) - CA-R137: r_j and the blindings are F_p elements, exact scalars
// for the Vesta group; the Pallas choice would break the identity for
// r_j in [q, p). THE EXACTNESS LEMMA: [z_Ui + r*z_1i] = [z'_i] even
// across the mod-p reduction, because k*p = identity (group order p).
// THE FOLD: W' = W_U + sum r_j*C_Wj (Vesta points), and the binding check:
//   recommit(z'_witness, rho') == W',  rho' = rho_U + sum r_j*rho_j  (F_p).
// HONEST BOUNDARY: openings naive until P1-13's WHIR integration; this
// layer delivers binding + homomorphic + challenge-consistent folding.
#pragma once
#include <hsma/mfold.hpp>
#include <hsma/pedersen.hpp>
#include "pallas_params_gen.hpp"
#include <cstdint>
#include <cstring>

namespace hsma::cfold {

inline fp::fe mk_fe(const std::uint64_t c[4]) noexcept {
    fp::fe x{}; for (int k = 0; k < 4; ++k) x.l[k] = c[k]; return x;
}
inline fp::fe mont_R() noexcept {
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return rr;
}

// Montgomery-encode canonical limbs: x * R mod p (the load4 pattern).
inline fp::fe mont(const fp::fe& canonical) noexcept {
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fp::fe_mul(canonical, rr);
}

inline constexpr unsigned NCOLS = 8u;   // z width = the Pedersen batch width

inline void to_batches(const std::vector<fp::fe>& z, std::uint64_t out[NCOLS][4]) noexcept {
    for (unsigned i = 0; i < NCOLS; ++i)
        for (int k = 0; k < 4; ++k) out[i][k] = 0;
    for (unsigned i = 0; i < NCOLS && i < z.size(); ++i) {
        fp::fe c = fp::fe_to_canonical(z[i]);
        for (int k = 0; k < 4; ++k) out[i][k] = c.l[k];
    }
}

struct CommittedInstance {
    mfold::Relaxed rel{};
    g2v::PtV W{};                    // pedv commitment over the 8 z-coordinates
    std::uint64_t rho[4] = {0,0,0,0};// blinding (canonical F_p limbs)
};

// rho is INPUT (golden-pinned by the emitter's DRBG) - no hidden derivation.
inline CommittedInstance commit_instance(const mfold::Relaxed& R,
                                         const std::uint64_t rho[4],
                                         const std::uint64_t ORDER[4]) noexcept {
    CommittedInstance Ci;
    Ci.rel = R;
    for (int k = 0; k < 4; ++k) Ci.rho[k] = rho[k];
    std::uint64_t m[NCOLS][4];
    to_batches(R.z, m);
    Ci.W = pedv::commit(m, Ci.rho, ORDER);
    return Ci;
}

// THE COMMITMENT FOLD: W' = W_U + sum r_j * C_Wj  (r_j: F_p = exact scalars).
inline g2v::PtV fold_commitments(const CommittedInstance& U,
                                 const std::vector<CommittedInstance>& js,
                                 const std::vector<fp::fe>& r) noexcept {
    g2v::PtV acc = U.W;
    for (std::size_t j = 0; j < js.size(); ++j) {
        const fp::fe rj = fp::fe_to_canonical(r[j]);
        acc = g2v::Vadd(acc, g2v::Vmul(js[j].W, rj.l.data()));
    }
    return acc;
}

// THE BINDING CHECK (the verifier's recomputation, no witness knowledge of
// blindings beyond the pinned rho): recommit(z', rho') == fold_commitments.
inline bool commitment_consistent(const CommittedInstance& U,
                                  const std::vector<CommittedInstance>& js,
                                  const mfold::MultifoldResult& MF,
                                  const std::uint64_t ORDER[4]) noexcept {
    // rho' = rho_U + sum r_j*rho_j   (F_p arithmetic - fev NOT needed:
    // rho and r_j are F_p; use fp::fe)
    // CA-R141 (rev 2): build fe values from canonical limbs by DIRECT limb
    // copy into the struct (the fe aggregate), then Montgomery-encode via
    // fe_mul(x, RR) - the identical path the golden load4 helpers use.
    // CA-R141 (rev 3 - the domain law): MF.r[j] is ALREADY Montgomery-domain
    // (it is an fp::fe straight from the fold arithmetic). Stripping it via
    // fe_to_canonical and multiplying with a Montgomery operand MIXES domains
    // (canonical x Montgomery = canonical product; the add then corrupts).
    // Correct: Montgomery throughout - Mont(rho_U) + MF.r[j]*Mont(rho_j)
    // = Mont(rho_U + r_j*rho_j); ONE canonical strip at the end.
    fp::fe rho_p = fp::fe_mul(mk_fe(U.rho), mont_R());
    for (std::size_t j = 0; j < js.size(); ++j) {
        const fp::fe rho = fp::fe_mul(mk_fe(js[j].rho), mont_R());
        rho_p = fp::fe_add(rho_p, fp::fe_mul(MF.r[j], rho));
    }
    fp::fe rpc = fp::fe_to_canonical(rho_p);
    std::uint64_t rr[4]; for (int k = 0; k < 4; ++k) rr[k] = rpc.l[k];
    std::uint64_t mm[NCOLS][4];
    to_batches(MF.folded.z, mm);
    g2v::PtV Wre = pedv::commit(mm, rr, ORDER);
    g2v::PtV Wfo = fold_commitments(U, js, MF.r);
    // affine coords on Vesta live in F_q (fev), not F_p - CA-R137's mirror:
    // the POINTS are Vesta points; only the folded SCALARS are F_p.
    fq::fev x1, y1, x2, y2;
    if (!g2v::to_affine(Wre, x1, y1) || !g2v::to_affine(Wfo, x2, y2)) return false;
    const fq::fev x1c = fq::fev_to_canonical(x1), x2c = fq::fev_to_canonical(x2);
    const fq::fev y1c = fq::fev_to_canonical(y1), y2c = fq::fev_to_canonical(y2);
    return x1c.l == x2c.l && y1c.l == y2c.l;
}

} // namespace hsma::cfold
