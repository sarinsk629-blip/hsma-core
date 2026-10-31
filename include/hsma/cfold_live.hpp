// HSMA :: cfold_live.hpp — P5 (DEC-408/409): the dual-layer commitment chain,
// LIVE. This is the production committed-instance layer that closes GAP-05's
// last integration step: the golden-pinned cfold.hpp (DEC-230) proves the
// algebra at toy width; THIS header runs the same laws on the node's real
// fold path, over the FULL z via pedv::commit_vec (per-position distinct
// bases, DEC-263 — the CA-R187 kernel-shift attack is closed by construction).
//
// THE LAWS:
//   RHO LABEL  : rho_entry = scalar(SHA256("HSMA_CFOLD_RHO|" || epoch_le4 ||
//                idx_le8 || d_le32)) — deterministic network-wide, bound to
//                the entry content (no grind-across-entries). rho_init =
//                scalar(SHA256("HSMA_CFOLD_RHO|init" || epoch_le4)).
//   COMMIT     : W_j = commit_vec(z_j, rho_j) — 16 distinct bases (NZ=16).
//   FOLD       : W' = W + r_j·W_j ; rho' = rho + r_j·rho_j  (the SAME r_j the
//                multifold_v2 transcript produced — one challenge, two chains).
//   SELF-CHECK : recommit(z', rho') == W'  after EVERY fold (17 scalar mults,
//                fail-fast). CA-R141 rev 3 domain law: rho arithmetic in the
//                Montgomery domain throughout; commit_vec takes canonical.
//   WIRE       : W' rides the epoch header compressed (pcompress 32-B);
//                z'||E'||u (the instance opening) rides beside it — the
//                verifier's dual binding:
//                  (1) recommit(z', rho') == W'           [group law]
//                  (2) C_piE == Sponge(z'||E'||u)          [hash↔group link]
//                  (3) W-chain continuity across epochs   [homomorphic audit]
//                Every input to all three is public: the commitment chain is
//                independently auditable WITHOUT any witness.
//   PRIVACY    : unchanged. All committed values are the post-decryption
//                execution spine (the f_exec transition wires); the mempool
//                layer's pre-decryption confidentiality is untouched.
#pragma once
#include <hsma/mfold.hpp>
#include <hsma/pedersen.hpp>
#include <hsma/pcompress.hpp>
#include <hsma/sha256.hpp>
#include "pallas_params_gen.hpp"
#include <cstdint>
#include <cstring>
#include <vector>

namespace hsma::cflive {

inline constexpr unsigned NZ_LIVE = 16u;   // the node's z width (fexec_circuit NZ)

// ---- the rho label law ----
inline bool rho_label(unsigned epoch, std::uint64_t idx, const fp::fe& d,
                      std::uint64_t out[4]) noexcept {
    std::uint8_t msg[15 + 4 + 8 + 32];
    std::memcpy(msg, "HSMA_CFOLD_RHO|", 15);
    for (int i = 0; i < 4; ++i) msg[15 + i] = (std::uint8_t)(epoch >> (8 * i));
    for (int i = 0; i < 8; ++i) msg[19 + i] = (std::uint8_t)(idx >> (8 * i));
    std::byte db[32];
    fp::fe_to_le_bytes(d, db);                          // canonicalizes (CA-R132)
    std::memcpy(msg + 27, db, 32);
    std::uint8_t dg[32];
    ::hsma::digest::sha256(msg, sizeof(msg), dg);
    return pedutil::scalar_from_digest(dg, pallas_gen::MOD.data(), out);
}
inline bool rho_label_init(unsigned epoch, std::uint64_t out[4]) noexcept {
    std::uint8_t msg[19 + 4];
    std::memcpy(msg, "HSMA_CFOLD_RHO|init", 19);
    for (int i = 0; i < 4; ++i) msg[19 + i] = (std::uint8_t)(epoch >> (8 * i));
    std::uint8_t dg[32];
    ::hsma::digest::sha256(msg, sizeof(msg), dg);
    return pedutil::scalar_from_digest(dg, pallas_gen::MOD.data(), out);
}

// ---- the commitment (canonicalized z; per-position bases) ----
inline g2v::PtV commit_z(const std::vector<fp::fe>& z, const std::uint64_t rho4[4]) noexcept {
    std::vector<fp::fe> c(z.size());
    for (std::size_t i = 0; i < z.size(); ++i) c[i] = fp::fe_to_canonical(z[i]);
    return pedv::commit_vec(c, rho4, pallas_gen::MOD.data());
}
inline bool rho_to_limbs(const fp::fe& rho_m, std::uint64_t out[4]) noexcept {
    const fp::fe rc = fp::fe_to_canonical(rho_m);
    for (int k = 0; k < 4; ++k) out[k] = rc.l[k];
    return true;
}

// ---- the live committed accumulator ----
struct LiveW {
    g2v::PtV W{};      // the running commitment (Jacobian)
    fp::fe rho{};      // the running blinding (Montgomery)
};

// genesis: the committed accumulator opens at the fresh instance
inline LiveW init_live(const std::vector<fp::fe>& z, unsigned epoch) noexcept {
    LiveW L;
    std::uint64_t r4[4];
    if (!rho_label_init(epoch, r4)) { /* unreachable: 32-B digest */ }
    std::array<std::uint64_t, 4> ra{};
    for (int k = 0; k < 4; ++k) ra[k] = r4[k];
    L.rho = fp::fe_from_canonical_limbs(ra);
    L.W = commit_z(z, r4);
    return L;
}

// THE ADVANCE (k=1, the node's live shape): r_j from the multifold_v2 result.
// W' = W + r·W_j ; rho' = rho + r·rho_j  — Montgomery throughout (CA-R141 r3).
inline void advance(LiveW& acc, const g2v::PtV& W_j, const fp::fe& rho_j_m,
                    const fp::fe& r_m) noexcept {
    acc.W = g2v::Vadd(acc.W, g2v::Vmul(W_j, fp::fe_to_canonical(r_m).l.data()));
    acc.rho = fp::fe_add(acc.rho, fp::fe_mul(r_m, rho_j_m));
}

// THE BINDING SELF-CHECK: recommit(z', rho') == W'
inline bool self_check(const std::vector<fp::fe>& z, const fp::fe& rho_m,
                       const g2v::PtV& W) noexcept {
    std::uint64_t r4[4];
    rho_to_limbs(rho_m, r4);
    const g2v::PtV Wre = commit_z(z, r4);
    fq::fev x1, y1, x2, y2;
    if (!g2v::to_affine(Wre, x1, y1) || !g2v::to_affine(W, x2, y2)) return false;
    const fq::fev x1c = fq::fev_to_canonical(x1), x2c = fq::fev_to_canonical(x2);
    const fq::fev y1c = fq::fev_to_canonical(y1), y2c = fq::fev_to_canonical(y2);
    return x1c.l == x2c.l && y1c.l == y2c.l;
}

// ---- the verifier's dual binding (public inputs only) ----
// (1) recommit(z', rho') == W'          — the group law
inline bool verify_recommit(const std::vector<fp::fe>& z, const std::uint64_t rho4[4],
                            const g2v::PtV& W) noexcept {
    std::array<std::uint64_t, 4> ra{};
    for (int k = 0; k < 4; ++k) ra[k] = rho4[k];
    return self_check(z, fp::fe_from_canonical_limbs(ra), W);
}
// (2) C_piE == Sponge(HSM_SUMCHECK_v1, z'||E'||u) — the hash↔group link.
//     evals = z' || E' || u, padded with zeros to the next power of two (the
//     wrap_open padding law).
inline bool verify_C_link(const std::vector<fp::fe>& z, const std::vector<fp::fe>& E,
                          const fp::fe& u, const fp::fe& C_piE) noexcept {
    std::vector<fp::fe> evals;
    for (const auto& v : z) evals.push_back(v);
    for (const auto& e : E) evals.push_back(e);
    evals.push_back(u);
    std::size_t npad = 1; while (npad < evals.size()) npad <<= 1;
    while (evals.size() < npad) evals.push_back(fp::fe_zero());
    fp::Sponge sp(dom::Dom::HSM_SUMCHECK_v1);
    for (const auto& v : evals) sp.absorb(v);
    const fp::fe Cex = sp.squeeze();
    return fp::fe_to_canonical(Cex).l == fp::fe_to_canonical(C_piE).l;
}
// (3) the compressed 32-B carrier for W' on the epoch header
inline bool W_put(const g2v::PtV& W, std::uint8_t out[32]) noexcept {
    return pcompress::compress_v(W, out);
}
inline bool W_get(const std::uint8_t in[32], g2v::PtV& W) noexcept {
    return pcompress::decompress_v(in, W);
}

} // namespace hsma::cflive
