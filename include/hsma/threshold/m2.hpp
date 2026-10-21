// HSMA :: threshold/m2.hpp — order-bound decryption shares (Step 12, DEC-201..203).
// G2-plane threshold KEM (unified X_E = Y2, DEC-030), Phase-0 DEM (SHA-256-CTR + tag,
// DEC-201; DEC-088 profiles deferred), order-bound records (HSM_DEC_SHARE_v2).
// Share verification = the pairing identity (10-B); attestation = bls_verify_aff (10-B).
// Tags derived via sizeof-1 (CA-R43); DEC-127; DEC-090.
#pragma once
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/h2g1.hpp>
#include <hsma/threshold/sig.hpp>
#include <hsma/threshold/pairing.hpp>
#include <hsma/threshold/scalar_r.hpp>
#include <hsma/threshold/interop.hpp>
#include <hsma/sha256.hpp>
#include <vector>
#include <cstring>

namespace hsma::threshold::m2 {

static constexpr char TAG_KDF[]   = "HSM_KDF_V1";
static constexpr char TAG_DEM[]   = "HSM_DEM_V1";
static constexpr char TAG_DTAG[]  = "HSM_DEM_TAG_V1";
static constexpr char TAG_CT[]    = "HSM_CT_V1";
static constexpr char TAG_ORD[]   = "HSM_ORDER_V1";
static constexpr char TAG_OROOT[] = "HSM_ORDROOT_V1";
static constexpr char TAG_SHR[]   = "HSM_DEC_SHARE_V2";

inline bool ser_g2(const g2::G2Pt& P, std::uint8_t out[192]) {
    std::uint64_t xa[6], xb[6], ya[6], yb[6];
    if (!g2::to_affine(P, xa, xb, ya, yb)) return false;
    const std::uint64_t* c[4] = { xa, xb, ya, yb };
    for (int i = 0; i < 4; ++i)
        for (int k = 0; k < 6; ++k)
            for (int b = 0; b < 8; ++b)
                out[i*48 + k*8 + b] = std::uint8_t(c[i][k] >> (8*b));
    return true;
}

inline void ser_hdr(std::uint8_t out[56], std::uint64_t epoch,
                    const std::uint8_t sender[32], std::uint64_t nonce, std::uint64_t fee) {
    for (int i = 0; i < 8; ++i) out[i]      = std::uint8_t(epoch >> (8*i));
    std::memcpy(out + 8, sender, 32);
    for (int i = 0; i < 8; ++i) out[40 + i] = std::uint8_t(nonce >> (8*i));
    for (int i = 0; i < 8; ++i) out[48 + i] = std::uint8_t(fee  >> (8*i));
}

inline void kdf(std::uint8_t out[32], const std::uint8_t ss[192],
                const std::uint8_t xe[192], const std::uint8_t hd[56]) {
    std::uint8_t buf[450];
    std::memcpy(buf, TAG_KDF, sizeof(TAG_KDF) - 1);
    std::memcpy(buf + 10, ss, 192);
    std::memcpy(buf + 202, xe, 192);
    std::memcpy(buf + 394, hd, 56);
    digest::sha256(buf, 450, out);
}

inline void dem_ks(std::uint8_t out[32], const std::uint8_t k[32], std::uint64_t blk) {
    std::uint8_t buf[50];
    std::memcpy(buf, TAG_DEM, sizeof(TAG_DEM) - 1);
    std::memcpy(buf + 10, k, 32);
    for (int b = 0; b < 8; ++b) buf[42 + b] = std::uint8_t(blk >> (8*b));
    digest::sha256(buf, 50, out);
}

inline void dem_tag(std::uint8_t out[32], const std::uint8_t k[32],
                    const std::uint8_t hd[56], const std::uint8_t* ct, std::size_t n) {
    digest::Sha256 h;
    h.update(reinterpret_cast<const std::uint8_t*>(TAG_DTAG), sizeof(TAG_DTAG) - 1);
    h.update(k, 32); h.update(hd, 56); h.update(ct, n);
    h.finish(out);
}

inline void dem_encrypt(std::vector<std::uint8_t>& ct, std::uint8_t tag[32],
                        const std::uint8_t k[32], const std::uint8_t hd[56],
                        const std::uint8_t* pl, std::size_t n) {
    ct.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t blk[32]; dem_ks(blk, k, i / 32);
        ct[i] = pl[i] ^ blk[i % 32];
    }
    dem_tag(tag, k, hd, ct.data(), n);
}

inline bool dem_decrypt(std::vector<std::uint8_t>& pl, const std::uint8_t k[32],
                        const std::uint8_t hd[56], const std::uint8_t* ct, std::size_t n,
                        const std::uint8_t tag[32]) {
    pl.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t blk[32]; dem_ks(blk, k, i / 32);
        pl[i] = ct[i] ^ blk[i % 32];
    }
    std::uint8_t t[32]; dem_tag(t, k, hd, ct, n);
    return std::memcmp(t, tag, 32) == 0;
}

inline void ct_hash(std::uint8_t out[32], const std::uint8_t rs[192],
                    const std::uint8_t* ct, std::size_t n) {
    digest::Sha256 h;
    h.update(reinterpret_cast<const std::uint8_t*>(TAG_CT), sizeof(TAG_CT) - 1);
    h.update(rs, 192); h.update(ct, n);
    h.finish(out);
}

inline void sort_key(std::uint8_t out[32], const std::uint8_t beacon[32],
                     const std::uint8_t cth[32]) {
    std::uint8_t buf[76];
    std::memcpy(buf, TAG_ORD, sizeof(TAG_ORD) - 1);
    std::memcpy(buf + 12, beacon, 32);
    std::memcpy(buf + 44, cth, 32);
    digest::sha256(buf, 76, out);
}

inline void order_root(std::uint8_t out[32],
                       const std::uint8_t sorted[][32], std::size_t n) {
    digest::Sha256 h;
    h.update(reinterpret_cast<const std::uint8_t*>(TAG_OROOT), sizeof(TAG_OROOT) - 1);
    for (std::size_t i = 0; i < n; ++i) h.update(sorted[i], 32);
    h.finish(out);
}

inline g2::G2Pt dec_share(const std::uint64_t s_canon[6], const g2::G2Pt& R) {
    mont::fe6 k{};
    for (int i = 0; i < 6; ++i) k[i] = s_canon[i];
    return g2::Pmul(R, k);
}

// THE pairing identity (whitepaper item 6): e(G1gen, D_j) == e(Y1_j, R)
inline bool verify_share(const g2::G2Pt& D, const g1::Pt& Y1, const g2::G2Pt& R) {
    std::uint64_t gx[6], gy[6], jx[6], jy[6];
    if (!g1::to_affine(g1::gen(), gx, gy)) return false;
    if (!g1::to_affine(Y1, jx, jy)) return false;
    return fq12_eq(pairing(gx, gy, D), pairing(jx, jy, R));
}

inline bool dec_preimage(std::uint8_t out[280], std::uint64_t epoch,
                         const std::uint8_t oroot[32], const std::uint8_t cth[32],
                         const g2::G2Pt& D) {
    std::memcpy(out, TAG_SHR, sizeof(TAG_SHR) - 1);
    for (int i = 0; i < 8; ++i) out[16 + i] = std::uint8_t(epoch >> (8*i));
    std::memcpy(out + 24, oroot, 32);
    std::memcpy(out + 56, cth, 32);
    return ser_g2(D, out + 88);
}

inline g1::Pt attest(const Fr& s_j, std::uint64_t epoch, const std::uint8_t oroot[32],
                     const std::uint8_t cth[32], const g2::G2Pt& D) {
    std::uint8_t pre[280];
    if (!dec_preimage(pre, epoch, oroot, cth, D)) return g1::Pt{};
    return sig::partial(s_j, hash_to_g1(pre, sizeof pre));
}

// e(sigma_j, G2gen) == e(H(pre), Y2_j) — bls_verify_aff, the 10-B law, direct reuse
inline bool verify_attest(const g1::Pt& sig, std::uint64_t epoch,
                          const std::uint8_t oroot[32], const std::uint8_t cth[32],
                          const g2::G2Pt& D, const g2::G2Pt& Y2) {
    std::uint8_t pre[280];
    if (!dec_preimage(pre, epoch, oroot, cth, D)) return false;
    const g1::Pt H = hash_to_g1(pre, sizeof pre);
    std::uint64_t sx[6], sy[6], hx[6], hy[6];
    if (!g1::to_affine(sig, sx, sy)) return false;
    if (!g1::to_affine(H, hx, hy)) return false;
    return bls_verify_aff(sx, sy, hx, hy, Y2);
}

inline g2::G2Pt aggregate_shares(const std::uint64_t lams[][6],
                                 const std::vector<g2::G2Pt>& Ds) {
    g2::G2Pt D{};
    for (std::size_t i = 0; i < Ds.size(); ++i) {
        mont::fe6 l{};
        for (int t = 0; t < 6; ++t) l[t] = lams[i][t];
        D = g2::Padd(D, g2::Pmul(Ds[i], l));
    }
    return D;
}

// ── P3-A (Zero-MEV production): share authentication + aggregate audit ──────
// Hot path: Chaum-Pedersen DLEQ over G2 ONLY — proves log_G(Y_j) == log_R(D_j)
// with ~2 scalar muls, NO pairing (the 10-B pairing identity per share would
// cost 203ms x 2 x n at n=224). The pairing remains the ASYNC AUDIT law:
// verify_aggregate below checks the committed aggregate once per envelope.
static constexpr char TAG_DLEQ[] = "HSM_DLEQ_V1";

inline bool ser_g2_or_inf(const g2::G2Pt& P, std::uint8_t out[193]) {
    if (g2::PisInf(P)) { out[0] = 0; std::memset(out + 1, 0, 192); return true; }
    out[0] = 1;
    return ser_g2(P, out + 1);
}

// G2 equality in the m2 plane (affine compare, both-inf == equal).
inline bool g2_eq(const g2::G2Pt& A, const g2::G2Pt& B) {
    std::uint64_t ax[6], axb[6], ay[6], ayb[6], bx[6], bxb[6], by[6], byb[6];
    const bool aok = g2::to_affine(A, ax, axb, ay, ayb);
    const bool bok = g2::to_affine(B, bx, bxb, by, byb);
    if (!aok && !bok) return true;
    if (aok != bok) return false;
    return std::memcmp(ax, bx, 48) == 0 && std::memcmp(ay, by, 48) == 0;
}

// canonical 32-byte serialization of an Fr (exits Montgomery via the x1 law)
inline void fr_ser(std::uint8_t out[32], const Fr& s) {
    mont::fe6 c{}; fr_to_fe6(s, c);
    for (int i = 0; i < 4; ++i)
        for (int b = 0; b < 8; ++b)
            out[i*8 + b] = std::uint8_t(c[i] >> (8*b));
    std::memset(out + 32, 0, 16);
}

// 253-bit scalar from a digest: mask to 253 bits, then reject-resample with a
// rehash counter. r ~ 0.66 * 2^253 -> 34% rejection per draw; 64 draws give a
// ~10^-30 exhaustion bound (the unmasked 256-bit law rejects 92%/draw and
// exhausts with ~0.7% probability per prove — measured, and fatal at t=112).
inline bool fr_from_digest(Fr& out, const std::uint8_t d0[32],
                           const std::uint8_t stmt[], std::size_t n,
                           std::uint8_t ctr0) {
    std::uint8_t ctr = ctr0;
    while (ctr < 64) {
        std::uint8_t d[32];
        if (ctr == ctr0) {
            std::memcpy(d, d0, 32);              // first draw: reuse the caller's digest
        } else {
            digest::Sha256 h;
            h.update(d0, 32);
            h.update(stmt, n);
            h.update(&ctr, 1);
            h.finish(d);
        }
        d[31] &= 0x1F;                           // uniform in [0, 2^253)
        std::uint64_t lim[4];
        for (int i = 0; i < 4; ++i) {
            lim[i] = 0;
            for (int b = 0; b < 8; ++b) lim[i] |= std::uint64_t(d[i*8 + b]) << (8*b);
        }
        if (fr_from_limbs(out, lim)) return true;
        ++ctr;
    }
    return false;
}

// 253-bit Fiat-Shamir challenge over the statement bytes.
inline Fr dleq_challenge(const std::uint8_t stmt[], std::size_t n) {
    digest::Sha256 h;
    h.update(reinterpret_cast<const std::uint8_t*>(TAG_DLEQ), sizeof(TAG_DLEQ) - 1);
    h.update(stmt, n);
    std::uint8_t d0[32]; h.finish(d0);
    Fr c{};
    if (!fr_from_digest(c, d0, stmt, n, 0)) return fr_one();  // unreachable
    return c;
}

struct Dleq { g2::G2Pt A1{}, A2{}; Fr z{}; };

// Deterministic nonce (EdDSA RFC-8032 pattern): k = H(canonical(s) || stmt).
// Distinct statements -> distinct k; re-proving the same statement leaks nothing.
inline bool dleq_prove(Dleq& p, const Fr& s, const g2::G2Pt& R,
                       const g2::G2Pt& Y, const g2::G2Pt& D) {
    std::uint8_t rs[193], ys[193], ds[193], sb[48];
    if (!ser_g2_or_inf(R, rs)) return false;
    if (!ser_g2_or_inf(Y, ys)) return false;
    if (!ser_g2_or_inf(D, ds)) return false;
    fr_ser(sb, s);
    digest::Sha256 h;
    h.update(reinterpret_cast<const std::uint8_t*>(TAG_DLEQ), sizeof(TAG_DLEQ) - 1);
    h.update(sb, 48); h.update(rs, 193); h.update(ys, 193); h.update(ds, 193);
    std::uint8_t kd[32]; h.finish(kd);
    Fr k{};
    if (!fr_from_digest(k, kd, ds, 193, 0)) return false;   // counter-rehash law
    mont::fe6 kk{}; fr_to_fe6(k, kk);
    p.A1 = g2::Pmul(g2::gen(), kk);            // [k]G
    p.A2 = g2::Pmul(R, kk);                    // [k]R
    // statement digest for the challenge
    std::uint8_t a1s[193], a2s[193];
    if (!ser_g2_or_inf(p.A1, a1s) || !ser_g2_or_inf(p.A2, a2s)) return false;
    std::uint8_t stbuf[10 + 193*5];
    std::memcpy(stbuf, TAG_DLEQ, sizeof(TAG_DLEQ) - 1);
    std::memcpy(stbuf + 10, rs, 193); std::memcpy(stbuf + 203, ys, 193);
    std::memcpy(stbuf + 396, ds, 193); std::memcpy(stbuf + 589, a1s, 193);
    std::memcpy(stbuf + 782, a2s, 193);
    const Fr c = dleq_challenge(stbuf, sizeof stbuf);   // c = H(stmt)
    p.z = fr_add(k, fr_mul(c, s));              // z = k + c*s
    return true;
}

// Verifier: [z]G == A1 + [c]Y  AND  [z]R == A2 + [c]D  (two G2 mul-adds, no pairing)
inline bool dleq_verify(const Dleq& p, const g2::G2Pt& R,
                        const g2::G2Pt& Y, const g2::G2Pt& D) {
    std::uint8_t rs[193], ys[193], ds[193], a1s[193], a2s[193];
    if (!ser_g2_or_inf(R, rs) || !ser_g2_or_inf(Y, ys) ||
        !ser_g2_or_inf(D, ds) || !ser_g2_or_inf(p.A1, a1s) ||
        !ser_g2_or_inf(p.A2, a2s)) return false;
    std::uint8_t stbuf[10 + 193*5];
    std::memcpy(stbuf, TAG_DLEQ, sizeof(TAG_DLEQ) - 1);
    std::memcpy(stbuf + 10, rs, 193); std::memcpy(stbuf + 203, ys, 193);
    std::memcpy(stbuf + 396, ds, 193); std::memcpy(stbuf + 589, a1s, 193);
    std::memcpy(stbuf + 782, a2s, 193);
    const Fr c = dleq_challenge(stbuf, sizeof stbuf);
    mont::fe6 zk{}, ck{};
    fr_to_fe6(p.z, zk); fr_to_fe6(c, ck);
    const g2::G2Pt lhs1 = g2::Pmul(g2::gen(), zk);
    const g2::G2Pt rhs1 = g2::Padd(p.A1, g2::Pmul(Y, ck));
    if (!g2_eq(lhs1, rhs1)) return false;
    const g2::G2Pt lhs2 = g2::Pmul(R, zk);
    const g2::G2Pt rhs2 = g2::Padd(p.A2, g2::Pmul(D, ck));
    return g2_eq(lhs2, rhs2);
}

// THE AGGREGATE AUDIT LAW (async): e(G1gen, D_agg) == e(Y1_agg, R).
// D_agg = [f(0)]R and Y1_agg = [f(0)]G1gen — the pairing identity lifted to
// the threshold aggregate. One pairing pair per envelope, run OFF the hot path
// (audit/slash); share-level honesty is enforced inline by DLEQ.
inline bool verify_aggregate(const g2::G2Pt& D_agg, const g1::Pt& Y1_agg,
                             const g2::G2Pt& R) {
    std::uint64_t gx[6], gy[6];
    if (!g1::to_affine(g1::gen(), gx, gy)) return false;
    std::uint64_t yx[6], yy[6];
    if (!g1::to_affine(Y1_agg, yx, yy)) return false;   // inf Y1_agg -> reject
    return fq12_eq(pairing(gx, gy, D_agg), pairing(yx, yy, R));
}

// Blame scan (decrypt-failure forensics): re-verify every DLEQ against the
// transcript publics; a failed DLEQ names the misbehaving member. If ALL pass,
// the shares are honest and the fault is the ENVELOPE (sender blame — the cth
// is the slashing evidence).
inline void blame_scan(std::vector<std::uint64_t>& bad_members,
                       const std::vector<std::pair<std::uint64_t, g2::G2Pt>>& shares,
                       const std::vector<Dleq>& proofs,
                       const std::vector<g2::G2Pt>& Ys,   // Ys[i] = T.Y[shares[i].first]
                       const g2::G2Pt& R) {
    bad_members.clear();
    if (shares.size() != proofs.size() || shares.size() != Ys.size()) {
        bad_members.push_back(0);   // caller contract violation: blame the reporter
        return;
    }
    for (std::size_t i = 0; i < shares.size(); ++i)
        if (!dleq_verify(proofs[i], R, Ys[i], shares[i].second))
            bad_members.push_back(shares[i].first);
}

} // namespace hsma::threshold::m2
