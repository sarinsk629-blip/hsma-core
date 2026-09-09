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

} // namespace hsma::threshold::m2
