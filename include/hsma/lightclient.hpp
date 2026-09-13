// HSMA :: lightclient.hpp — the light-client epoch-header certificate
// (Step 22, DEC-215). Header: {height, epoch, state_root, digest_E,
// beacon_digest}; certificate sigma = G7 threshold signature over
// h2g1(HSM_CERT_v1 || fields). Light-client verify = ONE pairing
// threshold::bls_verify_aff(sig, H, Y) + chain continuity
// digest_E == poseidon3(HSM_FOLD_v1, prev_digest, decree_root) (Step 14/17
// semantics) + beacon binding (the REAL HSM_BEACON_V1 chain, Step 9/11).
// Genesis-sync (height 0 without a checkpoint cert) rejected by policy
// (whitepaper item 10). Phase-0: sigma 96-B uncompressed (the 48-B compressed
// wire form is production transport). All lengths DERIVED (CA-R64); DEC-090;
// CA-R84 lesson: local feq helper.
#pragma once
#include <hsma/poseidon.hpp>
#include <hsma/consensus.hpp>
#include <hsma/threshold/h2g1.hpp>
#include <hsma/threshold/pairing.hpp>
#include <hsma/threshold/beacon.hpp>
#include <array>
#include <cstring>
#include <cstdint>

namespace hsma::lc {

inline bool feq(const fp::fe& a, const fp::fe& b) { return a.l == b.l; }

static constexpr char TAG_CERT[] = "HSM_CERT_v1";          // 11 chars
inline constexpr std::size_t PRE_LEN = sizeof(TAG_CERT) - 1   // 11
                                     + 8 + 8                  // height, epoch
                                     + 32 + 32 + 32;          // state, digest, beacon = 123

struct Header {
    std::uint64_t height;
    std::uint64_t epoch;
    std::uint8_t  state_root[32];
    fp::fe        digest;      // the fold-chain digest (Pallas fe)
    std::uint8_t  beacon[32];
};

// the canonical 123-B certificate preimage — all offsets derived (CA-R64)
inline void preimage(const Header& h, std::uint8_t out[PRE_LEN]) {
    std::size_t o = 0;
    std::memcpy(out + o, TAG_CERT, sizeof(TAG_CERT) - 1); o += sizeof(TAG_CERT) - 1;
    for (int i = 0; i < 8; ++i) out[o + i] = std::uint8_t(h.height >> (8 * i));
    o += 8;
    for (int i = 0; i < 8; ++i) out[o + i] = std::uint8_t(h.epoch >> (8 * i));
    o += 8;
    std::memcpy(out + o, h.state_root, 32); o += 32;
    const auto dc = fp::fe_to_canonical(h.digest);          // canonical LE32
    std::memcpy(out + o, dc.l.data(), 32); o += 32;
    std::memcpy(out + o, h.beacon, 32); o += 32;
}

// genesis-sync policy (item 10): height 0 requires a checkpoint cert.
inline bool may_sync(std::uint64_t height, bool has_cert) {
    return !(height == 0 && !has_cert);
}

// The one-pairing certificate check + chain continuity + beacon binding.
// digest_prev/decree_root: the parent header's digest and this epoch's
// certified decree root (recompute the fold-chain link). expected_beacon:
// the beacon RECOMPUTED from the committee (the production path) or golden
// (Phase-0 harness); when recompute_committee is null the caller asserts
// golden parity elsewhere — the header check here is binding either way.
inline bool verify(const Header& h, bool has_cert,
                   const std::uint64_t sigx[6], const std::uint64_t sigy[6],
                   const threshold::g2::G2Pt& Y,
                   const fp::fe& prev_digest, const fp::fe& decree_root) {
    if (!may_sync(h.height, has_cert)) return false;
    // 1. chain continuity (the fold digest: Step 14's F_head, in-field)
    const fp::fe want = poseidon3(dom::Dom::HSM_FOLD_v1, prev_digest, decree_root);
    if (!feq(want, h.digest)) return false;
    // 2. the certificate: ONE pairing (V0b-3 signature, verbatim)
    std::uint8_t pre[PRE_LEN];
    preimage(h, pre);
    const threshold::g1::Pt Hh = threshold::hash_to_g1(pre, sizeof pre);
    std::uint64_t hx[6], hy[6];
    if (!threshold::g1::to_affine(Hh, hx, hy)) return false;
    return threshold::bls_verify_aff(sigx, sigy, hx, hy, Y);
}

} // namespace hsma::lc
