// HSMA :: m2envelope.hpp - P4-1 (DEC-276): the encrypted mempool envelope.
// The sender-side encryption + the wire format for the Commit-then-Simulate
// ceremony. Wires the PROVEN m2.hpp primitives: kdf, dem_encrypt, ct_hash.
//
// THE FLOW: the sender picks r, computes R = [r]G2gen and ss = [r]X_E
// (the committee's aggregate public key), derives the DEM key via kdf,
// encrypts the payload, and gossips the envelope {R, ct, tag, ct_hash}.
// NOBODY can decrypt without t-of-n committee shares.
//
// WIRE FORMAT (type 0x07): R(192) || ct_len(4) || ct || tag(32) || cth(32)
#pragma once
#include <hsma/threshold/m2.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/p2p.hpp>
#include <vector>
#include <cstring>

namespace hsma::m2env {

using threshold::g2::G2Pt;

// ---- the sender's encryption --------------------------------------------
struct Envelope {
    G2Pt R{};                              // the ephemeral public key
    std::vector<std::uint8_t> ct;          // the encrypted payload
    std::uint8_t tag[32]{};                // the DEM integrity tag
    std::uint8_t cth[32]{};                // the ciphertext hash
    std::uint8_t hdr[56]{};                // the header (epoch + metadata)
};

// ser_g2: m2.hpp's own G2 serializer (192 bytes)
inline std::vector<std::uint8_t> pt_to_bytes(const G2Pt& P) noexcept {
    std::uint8_t buf[192];
    threshold::m2::ser_g2(P, buf);
    return std::vector<std::uint8_t>(buf, buf + 192);
}

// the sender: encrypt payload under the committee's X_E
// (X_E is the aggregate public key: X_E = Y2 = [S]G2gen from DEC-030)
inline Envelope encrypt(
    const std::vector<std::uint8_t>& payload,
    const G2Pt& X_E,
    std::uint64_t epoch) noexcept
{
    Envelope env;

    // (1) the ephemeral keypair: r random, R = [r]G2gen
    // (testnet: r is deterministic for the probe; production uses RNG)
    // the shared secret: ss = [r]X_E (the sender computes it from the public key)
    // for the testnet probe: r = a fixed scalar, ss = [r]X_E
    threshold::Fr r_fr{}; threshold::fr_from_u64(r_fr, 42);  // testnet: r=42, production: RNG
    threshold::mont::fe6 rk{}; threshold::fr_to_fe6(r_fr, rk);
    // ss = [r]X_E
    G2Pt ss_pt = threshold::g2::Pmul(X_E, rk);
    auto ss = pt_to_bytes(ss_pt);
    auto xe = pt_to_bytes(X_E);

    // (2) the header: 56 bytes (epoch + flags + reserved)
    {
    std::uint8_t sender[32] = {};   // testnet: zero sender
    threshold::m2::ser_hdr(env.hdr, epoch, sender, 0, 0);
}

    // (3) the DEM key
    std::uint8_t k[32];
    threshold::m2::kdf(k, ss.data(), xe.data(), env.hdr);

    // (4) the encryption
    env.ct = payload;
    threshold::m2::dem_encrypt(env.ct, env.tag, k, env.hdr, payload.data(), payload.size());
    // the ciphertext's hash (for ordering)
    // the R serialization feeds ct_hash
    auto r_ser = pt_to_bytes(env.R);
    threshold::m2::ct_hash(env.cth, r_ser.data(), env.ct.data(), env.ct.size());

    // (5) the ephemeral R: for the probe, R = [r]G2gen
    // (we need a G2gen call - the rk is the scalar)
    env.R = threshold::g2::Pmul(threshold::g2::gen(), rk);

    return env;
}

// ---- the wire format ------------------------------------------------------
inline p2p::Message encode_envelope(const Envelope& env) noexcept {
    p2p::Message m; m.type = 0x07;   // ENVELOPE
    auto r_ser = pt_to_bytes(env.R);
    m.payload.insert(m.payload.end(), r_ser.begin(), r_ser.end());   // 192
    m.payload.insert(m.payload.end(), env.hdr, env.hdr + 56);        // 56 (CA-R203: carried, not assumed)
    std::uint8_t cl[4];
    std::uint32_t ctlen = (std::uint32_t)env.ct.size();
    for (int i = 3; i >= 0; --i) cl[i] = std::uint8_t(ctlen >> (8*(3-i)));
    m.payload.insert(m.payload.end(), cl, cl + 4);
    m.payload.insert(m.payload.end(), env.ct.begin(), env.ct.end());
    m.payload.insert(m.payload.end(), env.tag, env.tag + 32);
    m.payload.insert(m.payload.end(), env.cth, env.cth + 32);
    return m;
}

struct DecodedEnvelope {
    G2Pt R{};
    std::uint8_t hdr[56]{};   // CA-R203: carried from the wire
    std::vector<std::uint8_t> ct;
    std::uint8_t tag[32]{};
    std::uint8_t cth[32]{};
    bool ok = false;
};
inline DecodedEnvelope decode_envelope(const p2p::Message& m) noexcept {
    DecodedEnvelope d{};
    if (m.type != 0x07 || m.payload.size() < 192 + 56 + 4 + 32 + 32) return d;
    const std::uint8_t* p = m.payload.data();
    // R from 192 bytes
    std::uint64_t xa[6], xb[6], ya[6], yb[6];
    for (int i = 0; i < 6; ++i) { xa[i]=0; xb[i]=0; ya[i]=0; yb[i]=0;
        for (int b = 0; b < 8; ++b) {
            xa[i] |= (std::uint64_t)p[i*8+b] << (8*b);
            xb[i] |= (std::uint64_t)p[48+i*8+b] << (8*b);
            ya[i] |= (std::uint64_t)p[96+i*8+b] << (8*b);
            yb[i] |= (std::uint64_t)p[144+i*8+b] << (8*b);
        } }
    d.R = threshold::g2::from_affine(xa, xb, ya, yb);
    // CA-R203: the hdr is carried in the wire (56 bytes after R)
    std::memcpy(d.hdr, p + 192, 56);
    std::uint32_t ctlen = 0;
    for (int i = 0; i < 4; ++i) ctlen = (ctlen<<8) | p[248+i];
    if (m.payload.size() < 248 + 4 + ctlen + 32 + 32) return d;
    d.ct.assign(p + 252, p + 252 + ctlen);
    std::memcpy(d.tag, p + 252 + ctlen, 32);
    std::memcpy(d.cth, p + 252 + ctlen + 32, 32);
    d.ok = true;
    return d;
}

} // namespace hsma::m2env
