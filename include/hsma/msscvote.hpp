// HSMA :: msscvote.hpp - P3-1 (DEC-271): the MSSC vote wire layer.
// Wires the proven organs: consensus.hpp's Vote automaton (step6),
// threshold::hash_to_g1 (step9), sig::partial (step9), the BLS pairing
// law via bls_verify_aff (step10b, m2::verify_attest as the canonical
// caller), p2p.hpp transport (P2-01).
//
// DEC-016 CANONICAL PREIMAGE (whitepaper section 3):
//   epoch(u32 BE) || weight_root(32) || C_id(32) || round(u64 BE) || pref(1)
// NO timestamps, NO view state, NO prover-discretionary bytes.
//
// HONEST SCOPE (P3-1): fixed test committee; per-member partial verify
// (e(sigma_j, G2gen) == e(H, Y_j) via the 10-B law); aggregate+tally = P3-2.
#pragma once
#include <hsma/consensus.hpp>
#include <hsma/threshold/g1.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/sig.hpp>
#include <hsma/threshold/h2g1.hpp>
#include <hsma/threshold/pairing.hpp>
#include <hsma/p2p.hpp>
#include <vector>
#include <cstring>

namespace hsma::msscvote {
// ---- the DEC-016 layout, stated ONCE (DEF-213: encode/decode must share it) ----
inline constexpr unsigned OFF_EPOCH = 0;                 // u32 BE
inline constexpr unsigned OFF_WROOT = 4;                 // 32B
inline constexpr unsigned OFF_CONFLICT = 36;             // 32B
inline constexpr unsigned OFF_PREFERENCE = 68;           // 32B
inline constexpr unsigned OFF_ROUND = 100;               // u64 BE
inline constexpr unsigned PREIMAGE_SIZE = 108;
inline constexpr unsigned SIG_SIZE = 96;                 // 12 limbs x 8
inline constexpr unsigned VOTE_PAYLOAD = PREIMAGE_SIZE + SIG_SIZE;  // 204


using consensus::Digest;
using threshold::g1::Pt;

// ---- the canonical preimage (DEC-016): 108 bytes -------------------------
inline std::vector<std::uint8_t> vote_preimage(
    std::uint32_t epoch, const Digest& weight_root, const Digest& conflict,
    std::uint64_t round, const Digest& preference) noexcept
{
    std::vector<std::uint8_t> b;
    b.reserve(PREIMAGE_SIZE);
    for (int i = 3; i >= 0; --i) b.push_back((epoch >> (8*i)) & 0xFF);
    for (const Digest* d : {&weight_root, &conflict, &preference}) {
        std::uint8_t tmp[32]; d->to_bytes(tmp);
        b.insert(b.end(), tmp, tmp + 32);
    }
    for (int i = 7; i >= 0; --i) b.push_back((round >> (8*i)) & 0xFF);
    return b;
}

// ---- sign: the m2::attest pattern verbatim -------------------------------
inline Pt sign_vote(const threshold::Fr& S_j,
                    const std::vector<std::uint8_t>& pre) noexcept {
    return threshold::sig::partial(S_j, threshold::hash_to_g1(pre.data(), pre.size()));
}

// ---- per-member verify: the m2::verify_attest pattern verbatim -----------
inline bool verify_vote(const Pt& sigma, const std::vector<std::uint8_t>& pre,
                        const threshold::g2::G2Pt& Y_j) noexcept {
    const Pt H = threshold::hash_to_g1(pre.data(), pre.size());
    std::uint64_t sx[6], sy[6], hx[6], hy[6];
    if (!threshold::g1::to_affine(sigma, sx, sy)) return false;
    if (!threshold::g1::to_affine(H, hx, hy)) return false;
    return threshold::bls_verify_aff(sx, sy, hx, hy, Y_j);
}

// ---- wire: type 0x06, payload = preimage(108) || sig(96) = 204 bytes ------
// DEF-394 (v2): payload = preimage(108) || sig(96) || member(u64 BE) = 212.
// The vote preimage stays EXACTLY DEC-016 (no member field — a preimage
// change is a fork); the member id rides OUTSIDE the preimage as a CLAIM
// that the pairing CHECKS: verify_vote_member does ONE pairing against
// Y[claimed] — a wrong claim fails the pairing and is rejected. The old
// signer-finding scan tried every member key (O(n) pairings per vote;
// ~45 s worst case at n=224). Legacy 204B payloads still decode (scan path)
// so the fleet can roll v2 out without a hard fork.
inline constexpr unsigned VOTE_PAYLOAD_V2 = PREIMAGE_SIZE + SIG_SIZE + 8;  // 212

inline p2p::Message encode_vote(std::uint32_t epoch, const Digest& wr,
                                const Digest& conf, std::uint64_t round,
                                const Digest& pref, const Pt& sigma) noexcept {
    p2p::Message m; m.type = 0x06;
    m.payload = vote_preimage(epoch, wr, conf, round, pref);
    std::uint64_t ax[6], ay[6];
    if (!threshold::g1::to_affine(sigma, ax, ay)) return m;   // inf sig -> empty (caller checks size)
    for (int i = 0; i < 6; ++i) for (int b = 7; b >= 0; --b)
        m.payload.push_back((ax[i] >> (8*b)) & 0xFF);
    for (int i = 0; i < 6; ++i) for (int b = 7; b >= 0; --b)
        m.payload.push_back((ay[i] >> (8*b)) & 0xFF);
    return m;
}

// v2: the sender CLAIMS a member id; the verifier checks the claim with one
// pairing (CA-R372f: the wire carries a claimed identity that the pairing
// CHECKS, never a scan that guesses).
inline p2p::Message encode_vote_v2(std::uint32_t epoch, const Digest& wr,
                                   const Digest& conf, std::uint64_t round,
                                   const Digest& pref, const Pt& sigma,
                                   std::uint64_t member) noexcept {
    p2p::Message m = encode_vote(epoch, wr, conf, round, pref, sigma);
    if (m.payload.size() != VOTE_PAYLOAD) return m;   // propagate the empty-sig guard
    for (int i = 7; i >= 0; --i) m.payload.push_back((member >> (8*i)) & 0xFF);
    return m;
}

struct DecodedVote {
    std::uint32_t epoch{}; std::uint64_t round{};
    Digest weight_root{}, conflict{}, preference{};
    Pt sigma{};
    std::uint64_t member{};   // v2: the CLAIMED signer (checked, not trusted)
    bool has_member{false};   // true => payload was 212B (v2)
    bool ok{false};
};
inline DecodedVote decode_vote(const p2p::Message& m) noexcept {
    DecodedVote d{};
    if (m.type != 0x06) return d;
    if (m.payload.size() != VOTE_PAYLOAD && m.payload.size() != VOTE_PAYLOAD_V2) return d;
    const std::uint8_t* p = m.payload.data();
    d.epoch = (std::uint32_t(p[0])<<24)|(std::uint32_t(p[1])<<16)|(std::uint32_t(p[2])<<8)|p[3];
    d.weight_root = Digest::from_bytes(p+OFF_WROOT);
    d.conflict    = Digest::from_bytes(p+OFF_CONFLICT);
    d.preference  = Digest::from_bytes(p+OFF_PREFERENCE);
    for (int i = 0; i < 8; ++i) d.round = (d.round<<8) | p[OFF_ROUND+i];
    std::uint64_t ax[6], ay[6];
    for (int i = 0; i < 6; ++i) { ax[i]=0; ay[i]=0;
        for (int b = 0; b < 8; ++b) {
            ax[i] = (ax[i]<<8) | p[PREIMAGE_SIZE + i*8 + b];
            ay[i] = (ay[i]<<8) | p[PREIMAGE_SIZE + 48 + i*8 + b];
        } }
    if (m.payload.size() == VOTE_PAYLOAD_V2) {
        d.has_member = true;
        for (int i = 0; i < 8; ++i)
            d.member = (d.member << 8) | p[PREIMAGE_SIZE + SIG_SIZE + i];
    }
    d.sigma = threshold::g1::from_affine(ax, ay);
    d.ok = true;
    return d;
}

// DEF-394: single-pairing verification against the CLAIMED member's key.
// O(1) crypto per vote; the claim is verified, never trusted.
inline bool verify_vote_member(const Pt& sigma, const std::vector<std::uint8_t>& pre,
                               const threshold::g2::G2Pt& Y_claimed) noexcept {
    return verify_vote(sigma, pre, Y_claimed);
}


// ---- P3-3b (DEC-275): the aggregate verify - one pairing per batch ------
// N threshold-BLS partials verify with ONE pairing against the aggregate
// public key Y_agg = sum(Y_j). The homomorphism: sig::aggregate for the
// sigmas, g2::Padd for the public keys. The cost drops from O(N) pairings
// to O(1) pairing + O(N) point-additions (each ~100x cheaper than a pairing).
//
// The lambda coefficients: for a SIMPLIFIED k-of-k (all members participate),
// each lambda = 1 (the sum is unweighted). For the production k-of-n,
// lambda_j = Lagrange(j) at x=0 (the step7 poly kernel).
struct AggregateVerify {
    threshold::g1::Pt sigma_agg{};       // the accumulated signature
    threshold::g2::G2Pt Y_agg{};         // the accumulated public key
    unsigned count = 0;
    bool initialized = false;
};

// accumulate a member's partial into the batch (no pairing yet)
inline void agg_accumulate(AggregateVerify& av, const threshold::g1::Pt& sigma_j,
                           const threshold::g2::G2Pt& Y_j) noexcept {
    if (!av.initialized) {
        av.sigma_agg = sigma_j;
        av.Y_agg = Y_j;
        av.initialized = true;
    } else {
        av.sigma_agg = threshold::g1::Padd(av.sigma_agg, sigma_j);
        av.Y_agg = threshold::g2::Padd(av.Y_agg, Y_j);
    }
    av.count++;
}

// the single pairing: e(sigma_agg, G2gen) == e(H(pre), Y_agg)
inline bool agg_verify(const AggregateVerify& av,
                       const std::vector<std::uint8_t>& pre) noexcept {
    if (!av.initialized || av.count == 0) return false;
    const threshold::g1::Pt H = threshold::hash_to_g1(pre.data(), pre.size());
    std::uint64_t sx[6], sy[6], hx[6], hy[6];
    if (!threshold::g1::to_affine(av.sigma_agg, sx, sy)) return false;
    if (!threshold::g1::to_affine(H, hx, hy)) return false;
    return threshold::bls_verify_aff(sx, sy, hx, hy, av.Y_agg);
}

// ---- ORDER_SIG (DEF-391): the LOCK ATTESTATION — wire type 0x0D ---------
// The ceremony's step-2 ("Lock") is not a private thought: it is a SIGNED
// statement. Each committee member threshold-signs the canonical order-lock
// preimage the moment the order root is committed and BEFORE any decryption
// share exists; anyone can aggregate the partials and hold
//     e(sigma_lock_agg, G2gen) == e(H(order_preimage), Y_agg)
// as the attestation that THIS committee committed THIS order. A share set
// for an epoch whose lock is unattested is refused: shares exist only under
// a signed lock (CA-R372c).
//
// Canonical order-lock preimage (NO discretionary bytes, mirrors DEC-016):
//   TAG(16) || epoch(u32 BE) || order_root(32)  = 52 bytes
inline constexpr char TAG_ORDERLOCK[] = "HSM_ORDERLOCK_V1";   // 16 chars
inline constexpr unsigned ORDER_PREIMAGE_SIZE =
    sizeof(TAG_ORDERLOCK) - 1 + 4 + 32;                          // 52
// wire: epoch(4) || oroot(32) || sigma(96) || member-claim(8) = 140.
// The member id rides OUTSIDE the preimage as a CLAIM the pairing checks
// (same law as the v2 vote wire, CA-R372f).
inline constexpr unsigned ORDER_SIG_WIRE = 4 + 32 + SIG_SIZE + 8;    // 140

inline std::vector<std::uint8_t> order_sig_preimage(
    std::uint32_t epoch, const std::uint8_t oroot[32]) noexcept {
    std::vector<std::uint8_t> b;
    b.reserve(ORDER_PREIMAGE_SIZE);
    b.insert(b.end(), TAG_ORDERLOCK, TAG_ORDERLOCK + sizeof(TAG_ORDERLOCK) - 1);
    for (int i = 3; i >= 0; --i) b.push_back((epoch >> (8*i)) & 0xFF);
    b.insert(b.end(), oroot, oroot + 32);
    return b;
}

inline Pt sign_order(const threshold::Fr& S_j,
                     const std::vector<std::uint8_t>& pre) noexcept {
    return threshold::sig::partial(S_j, threshold::hash_to_g1(pre.data(), pre.size()));
}

// wire 0x0D: epoch(u32 BE) || order_root(32) || sigma(96) || member(u64 BE)
inline p2p::Message encode_order_sig(std::uint32_t epoch,
                                     const std::uint8_t oroot[32],
                                     const Pt& sigma,
                                     std::uint64_t member) noexcept {
    p2p::Message m; m.type = 0x0D;
    for (int i = 3; i >= 0; --i) m.payload.push_back((epoch >> (8*i)) & 0xFF);
    m.payload.insert(m.payload.end(), oroot, oroot + 32);
    std::uint64_t ax[6], ay[6];
    if (!threshold::g1::to_affine(sigma, ax, ay)) return m;   // inf -> caller checks size
    for (int i = 0; i < 6; ++i) for (int b = 7; b >= 0; --b)
        m.payload.push_back((ax[i] >> (8*b)) & 0xFF);
    for (int i = 0; i < 6; ++i) for (int b = 7; b >= 0; --b)
        m.payload.push_back((ay[i] >> (8*b)) & 0xFF);
    for (int i = 7; i >= 0; --i) m.payload.push_back((member >> (8*i)) & 0xFF);
    return m;
}

struct DecodedOrderSig {
    std::uint32_t epoch{};
    std::uint8_t oroot[32]{};
    std::uint64_t member{};   // the CLAIMED signer (checked, not trusted)
    Pt sigma{};
    bool ok{false};
};
inline DecodedOrderSig decode_order_sig(const p2p::Message& m) noexcept {
    DecodedOrderSig d{};
    if (m.type != 0x0D || m.payload.size() != ORDER_SIG_WIRE) return d;
    const std::uint8_t* p = m.payload.data();
    d.epoch = (std::uint32_t(p[0])<<24)|(std::uint32_t(p[1])<<16)|(std::uint32_t(p[2])<<8)|p[3];
    std::memcpy(d.oroot, p + 4, 32);
    std::uint64_t ax[6], ay[6];
    for (int i = 0; i < 6; ++i) { ax[i]=0; ay[i]=0;
        for (int b = 0; b < 8; ++b) {
            ax[i] = (ax[i]<<8) | p[36 + i*8 + b];
            ay[i] = (ay[i]<<8) | p[36 + 48 + i*8 + b];
        } }
    for (int i = 0; i < 8; ++i)
        d.member = (d.member << 8) | p[36 + SIG_SIZE + i];
    d.sigma = threshold::g1::from_affine(ax, ay);
    d.ok = true;
    return d;
}

} // namespace hsma::msscvote
