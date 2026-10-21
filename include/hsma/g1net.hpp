// HSMA :: g1net.hpp — the G1 transport skeleton (Step 18, DEC-211).
// Named g1net to avoid collision with threshold/g1.hpp (the BLS G1 curve).
// Whitepaper §8: beacon-seeded sampler (§8.1), 4-tier taxonomy (§8.2, DEC-022),
// contact root (§8.3, DEC-024), EMA scoring (§8.1, DEC-079), eclipse
// containment (INV-G3: the consensus consumer enforces stall-never-divergence;
// this layer is pure cryptography — no sockets in Phase 0).
// Poseidon over registry domains HSM_PEERSEED_v1 / IV_IDENT — no new domains.
// All arithmetic integer/fixed-point (DEC-090).
#pragma once
#include <hsma/poseidon.hpp>
#include <hsma/params.hpp>
#include <array>
#include <cstdint>

namespace hsma::g1net {

// ── 1. The beacon-seeded sampler (§8.1) ──
// seed = P3(P3(P3(P3(wr, bc), cid), acct), round) over HSM_PEERSEED_v1
inline fp::fe sampler_seed(const fp::fe& weight_root, const fp::fe& beacon,
                           const fp::fe& cid, const fp::fe& acct,
                           std::uint64_t round) {
    const dom::Dom D = dom::Dom::HSM_PEERSEED_v1;
    const fp::fe d1 = poseidon3(D, weight_root, beacon);
    const fp::fe d2 = poseidon3(D, d1, cid);
    const fp::fe d3 = poseidon3(D, d2, acct);
    return poseidon3(D, d3, fp::fe_from_u64(round));
}
// weighted draw: sel = limb0(P3(seed, k)) % T; cumulative walk (limb0 ==
// the first 8 LE bytes — the oracle's _u64)
inline std::size_t weighted_draw(const fp::fe& seed, const std::uint64_t* w,
                                 std::size_t n, std::uint64_t total,
                                 std::uint64_t k) {
    const fp::fe h = poseidon3(dom::Dom::HSM_PEERSEED_v1, seed, fp::fe_from_u64(k));
    const std::uint64_t sel = fp::fe_to_canonical(h).l[0] % total;
    std::uint64_t c = 0;
    for (std::size_t i = 0; i < n; ++i) { c += w[i]; if (sel < c) return i; }
    return n - 1;
}

// ── 2. The contact root (§8.3, DEC-024) ──
// AccountID = Poseidon(IV_IDENT, consensus_pk) — bound to the key, never to
// the rotatable transport ID (rotation-independence is structural: no
// transport input exists in the preimage). Rebind cooldown = 1 epoch.
inline fp::fe account_id(const fp::fe& consensus_pk) {
    return poseidon3(dom::Dom::IV_IDENT, consensus_pk, fp::fe_zero());
}
inline bool may_rebind(std::uint64_t last_epoch, std::uint64_t epoch) {
    return epoch >= last_epoch + 1;   // Δ_rebind = 1 epoch
}

// ── 3. The 4-tier taxonomy (§8.2, DEC-022) ──
enum class MsgClass : std::uint8_t { P0 = 0, P1 = 1, P2 = 2, P3 = 3 };
enum class Transport : std::uint8_t { Push = 0, Gossipsub = 1, AnnouncePull = 2, PullOnly = 3 };
enum class Auth : std::uint8_t { CanonicalPreimage = 0, ContentAddressed = 1 };
struct MsgSpec { std::size_t cap; Transport t; Auth a; };
inline constexpr MsgSpec TAX[4] = {
    { 4 * 1024,  Transport::Push,         Auth::CanonicalPreimage }, // P0 safety
    { 2 * 1024,  Transport::Gossipsub,    Auth::CanonicalPreimage }, // P1 consensus
    { 64 * 1024, Transport::AnnouncePull, Auth::ContentAddressed  }, // P2 manifests
    {128 * 1024, Transport::PullOnly,     Auth::ContentAddressed  }, // P3 bulk proofs
};
static_assert(TAX[3].cap == params::MAX_PROOF_BYTES,
              "P3 cap must equal the 128 KB transport firewall (params.hpp)");
inline bool admit(MsgClass c, std::size_t size, bool pull) {
    const MsgSpec& m = TAX[std::size_t(c)];
    if (size > m.cap) return false;
    if (m.t == Transport::PullOnly && !pull) return false;
    return true;
}

// ── 4. Peer scoring EMA (§8.1, DEC-079) — fixed-point integers (DEC-090) ──
// λ = 971532/10^6 = 2^(-1/24): the 24h half-life applies BOTH directions —
// decay s·λ, recovery s + (1-λ)(SC-s). (CA-R76: the rates must be symmetric.)
// The bounded negative impulse (≤2.5%/h) is applied per-window by the
// production scorer; Phase 0 pins the constant.
inline constexpr std::uint64_t EMA_SCALE   = 1000000;
inline constexpr std::uint64_t EMA_LAM_N   = 971532;
inline constexpr std::uint64_t EMA_REC_N   = 28468;   // == EMA_SCALE - EMA_LAM_N
inline constexpr std::uint64_t EMA_IMPULSE = 25000;
inline constexpr std::uint64_t TH_CORE = 800000, TH_GRAY = 600000;

inline void ema_tick(std::uint64_t& s, bool responded) {
    if (responded) {
        s += (1000000 - s) * EMA_REC_N / EMA_SCALE;
        if (s > 1000000) s = 1000000;
    } else {
        s = s * EMA_LAM_N / EMA_SCALE;
    }
}
inline unsigned classify(std::uint64_t s) {
    return s >= TH_CORE ? 2u : (s >= TH_GRAY ? 1u : 0u);
}

} // namespace hsma::g1net
