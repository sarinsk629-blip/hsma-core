// HSMA :: msscloop.hpp - P3-2 (DEC-272) + P3-3 (DEC-274): the live MSSC
// sampling loop + the beacon-gated stall breaker.
//
// WHITEPAPER PARAMETERS (section 3): alpha=0.75, phi_floor=0.50
// TESTNET HONEST SCOPE: k=2, beta=5, round=1s. The convergence property
// is in the FLIP, not the constant.
//
// P2 PRODUCTION PACKAGE (DEF-392/393/395, laws CA-R372d/e/g):
//   - DEF-392: every basis-point cross-multiplication is unsigned __int128.
//     The u64 form overflowed at agreeing*10000 >= 2^64 — weights grow until
//     it fires; the proven automaton (consensus.hpp, DEC-138/E-7) always was
//     128-bit. Same-width quorum math is a production incident on a timer.
//   - DEF-395: consensus identity is a MEMBER ID, never a port number and
//     never a vector index. tick() consumes (member_id, preference) pairs
//     and attributes weight by identity lookup; the old zip of a map-ordered
//     preference vector against a connection-ordered peer vector silently
//     credited the wrong members' weights.
//   - DEF-393: vote freshness is a helper here (vote_fresh) — a vote is
//     state for ONE epoch, ONE weight root, ONE conflict set, and a bounded
//     round window. Outside the window it is a replay, not an opinion.
#pragma once
#include <hsma/consensus.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/threshold/beacon.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/p2p.hpp>
#include <vector>
#include <cstring>
#include <utility>

namespace hsma::msscloop {

using consensus::Digest;
using consensus::View;
using consensus::Vote;
using consensus::Kind;
using consensus::State;

struct Config {
    // CA-R200/DEC-090: basis-point integer arithmetic (no float, cross-hardware deterministic)
    std::uint64_t alpha_bp = 7500;       // 75.00%
    std::uint64_t phi_floor_bp = 5000;   // 50.00%
    unsigned beta = 5;
    unsigned k = 2;
    unsigned stall_limit = 50;
    unsigned max_rounds = 30;
};

struct NodeState {
    Digest conflict;
    Digest preference;
    unsigned confidence = 0;
    unsigned stall = 0;
    unsigned rounds = 0;
    State state = State::Active;
    std::uint64_t self_weight = 0;
    std::uint64_t total_weight = 0;
    struct Peer { std::uint32_t ip; std::uint16_t port; std::uint64_t weight; std::uint64_t member; };
    std::vector<Peer> peers;
};

// DEF-395: weight attribution BY IDENTITY. A peer record carries the member
// id its weight belongs to; looking up weight by anything else (port, index,
// position in a map) credits the wrong voice.
inline std::uint64_t weight_of(const NodeState& ns, std::uint64_t member) noexcept {
    for (const auto& p : ns.peers) if (p.member == member) return p.weight;
    return 0;
}

// DEF-393: the freshness gate. A vote is admissible for exactly ONE epoch,
// ONE weight root, ONE conflict set, and a round window of +-1 (clock skew).
// Everything else is a replay or a fork statement.
inline bool vote_fresh(std::uint32_t vepoch, std::uint64_t vround,
                       const Digest& vwr, const Digest& cur_wr,
                       const Digest& vconflict, const Digest& cur_conflict,
                       std::uint64_t cur_epoch, std::uint64_t cur_round) noexcept {
    if (vepoch != std::uint32_t(cur_epoch)) return false;
    if (!(vwr == cur_wr)) return false;
    if (!(vconflict == cur_conflict)) return false;
    const std::uint64_t d = vround >= cur_round ? vround - cur_round : cur_round - vround;
    return d <= 1;
}

struct RoundResult {
    Kind kind;
    std::uint64_t sampled_weight = 0;
    std::uint64_t agreeing_weight = 0;
    bool flipped = false;
};

// preference vector: (member_id, preference) pairs — identity-carried.
inline RoundResult tick(NodeState& ns, const Config& cfg,
                        const std::vector<std::pair<std::uint64_t, Digest>>& member_prefs) noexcept {
    RoundResult rr{};
    ns.rounds++;

    const Digest NO_PREF{};   // all-zero digest = "no preference yet"
    const bool have_pref = !(ns.preference == NO_PREF);

    // sampled = self + every REPORTED voter's weight (identity-attributed)
    std::uint64_t sampled = have_pref ? ns.self_weight : 0;
    for (const auto& [mid, pref] : member_prefs)
        sampled += weight_of(ns, mid);
    if (ns.total_weight > 0 &&
        (unsigned __int128)sampled * 10000ull <
            (unsigned __int128)cfg.phi_floor_bp * ns.total_weight) {
        rr.kind = Kind::FloorAbort;
        ns.stall++;
        return rr;
    }
    rr.sampled_weight = sampled;

    std::uint64_t agreeing = have_pref ? ns.self_weight : 0;
    if (have_pref)
        for (const auto& [mid, pref] : member_prefs)
            if (pref == ns.preference) agreeing += weight_of(ns, mid);
    rr.agreeing_weight = agreeing;

    // alpha check: agreeing * 10000 >= alpha_bp * sampled
    // DEF-392: __int128 — the quorum comparison must be wider than its operands.
    if ((unsigned __int128)agreeing * 10000ull >= (unsigned __int128)cfg.alpha_bp * sampled) {
        ns.confidence++;
        ns.stall = 0;
        rr.kind = (ns.confidence >= cfg.beta) ? Kind::Confirmed : Kind::NoQuorum;
        if (ns.confidence >= cfg.beta) ns.state = State::Finalized;
    } else {
        if (have_pref && ns.confidence > 0) rr.flipped = true;
        ns.confidence = 0;
        // plurality by weight among the REPORTED preferences (identity-attributed);
        // lex-ascending digest tiebreak — deterministic across the fleet.
        Digest majority = have_pref ? ns.preference : NO_PREF;
        std::uint64_t maj_w = have_pref ? ns.self_weight : 0;
        bool any = have_pref;
        for (const auto& [mid, pref] : member_prefs) {
            const std::uint64_t w = weight_of(ns, mid);
            if (w == 0) continue;
            if (!any || w > maj_w || (w == maj_w && pref.byte_less(majority))) {
                majority = pref; maj_w = w; any = true;
            }
        }
        if (any && majority != ns.preference) {
            ns.preference = majority;
            rr.flipped = true;
        }
        rr.kind = Kind::Switched;
        ns.stall++;
    }

    if (ns.stall >= cfg.stall_limit) ns.state = State::Suspended;
    return rr;
}

// ---- P3-3 (DEC-274): the beacon-gated stall breaker ----
// DEF-392b: the breaker resolves REAL conflicts. The frozen candidate set is
// the caller's ACTUAL conflicting preferences (harvested from verified votes)
// — the old body fabricated a peer preference from the string "decreeB",
// which made the breaker a test harness wearing a production signature.
// The beacon is the REAL threshold beacon (DEC-200: threshold::beacon is the
// sole producer) — a constant or hashed-literal beacon here would key the
// tiebreak to attacker-known entropy.
struct BreakerResult {
    bool suspended = false;
    bool resolved = false;
    Digest winner{};
    std::uint64_t stagger_ms = 0;
};

inline BreakerResult breaker_tick(NodeState& ns, const Config& cfg,
                                  const threshold::beacon::Committee& committee,
                                  std::uint64_t next_epoch,
                                  const Digest& prev_beacon,
                                  const std::vector<Digest>& frozen_candidates) noexcept {
    BreakerResult br{};
    if (ns.state != State::Suspended) {
        if (ns.stall >= cfg.stall_limit && ns.state == State::Active) {
            ns.state = State::Suspended;
            br.suspended = true;
        }
        if (!br.suspended) return br;
    }
    // A stall breaker with fewer than two REAL candidates has nothing to
    // break: report the suspension, refuse to invent a winner.
    if (frozen_candidates.size() < 2) { br.suspended = true; return br; }

    const auto beacon = threshold::beacon::epoch_beacon(committee, next_epoch, prev_beacon);
    const std::vector<Digest> frozen = frozen_candidates;   // the REAL conflict set
    br.stagger_ms = consensus::Automaton::resolve_breaker(frozen, beacon, ns.conflict, &br.winner);
    br.resolved = true;
    ns.preference = br.winner;
    ns.confidence = 0; ns.stall = 0;
    ns.state = State::Active;
    return br;
}

} // namespace hsma::msscloop
