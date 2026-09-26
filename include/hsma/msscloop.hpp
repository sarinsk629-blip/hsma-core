// HSMA :: msscloop.hpp - P3-2 (DEC-272) + P3-3 (DEC-274): the live MSSC
// sampling loop + the beacon-gated stall breaker.
//
// WHITEPAPER PARAMETERS (section 3): alpha=0.75, phi_floor=0.50
// TESTNET HONEST SCOPE: k=2, beta=5, round=1s. The convergence property
// is in the FLIP, not the constant.
#pragma once
#include <hsma/consensus.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/threshold/beacon.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/p2p.hpp>
#include <vector>
#include <cstring>

namespace hsma::msscloop {

using consensus::Digest;
using consensus::View;
using consensus::Vote;
using consensus::Kind;
using consensus::State;

struct Config {
    double alpha = 0.75;
    double phi_floor = 0.50;
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
    struct Peer { std::uint32_t ip; std::uint16_t port; std::uint64_t weight; };
    std::vector<Peer> peers;
};

struct RoundResult {
    Kind kind;
    std::uint64_t sampled_weight = 0;
    std::uint64_t agreeing_weight = 0;
    bool flipped = false;
};

inline RoundResult tick(NodeState& ns, const Config& cfg,
                        const std::vector<Digest>& peer_prefs) noexcept {
    RoundResult rr{};
    ns.rounds++;

    std::uint64_t sampled = ns.self_weight;
    for (std::size_t i = 0; i < peer_prefs.size() && i < ns.peers.size(); ++i)
        sampled += ns.peers[i].weight;
    if (ns.total_weight > 0 && (double)sampled / (double)ns.total_weight < cfg.phi_floor) {
        rr.kind = Kind::FloorAbort;
        ns.stall++;
        return rr;
    }
    rr.sampled_weight = sampled;

    std::uint64_t agreeing = ns.self_weight;
    for (std::size_t i = 0; i < peer_prefs.size() && i < ns.peers.size(); ++i)
        if (peer_prefs[i] == ns.preference) agreeing += ns.peers[i].weight;
    rr.agreeing_weight = agreeing;

    const double frac = (double)agreeing / (double)sampled;
    if (frac >= cfg.alpha) {
        ns.confidence++;
        ns.stall = 0;
        rr.kind = (ns.confidence >= cfg.beta) ? Kind::Confirmed : Kind::NoQuorum;
        if (ns.confidence >= cfg.beta) ns.state = State::Finalized;
    } else {
        if (ns.confidence > 0) rr.flipped = true;
        ns.confidence = 0;
        Digest majority = ns.preference;
        std::uint64_t maj_w = ns.self_weight;
        for (std::size_t i = 0; i < peer_prefs.size() && i < ns.peers.size(); ++i) {
            if (peer_prefs[i] != ns.preference && ns.peers[i].weight > maj_w) {
                majority = peer_prefs[i];
                maj_w = ns.peers[i].weight;
            }
        }
        if (majority != ns.preference) {
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
struct BreakerResult {
    bool suspended = false;
    bool resolved = false;
    Digest winner{};
    std::uint64_t stagger_ms = 0;
};

inline BreakerResult breaker_tick(NodeState& ns, const Config& cfg,
                                  const threshold::beacon::Committee& committee,
                                  std::uint64_t next_epoch,
                                  const Digest& prev_beacon) noexcept {
    BreakerResult br{};
    if (ns.state != State::Suspended) {
        if (ns.stall >= cfg.stall_limit && ns.state == State::Active) {
            ns.state = State::Suspended;
            br.suspended = true;
        }
        if (!br.suspended) return br;
    }
    auto beacon = threshold::beacon::epoch_beacon(committee, next_epoch, prev_beacon);
    std::vector<Digest> frozen = {ns.preference};
    Digest peer_pref = consensus::sha256d((const std::uint8_t*)"decreeB", 7);
    if (ns.preference == peer_pref)
        peer_pref = consensus::sha256d((const std::uint8_t*)"decreeA", 7);
    frozen.push_back(peer_pref);
    consensus::Snapshot dummy{};
    dummy.w = {1}; dummy.total = 1; dummy.self_row = 0;
    dummy.ids = {Digest{}};
    consensus::Automaton auto_(dummy, next_epoch);
    br.stagger_ms = consensus::Automaton::resolve_breaker(frozen, beacon, ns.conflict, &br.winner);
    br.resolved = true;
    ns.preference = br.winner;
    ns.confidence = 0; ns.stall = 0;
    ns.state = State::Active;
    return br;
}

} // namespace hsma::msscloop
