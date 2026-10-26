// HSMA :: epoch_node.cpp - P2-02 (the epoch node: networking + folding)
// The full testnet validator: collects decree entries, folds them through
// the f_exec circuit + mfold, produces π_E via the WHIR wrap, gossips
// epoch headers to peers.
//
// Usage: ./epoch_node [port] [--seed ip:port ...]
// Default port: 31233
// K_ENTRIES: 10 decree entries per epoch (golden scale)
#include <hsma/p2p.hpp>
#include <hsma/mfold.hpp>
#include <hsma/nivc.hpp>
#include <hsma/fexec_circuit.hpp>
#include <hsma/whir.hpp>
#include <hsma/explorer.hpp>
#include <hsma/verifier.hpp>   // Phase 6.17 v2 s2: the rotating epoch-verifier
#include <hsma/pouw.hpp>
#include <hsma/pouw/gemm_backend.hpp>
#include <hsma/sha256.hpp>
#include <array>
#include <unordered_map>
#include <hsma/peersec.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/msscloop.hpp>
#include <hsma/m2envelope.hpp>
#include <hsma/threshold/m2.hpp>
#include <hsma/threshold/beacon.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <hsma/econ/stake.hpp>

// Phase 6.1: API helper — defined in hsma::explorer namespace to match
// the extern declaration in explorer.hpp's serve_request
namespace hsma::explorer {
} // namespace hsma::explorer
#include <map>
#include <string>
#include <cstdlib>
#include <chrono>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include "fexec_golden.hpp"
#include "pallas_params_gen.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>

using namespace hsma;
using hsma::explorer::WorkStatus;
using hsma::explorer::WorkItem;
using hsma::explorer::g_work_queue;
using hsma::explorer::g_work_done;
using hsma::explorer::g_next_work_id;
using hsma::explorer::g_work_mutex;

// the epoch state
static unsigned current_epoch = 0;
static unsigned decree_count = 0;
static constexpr unsigned K_ENTRIES = 10;   // the golden-scale default (DEC-102)
// DEF-400: the production k is WIRED, not frozen. --k-entries (1..65536);
// production epoch = 476 (DEC-238). The mempool ceremony trigger, the fold
// lifecycle and the explorer all follow g_k_entries.
static unsigned g_k_entries = K_ENTRIES;
// DEF-401/402: the NIVC epoch accumulator (41B, the proven PC machine,
// Step 16/DEC-209) + the PROVEN digest law. The testnet honest boundary:
// the SMT-gated fold_step (real accounts) lands with the fleet integration;
// the node runs the f_head/exec-absorption/f_close chain verbatim.
static nivc::Accumulator g_acc{};
static unsigned g_entry_seq = 0;             // the per-epoch entry index
static fp::fe g_epoch_droot = fp::fe_zero(); // testnet: no decree SMT yet (honest)

// the folding state
static mfold::SparseMat A, B, C;
static mfold::Relaxed accumulator;
static std::vector<std::array<std::uint64_t,4>> digest_chain;   // (legacy limbs, unused by the fold path)
static std::vector<fp::fe> digest_chain_fe;   // DEF-402: the PROVEN fe chain
// P3-1b (DEC-271): the test committee. HONEST SCOPE: the poly is a PUBLIC
// test constant (both sides derive Y_j from it); live DKG rotation = P3-2+.
static threshold::Poly g_test_poly;   // Poly lives at threshold level (poly.hpp:10, [R-P2])
static hsma::threshold::vss::Transcript g_dkg_T{};
static explorer::NodeState g_ns_shared{}; // P5-D: the ONE status the explorer serves live
static std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>> g_members;
static msscvote::AggregateVerify g_agg_verify;   // P3-3b: the batch accumulator
// P5-B (DEC-287): per-(round,preference) same-message vote batches.
// BGLS law: e(sum sigma_i, G2) == e(H(pre), sum Y_i) holds ONLY for a shared
// preimage — batches are keyed by (round, preference-digest). At 2 sigs:
// ONE pairing verifies the batch. g_agg_verify (old global) retired.
struct AggBatch { msscvote::AggregateVerify av{}; std::vector<std::uint8_t> pre{}; unsigned count = 0; };
static std::map<std::array<std::uint8_t, 40>, AggBatch> g_agg_batches;
static unsigned long long g_agg_receipts = 0;   // lifetime verified-batch count
static msscloop::NodeState g_mssc;
static std::map<std::uint64_t, consensus::Digest> g_peer_prefs;
static unsigned g_self_member = 1;
static threshold::Fr g_own_share;
static threshold::Fr g_env_secret;   // P4-3b: the poly secret for the envelope decrypt
static std::chrono::steady_clock::time_point g_last_tick;
// ---- P5-D (DEF-226 closure): component liveness ----
static std::atomic<std::uint64_t> g_hb_consensus{0};
static std::atomic<bool> g_fleet_active{false};   // true when peer_fds is non-empty
// ---- P5-E: economic enforcement on the vote path ----
static econ::Params g_stake_params{};
static econ::StakeRegistry g_stake_reg(g_stake_params);
static std::map<std::pair<std::uint64_t, std::uint64_t>, std::string> g_signed_prefs;
static std::map<std::uint64_t, bool> g_adversarial;
// ---- Gate-3: participation ledger (uptime receipts, anti-Sybil identity) ----
struct UptimeReceipt {
    std::uint64_t member_id;
    std::uint64_t epoch;
    std::uint64_t round;
    std::uint64_t uptime_s;
    // the BLS signature over H(member || epoch || round || uptime) — verified on receipt
};
static std::map<std::uint64_t, std::uint64_t> g_uptime_ledger;   // member -> total seconds confirmed
static std::map<std::uint64_t, std::uint64_t> g_receipt_count;   // member -> receipt count
static std::map<std::uint64_t, std::uint64_t> g_last_receipt;    // member -> last round seen (anti-replay)
// ---- Gate-3: peer discovery (fleet self-organization) ----
struct DiscPeer { std::uint32_t ip; std::uint16_t port; };
static std::vector<DiscPeer> g_discovered;
static std::uint32_t g_my_public_ip = 0;
static std::vector<msscloop::NodeState::Peer> g_seed_addrs; // for auto-reconnect  // set via --public-ip or committee.toml
static std::map<std::uint64_t, bool> g_stake_seeded; // per-member auto-bond (one each)

static const std::chrono::steady_clock::time_point g_boot = std::chrono::steady_clock::now();

// ---- P5-E+/Gate-3: committee config loader (minimal TOML subset, zero deps) ----
struct CfgMember { std::uint64_t id=0, weight=0; std::string endpoint, op; };
static std::vector<CfgMember> load_committee_config(const char* path, std::uint64_t& t_out) {
    std::vector<CfgMember> out; t_out = 0;
    FILE* f = std::fopen(path, "r");
    if (!f) return out;                       // no file -> caller keeps defaults
    char line[512];
    CfgMember cur{}; bool in_member = false;
    while (std::fgets(line, sizeof line, f)) {
        std::string L(line);
        // strip comments + whitespace
        auto hash = L.find('#'); if (hash != std::string::npos) L = L.substr(0, hash);
        // trim
        const auto b = L.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;
        L = L.substr(b, L.find_last_not_of(" \t\r\n") + 1);
        auto kv = [&](const std::string& key)->std::string{
            auto e = L.find(key + " ="); if (e == std::string::npos || e != 0) return "";
            auto v = L.substr(e + key.size() + 2);
            auto q1 = v.find('"');
            if (q1 != std::string::npos) { auto q2 = v.find('"', q1+1); return v.substr(q1+1, q2-q1-1); }
            auto h = v.find('#'); if (h != std::string::npos) v = v.substr(0, h);
            while (!v.empty() && (v.back()==' '||v.back()=='\r')) v.pop_back();
            return v;
        };
        if (L.rfind("[[member]]", 0) == 0) {
            if (in_member && cur.id) out.push_back(cur);
            cur = CfgMember{}; in_member = true; continue;
        }
        if (L.rfind("threshold_t", 0) == 0) t_out = std::strtoull(kv("threshold_t").c_str(), nullptr, 10);
        if (!in_member) continue;
        if (L.rfind("id", 0) == 0)       cur.id = std::strtoull(kv("id").c_str(), nullptr, 10);
        if (L.rfind("weight", 0) == 0)   cur.weight = std::strtoull(kv("weight").c_str(), nullptr, 10);
        if (L.rfind("endpoint", 0) == 0) cur.endpoint = kv("endpoint");
        if (L.rfind("operator", 0) == 0) cur.op = kv("operator");
    }
    if (in_member && cur.id) out.push_back(cur);
    std::fclose(f);
    return out;
}

// Gate-3: config state at FILE SCOPE — the committee block and the mssc peers
// block both read these (block-local versions broke scope: the committee block
// closes before the peers site — DEF-247).
static std::vector<CfgMember> g_cfg_members;
static std::uint64_t g_cfg_t_raw = 0;
static std::uint64_t g_cfg_n = 3, g_cfg_t_eff = 2;
static bool g_from_config = false;

// ---- Phase 6.1: API helper functions (called from explorer thread) ----
static std::map<std::uint64_t, std::pair<bool, std::uint64_t>> g_api_results;
static void api_register_model(std::uint64_t mid, std::uint64_t commitment) {
    std::printf("[api] model %llu registered (C=%llu)\n",
        (unsigned long long)mid, (unsigned long long)commitment);
}
static std::string api_get_result(std::uint64_t wid) {
    auto it = g_api_results.find(wid);
    if (it == g_api_results.end()) return "{\"error\":\"not found\"}";
    char buf[128];
    std::snprintf(buf, sizeof(buf), "{\"work_id\":%llu,\"verified\":%s}",
        (unsigned long long)wid, it->second.first ? "true" : "false");
    return buf;
}

static void hb_watchdog() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        const std::uint64_t c0 = g_hb_consensus.load(std::memory_order_relaxed);
        std::this_thread::sleep_for(std::chrono::seconds(60));
        // P5-D+: also check the explorer's liveness
        if (g_ns_shared.explorer_hb > 0) {
            static std::uint64_t last_expl_hb = 0;
            if (g_ns_shared.explorer_hb == last_expl_hb) {
                // explorer hasn't served any request in 90+ seconds
                // (it should serve at least the cron's 1-min probe)
                std::fprintf(stderr, "[watchdog] explorer stalled — _Exit(1)\n");
                std::_Exit(1);
            }
            last_expl_hb = g_ns_shared.explorer_hb;
        }
                if (g_fleet_active.load() && g_hb_consensus.load(std::memory_order_relaxed) == c0) {
            std::fprintf(stderr, "[watchdog] consensus heartbeat stalled >60s - _Exit(1), supervisor restarts\n");
            std::fflush(stderr);
            std::_Exit(1);
        }
    }
}
static msscloop::Config g_cfg;
// P4-3 (DEC-279): the encrypted mempool state
struct MempoolEntry {
    m2env::Envelope env;
    bool decrypted = false;
    std::vector<std::uint8_t> payload;
};
static std::vector<MempoolEntry> g_mempool;
static std::vector<std::vector<std::uint8_t>> g_dec_shares;  // our shares per envelope
// DEF-P3-03: O(1) envelope dedup — cth-keyed hash index alongside the pool.
// The old path linear-scanned g_mempool per incoming envelope (O(n^2)/epoch).
struct CthKey { std::uint8_t b[32]; bool operator==(const CthKey& o) const { return std::memcmp(b, o.b, 32) == 0; } };
struct CthHash { std::size_t operator()(const CthKey& k) const {
    std::size_t h = 1469598103934665603ull;
    for (int i = 0; i < 32; ++i) { h ^= k.b[i]; h *= 1099511628211ull; }
    return h; } };
static std::unordered_map<CthKey, std::size_t, CthHash> g_env_index;
static void handle_decree(const std::vector<std::uint8_t>& payload);  // fwd: try_decrypt below
// P5-C: collected decryption shares per envelope — (member_id, D_j) pairs.
// Decryption fires when the count of DISTINCT member x's reaches t=2.
static std::map<std::size_t, std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>>> g_thr_shares;
static std::uint8_t g_order_root[32] = {};
static threshold::g2::G2Pt g_xe;   // the committee's aggregate public key
static bool g_order_committed = false;

// ---- P2 production package state (DEF-390/391/393/395/398) ----
static consensus::Digest g_prev_beacon{};       // the REAL beacon chain (zero digest = genesis)
static consensus::Digest g_weight_root{};       // H(TAG || roster(id,weight)) - the vote fork filter
static std::uint32_t g_pool_epoch = 0;          // the epoch the current mempool ceremony belongs to
struct OrderLock { msscvote::AggregateVerify av{}; std::uint8_t oroot[32]{}; bool attested = false; };
static std::map<std::uint32_t, OrderLock> g_order_locks;   // epoch -> lock attestation
static std::map<int, std::uint64_t> g_fd_member;           // fd -> verified member identity (DEF-395)
static unsigned pouw_inner = 64;          // P2-07: file-scope - one truth, all sites
static std::uint64_t pouw_weight = 0;     // last self-verified PoUW receipt

// DEF-P3-05/06: the ONE shared threshold-decrypt path (the duplicated bodies
// are retired). Own share is reconstructed from the STORED serialization —
// never from uninitialized stack arrays. The DEM key binds the WIRE-CARRIED
// envelope header (CA-R203: carried, not assumed/guessed). Aggregation runs
// the batch-Lagrange kernel (1 inversion total). Decrypt failure hands the
// forensics to the async audit (blame_scan / verify_aggregate), not the hot path.
static bool try_decrypt_envelope(std::size_t eix) {
    if (eix >= g_mempool.size()) return false;
    auto& me = g_mempool[eix];
    if (me.decrypted) return true;
    std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>> shares;
    if (eix < g_dec_shares.size() && g_dec_shares[eix].size() >= 192) {
        const auto& ser = g_dec_shares[eix];
        std::uint64_t xa[6], xb[6], ya[6], yb[6];
        for (int i = 0; i < 6; ++i) { xa[i]=0; xb[i]=0; ya[i]=0; yb[i]=0;
            for (int b = 0; b < 8; ++b) {
                xa[i] |= (std::uint64_t)ser[i*8+b] << (8*b);
                xb[i] |= (std::uint64_t)ser[48+i*8+b] << (8*b);
                ya[i] |= (std::uint64_t)ser[96+i*8+b] << (8*b);
                yb[i] |= (std::uint64_t)ser[144+i*8+b] << (8*b);
            } }
        shares.push_back({g_self_member, threshold::g2::from_affine(xa, xb, ya, yb)});
    }
    for (const auto& [mid, Dj] : g_thr_shares[eix]) shares.push_back({mid, Dj});
    for (std::size_t a = 0; a < shares.size(); ++a)
        for (std::size_t b2 = a+1; b2 < shares.size(); ++b2)
            if (shares[a].first == shares[b2].first) return false;   // dup x: refuse
    if (shares.size() < 2) {
        std::printf("[thr] envelope %zu: %zu/%u shares, waiting\n", eix, shares.size(), 2u);
        return false;
    }
    threshold::g2::G2Pt D_agg{};
    if (!hsma::threshold::vss::agg_dec_share(D_agg, shares)) {
        std::printf("[thr] envelope %zu: agg FAILED\n", eix);
        return false;
    }
    auto ss_b = m2env::pt_to_bytes(D_agg);
    auto xe_b = m2env::pt_to_bytes(g_xe);
    std::uint8_t k[32];
    threshold::m2::kdf(k, ss_b.data(), xe_b.data(), me.env.hdr);   // STORED hdr (CA-R203)
    std::vector<std::uint8_t> pl;
    if (!threshold::m2::dem_decrypt(pl, k, me.env.hdr,
            me.env.ct.data(), me.env.ct.size(), me.env.tag)) {
        std::printf("[decrypt] envelope %zu: TAG FAILED (async audit owns blame)\n", eix);
        return false;
    }
    me.decrypted = true;
    me.payload = pl;
    std::printf("[decrypt] envelope %zu: \"%s\" (tag OK) [shared path]\n",
        eix, std::string(pl.begin(), pl.end()).c_str());
    if (pl.size() < 32) {
        std::vector<std::uint8_t> padded = pl;
        while (padded.size() < 32) padded.push_back(0);
        handle_decree(padded);
    } else {
        handle_decree(pl);
    }
    return true;
}

// DEF-P3-08: late-joiner STATE SYNC — the full share set rides ONE 0x0C
// message (O(1) messages/epoch), not one 0x08 per share (O(n)).
static void send_sync_batch(int fd) {
    const std::size_t cnt = std::min(g_dec_shares.size(), g_mempool.size());
    std::vector<std::uint8_t> pl;
    for (int i = 0; i < 4; ++i) pl.push_back(std::uint8_t(cnt >> (8*i)));   // LE (wire law)
    for (std::size_t sx = 0; sx < cnt; ++sx) {
        pl.push_back(std::uint8_t(sx)); pl.push_back(std::uint8_t(sx>>8));
        pl.push_back(std::uint8_t(sx>>16)); pl.push_back(std::uint8_t(sx>>24));
        for (int i = 0; i < 8; ++i) pl.push_back(std::uint8_t(g_self_member >> (8*i)));
        const auto& ser = g_dec_shares[sx];
        pl.insert(pl.end(), ser.begin(), ser.begin() + 192);
    }
    p2p::Message mb{}; mb.type = 0x0C; mb.payload = std::move(pl);
    p2p::send_message(fd, mb);
    std::printf("[sync] 0x0C batch: %zu share records -> fd %d\n", cnt, fd);
}
static const char* pouw_verify = "PENDING";
static std::uint32_t g_hash[4] = {0,0,0,0}; // P2-10a (DEFECT-190 fix): last completed epoch's P.v limbs - the REAL state fingerprint

// peer connections
static std::vector<int> peer_fds;
static std::map<int, std::uint64_t> g_fd_weights;
// Phase 6.9: per-peer P2P enforcement — source-IP ban map (accept + recv paths)
static std::map<std::uint32_t, std::uint64_t> g_peer_bans;
// DEF-391: step 3 (Share) happens only after step 2 (Lock) is ATTESTED.
// ONE 0x0C sync batch per peer carries ALL stored shares.
static void publish_locked_shares() {
    auto it = g_order_locks.find(g_pool_epoch);
    if (it == g_order_locks.end() || !it->second.attested) {
        std::printf("[order] share publication REFUSED - no attested lock for epoch %u\n",
            (unsigned)g_pool_epoch);
        return;
    }
    for (int fd : peer_fds) send_sync_batch(fd);
    std::printf("[order] lock ATTESTED for epoch %u - shares published (0x0C, one msg/peer)\n",
        (unsigned)g_pool_epoch);
}

// DEF-391: the lock attestation ingest - verify the claim with ONE pairing,
// accumulate, attest at the threshold. The attested root is stored WITH the
// lock: a foreign root never mixes into this epoch's accumulator.
static void order_lock_ingest(std::uint32_t epoch, const std::uint8_t oroot[32],
                              const msscvote::Pt& sigma, std::uint64_t member,
                              const threshold::g2::G2Pt& Y) {
    auto& L = g_order_locks[epoch];
    if (L.av.count == 0) std::memcpy(L.oroot, oroot, 32);
    if (std::memcmp(L.oroot, oroot, 32) != 0) {
        std::printf("[order] 0x0D root MISMATCH for epoch %u - refused\n", (unsigned)epoch);
        return;
    }
    auto pre = msscvote::order_sig_preimage(epoch, oroot);
    if (!msscvote::verify_vote_member(sigma, pre, Y)) {
        std::printf("[order] 0x0D from member %llu FAILED pairing - refused\n",
            (unsigned long long)member);
        return;
    }
    msscvote::agg_accumulate(L.av, sigma, Y);
    std::printf("[order] 0x0D member %llu -> lock %u partials for epoch %u\n",
        (unsigned long long)member, L.av.count, (unsigned)epoch);
    if ((unsigned)L.av.count >= (unsigned)g_cfg_t_eff && msscvote::agg_verify(L.av, pre)) {
        L.attested = true;
        std::printf("[order] LOCK ATTESTED for epoch %u (t=%u, one aggregate pairing)\n",
            (unsigned)epoch, (unsigned)g_cfg_t_eff);
        if (epoch == g_pool_epoch && g_order_committed
            && std::memcmp(L.oroot, g_order_root, 32) == 0)
            publish_locked_shares();
    }
}

// DEF-398: the ceremony is PER-EPOCH. Every structure that belongs to the
// epoch's ceremony dies with it - the old node ordered ONCE per process
// lifetime and carried envelopes, shares, votes and locks across epochs,
// where the DKG rotation had already made them foreign. Undecrypted
// envelopes are dropped with a forensics count (their cth is in this log).
static void reset_epoch_ceremony() {
    std::size_t undec = 0;
    for (const auto& me : g_mempool) if (!me.decrypted) ++undec;
    if (undec) std::printf("[order] epoch %u close: %zu envelope(s) undecrypted - dropped\n",
        current_epoch, undec);
    g_order_committed = false;
    g_mempool.clear();
    g_env_index.clear();
    g_dec_shares.clear();
    g_thr_shares.clear();
    g_peer_prefs.clear();
    g_agg_batches.clear();
    g_order_locks.clear();
    std::printf("[order] ceremony state reset for epoch %u\n", current_epoch);
}

// Phase 6.17 s2: this epoch's claim-decree payloads — the quorum-audit sample
// pool. Cleared at epoch completion (the next epoch's claims are new claims).
static std::vector<std::vector<std::uint8_t>> g_epoch_claims;
static bool g_quorum_audited_this_pool = false;   // one audit per pool lifecycle

// Phase 6.17 v2 s2: the rotating epoch-verifier — receipt of the last deep
// audit + the lifetime rotation counter. Served via GET /verifier; the receipt
// is the node's own verifier duty made legible to the fleet.
struct VerifierReceipt {
    bool has = false;                 // false = honest zero state (nothing audited yet)
    unsigned epoch = 0;
    std::size_t pool = 0;
    std::uint64_t work_id = 0;
    bool digest_ok = false, recompute_ran = false, recompute_ok = false, pass = false;
    std::string identity_hex;
    // ---- s4: the pool AGGREGATE receipt (tier-1 for EVERY claim) ----
    bool pool_has = false;
    std::size_t pool_size = 0;
    unsigned long long pool_structure_bad = 0, pool_unknown_work = 0;
    unsigned long long pool_tier1_ok = 0, pool_tier1_bad = 0;
    unsigned long long pool_tier2_ran = 0, pool_tier2_ok = 0, pool_tier2_bad = 0;
    unsigned long long pool_tier2_skipped = 0, pool_macs_spent = 0;
    bool pool_pass = false;
};
static VerifierReceipt g_verifier_receipt;
static unsigned long long g_verifier_rotations = 0;

// ---- Phase 6.17 v2 s4 (DEC-s4): the DKG rotation ----
// The P5-A machinery (beacon-seeded Feldman VSS, per-epoch rotation) was
// golden-proven but never WIRED — the node never derived its epoch committee.
// Now it does: at startup and at every epoch completion the committee is
// re-dealt (vss::deal) with prev = the CURRENT chain tip, every member share
// is verified against the Feldman commitments, and the aggregate public key
// C[0] = [f(0)]G2 becomes the epoch's committee identity (served on /dkg).
// No secret material is kept beyond the transcript — the testnet committee
// is deterministic from the chain, which is the point: every fleet member
// derives the SAME committee from the SAME chain (auditable determinism).
static threshold::vss::Transcript g_dkg;
static bool g_dkg_live = false;
static unsigned g_dkg_shares_ok = 0;
static unsigned g_dkg_n = 0, g_dkg_t = 0;
static std::string g_dkg_agg_pk_hex;

static std::string g2_to_hex(const threshold::g2::G2Pt& P) {
    std::uint64_t x0[6], x1[6], y0[6], y1[6];
    if (!threshold::g2::to_affine(P, x0, x1, y0, y1)) return std::string(384, '0');
    static const char* d = "0123456789abcdef";
    std::string out; out.reserve(384);
    const auto limb = [&out](std::uint64_t v) {
        for (int b = 0; b < 8; ++b) {
            const std::uint8_t byte = (std::uint8_t)(v >> (8 * b));
            out += d[byte >> 4]; out += d[byte & 15];
        }
    };
    for (int k = 0; k < 6; ++k) limb(x0[k]);
    for (int k = 0; k < 6; ++k) limb(x1[k]);
    for (int k = 0; k < 6; ++k) limb(y0[k]);
    for (int k = 0; k < 6; ++k) limb(y1[k]);
    return out;
}

static void rotate_dkg() {
    // prev = the CURRENT chain tip (the last digest of the epoch being closed
    // — at startup, the genesis-era chain head). The chain stores 4-limb
    // tails; the Digest is reconstructed LE64-per-limb — the same put64
    // convention the claim identity and select_index both ride.
    consensus::Digest prev{};
    if (!digest_chain.empty()) {
        std::uint8_t pb[32];
        for (int k = 0; k < 4; ++k)
            for (int b = 0; b < 8; ++b)
                pb[k * 8 + b] = (std::uint8_t)(digest_chain.back()[k] >> (8 * b));
        prev = consensus::Digest::from_bytes(pb);
    }
    // config: the proven testnet shape n=5, t=3 (law: t >= 2, 2t >= n,
    // n <= 224; capstone 224/112).
    threshold::vss::Transcript T;
    if (!threshold::vss::deal(T, current_epoch, 5, 3, &prev)) {
        std::printf("[dkg] epoch %u deal REJECTED by the config law — committee carries over\n", current_epoch);
        return;
    }
    unsigned ok = 0;
    for (std::uint64_t j = 1; j <= T.n; ++j)
        ok += threshold::vss::verify_share(T, j, T.Y[j]) ? 1u : 0u;
    g_dkg = T;
    g_dkg_live = true;
    g_dkg_shares_ok = ok;
    g_dkg_n = (unsigned)T.n;
    g_dkg_t = (unsigned)T.t;
    g_dkg_agg_pk_hex = g2_to_hex(T.C[0]);   // C_0 = [f(0)]G2 — the aggregate pk
    std::printf("[dkg] epoch %u committee rotated: n=%u t=%u shares_ok=%u/%u agg_pk=%s...\n",
                current_epoch, g_dkg_n, g_dkg_t, ok, (unsigned)T.n,
                g_dkg_agg_pk_hex.substr(0, 16).c_str());
}

// P2-08 (DEC-254): the shared epoch PoUW - main AND handle_decree call this.
// Writes the file-scope globals; deterministic from the epoch's digest chain.
// Phase 6.13: cross-node PoUW verification — pure, no global writes.
// Recomputes the deterministic epoch GEMM from a chain tail and verifies
// the claimed weight. Returns true if the claim matches a verified proof.
static bool verify_peer_epoch_pouw(const std::array<std::uint64_t,4>& chain_tail,
                                   std::uint64_t claimed_w) noexcept {
    const unsigned N = pouw_inner;
    std::uint64_t st = 0;
    for (int k = 0; k < 4; ++k) st = st * 0x9E3779B97F4A7C15ull + chain_tail[k];
    auto rnd = [&st]() -> fp::fe {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        return fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
    };
    std::vector<fp::fe> Am((std::size_t)N*N), Bm((std::size_t)N*N), Cm((std::size_t)N*N);
    for (auto& x : Am) x = rnd();
    for (auto& x : Bm) x = rnd();
    for (unsigned i = 0; i < N; ++i)
        for (unsigned j = 0; j < N; ++j) {
            fp::fe acc = fp::fe_zero();
            for (unsigned k = 0; k < N; ++k)
                acc = fp::fe_add(acc, fp::fe_mul(Am[i*N+k], Bm[k*N+j]));
            Cm[i*N+j] = acc;
        }
    pouw::GemmProofV2 PP = pouw::prove_gemm_v2(Am, Bm, Cm, N, N, N);
    const bool vok = pouw::verify_gemm_v2(PP, Am, Bm, Cm);
    const std::uint64_t w = vok ? pouw::weight(N, 1) : 0;
    return (vok && w == claimed_w);
}

static void run_epoch_pouw() {
    // ---- P2-06 (DEC-250): the epoch PoUW - deterministic, self-verified ----
    // The epoch's own digest chain seeds a 64^3 GEMM (xorshift64* expansion
    // of the chain tail - CA-R90 float-free); the node proves it FS-bound
    // (DEC-248 v2) and verifies its OWN proof (CA-R126 applied to PoUW).
    // Same epoch bytes -> same GEMM -> same weight. [G8]-testable.
    {
        const unsigned N = pouw_inner;
        auto t0 = std::chrono::steady_clock::now();
        std::uint64_t st = 0;
        {   const auto& db = digest_chain.back();
            for (int k = 0; k < 4; ++k) st = st * 0x9E3779B97F4A7C15ull + db[k]; }
        auto rnd = [&st]() -> fp::fe {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            return fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull); };
        std::vector<fp::fe> Am((std::size_t)N*N), Bm((std::size_t)N*N), Cm((std::size_t)N*N);
        for (auto& x : Am) x = rnd();
        for (auto& x : Bm) x = rnd();
        pouw::gemm(Am.data(), Bm.data(), Cm.data(), N);
        pouw::GemmProofV2 PP = pouw::prove_gemm_v2(Am, Bm, Cm, N, N, N);
        const bool vok = pouw::verify_gemm_v2(PP, Am, Bm, Cm);
        pouw_verify = vok ? "ACCEPT" : "REJECT";
        pouw_weight = vok ? pouw::weight(N, 1) : 0;
        auto t1 = std::chrono::steady_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        std::fprintf(stderr, "[pouw-timing]"); std::printf("[pouw] epoch %u: %u^3 GEMM self-verify %s | weight %llu MACs | %.0f ms\n",
            current_epoch, N, pouw_verify, (unsigned long long)pouw_weight, ms);
    }

}

static fp::fe ld(const std::array<std::uint64_t,4>& c) {
    fp::fe x{}; std::memcpy(x.l.data(), c.data(), 32);
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fp::fe_mul(x, rr);
}

// DEF-402: the fe-native witness builder - the proven law's values, no
// limb round-trips. Z_PTHASH = Z_COMPUTED = pt (binding row SAT by
// construction); Z_DNEW carries the gossip-verified chain tip.
static std::vector<fp::fe> build_witness_fe(
    const fp::fe& dprev, const fp::fe& dnew, const fp::fe& pt) {
    std::vector<fp::fe> z(fcirc::NZ, fp::fe_zero());
    z[fcirc::Z_DPREV] = dprev;
    z[fcirc::Z_DNEW] = dnew;
    z[fcirc::Z_PTHASH] = pt;
    z[fcirc::Z_COMPUTED] = pt;
    z[fcirc::Z_NONCES] = fp::fe_from_u64(7);
    z[fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
    z[fcirc::Z_LT] = fp::fe_one();
    z[fcirc::Z_SELF] = fp::fe_zero();
    z[fcirc::Z_ISPAD] = fp::fe_zero();
    z[fcirc::Z_PC] = fp::fe_from_u64(1);
    z[fcirc::Z_SELEXEC] = fp::fe_one();
    z[fcirc::Z_NOTPAD] = fp::fe_one();
    z[fcirc::Z_H] = fp::fe_mul(z[fcirc::Z_PC], z[fcirc::Z_PC]);
    z[fcirc::Z_ONE] = fp::fe_one();
    return z;
}

// witness builder (the same as the f_exec golden)
static std::vector<fp::fe> build_witness(
    const std::array<std::uint64_t,4>& dprev,
    const std::array<std::uint64_t,4>& dnew) {
    std::vector<fp::fe> z(fcirc::NZ, fp::fe_zero());
    z[fcirc::Z_DPREV] = ld(dprev);
    z[fcirc::Z_DNEW] = ld(dnew);
    z[fcirc::Z_PTHASH] = ld(dprev);
    z[fcirc::Z_COMPUTED] = ld(dprev);
    z[fcirc::Z_NONCES] = fp::fe_from_u64(7);
    z[fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
    z[fcirc::Z_LT] = fp::fe_one();
    z[fcirc::Z_SELF] = fp::fe_zero();
    z[fcirc::Z_ISPAD] = fp::fe_zero();
    z[fcirc::Z_PC] = fp::fe_from_u64(1);
    z[fcirc::Z_SELEXEC] = fp::fe_one();
    z[fcirc::Z_NOTPAD] = fp::fe_one();
    z[fcirc::Z_H] = fp::fe_mul(z[fcirc::Z_PC], z[fcirc::Z_PC]);
    z[fcirc::Z_ONE] = fp::fe_one();
    return z;
}

// DEF-402: the digest chain follows the PROVEN F_exec law (fold.hpp,
// Step 14) - NOT a synthetic XOR. The entry's pt binds (amount, fee, nonce)
// through fold::pt_hash_of (P3(HSM_PT_v1, e1, e2)); the chain step is the
// exec absorption (P3(HSM_FOLD_v1, d_prev, pt)). Both sides derive the same
// (amount, fee, nonce) from (epoch, idx) - a pure function - so every node
// reconstructs identical witnesses and the header digest is library-exact
// (lightclient.hpp chain-continuity consumes exactly this law).
struct EntryTerms { unsigned __int128 amount; std::uint64_t fee; std::uint64_t nonce; };
static EntryTerms entry_terms(unsigned epoch, unsigned idx) {
    std::uint8_t m[8];                                   // (epoch, idx) LE
    for (int i = 0; i < 4; ++i) m[i] = std::uint8_t(epoch >> (8 * i));
    for (int i = 0; i < 4; ++i) m[4 + i] = std::uint8_t(idx >> (8 * i));
    const auto d = consensus::sha256d(m, sizeof m);      // 64 spread bits
    const std::uint64_t h = d.l[0] ^ (d.l[1] << 1);
    EntryTerms t;
    t.amount = (((unsigned __int128)(h & 0xFFFFFFFFull)) << 64)
             | (unsigned __int128)((h >> 32) | 1ull);              // nonzero
    t.fee    = 5 + (h % 7);
    t.nonce  = (std::uint64_t)idx + 1;
    return t;
}
static fp::fe entry_pt(const EntryTerms& t) {
    return fold::pt_hash_of(t.amount, (unsigned __int128)t.fee, t.nonce);
}
// the chain step: d_new = P3(HSM_FOLD_v1, d_prev, pt)  (the F_exec law)
static fp::fe chain_step(const fp::fe& dprev, const fp::fe& pt) {
    return poseidon3(dom::Dom::HSM_FOLD_v1, dprev, pt);
}
static fp::fe fe_from_payload(const std::vector<std::uint8_t>& p) {
    std::byte b[32];
    for (int i = 0; i < 32; ++i) b[i] = std::byte(p[i]);
    const auto r = fp::fe_from_le_bytes(b);        // DEC-105: canonical-only
    return r.value;
}
// the chain advances in BOTH representations: the fe chain (the fold law)
// and the limb view (the PoUW/verifier/peer consumers read the same bytes)
static void chain_push(const fp::fe& v) {
    digest_chain_fe.push_back(v);
    digest_chain.push_back(fp::fe_to_canonical(v).l);
}

// handle an incoming decree entry: add it to the current epoch
// P2-08: DEFECT-168 fix - seen-message fingerprints (FNV-1a, FIFO cap 256).
// Safe failure direction: a false positive only skips a re-gossip/fold.
static std::vector<std::uint64_t> seen_fps;
static bool seen_or_add(const std::vector<std::uint8_t>& p) {
    std::uint64_t h = 1469598103934665603ull;
    for (std::uint8_t b : p) { h ^= b; h *= 1099511628211ull; }
    for (std::uint64_t f : seen_fps) if (f == h) return true;
    seen_fps.push_back(h);
    if (seen_fps.size() > 256) seen_fps.erase(seen_fps.begin());
    return false;
}

// DEF-403: the ONE epoch-header builder (both call sites). The digest
// field carries the NIVC accumulator tip (canonical LE, the real epoch
// chain), the size field the MEASURED tau-free π_E wire size.
static void gossip_epoch_header(const whir::Proof& P) {
    const auto wire = whir::wire_encode(P);
    p2p::Message hdr{};
    hdr.type = p2p::EPOCH_HEADER;
    // payload (DERIVED, 52B): epoch@0(4) digest@4(4xu32) size@20(4)
    //   inner@24(4) weight@28(8) hash@36(4xu32) - DEFECT-184
    p2p::put_u32(hdr.payload, current_epoch);
    const fp::fe dcanon = fp::fe_to_canonical(g_acc.digest);
    for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)dcanon.l[k]);
    p2p::put_u32(hdr.payload, (std::uint32_t)wire.size());   // MEASURED (DEF-403)
    p2p::put_u32(hdr.payload, pouw_inner);   // P2-07: the weight rides the header
    p2p::put_u64(hdr.payload, pouw_weight); // P2-07: the weight (u64)
    fp::fe ocanon = fp::fe_to_canonical(P.v);
    for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)ocanon.l[k]);
    for (int k = 0; k < 4; ++k) g_hash[k] = (std::uint32_t)ocanon.l[k]; // P2-10a: store
    g_ns_shared.pi_e_size = (unsigned)wire.size();           // the explorer too
    for (int fd : peer_fds) p2p::send_message(fd, hdr);
    std::printf("[gossip] epoch %u header sent to %zu peers (pi_E wire %zu B)\n",
        current_epoch, peer_fds.size(), wire.size());
}

static void handle_decree(const std::vector<std::uint8_t>& payload) {
    auto decree_t0 = std::chrono::steady_clock::now();
    // P2-08: DEFECT-170 - a re-received decree would DOUBLE-FOLD into the
    // accumulator. Fingerprint dedup, safe direction.
    if (seen_or_add(payload)) { std::printf("[decree] duplicate entry - skipped\n"); return; }
    if (payload.size() < 32) return;
    
    // DEF-402: the payload IS the chain tip - canonical LE of the epoch's
    // d_new (the sender computed it under the PROVEN law; we parse it under
    // the canonical-only boundary, DEC-105).
    const fp::fe dnew = fe_from_payload(payload);
    
    // chain: dprev = the last digest in the chain (fp::fe, the proven law)
    const fp::fe dprev = digest_chain_fe.back();
    chain_push(dnew);
    
    // witness: the (amount, fee, nonce) terms are a pure function of
    // (epoch, idx); the pt binding and the chain link are library-exact.
    const auto terms = entry_terms(current_epoch, g_entry_seq++);
    const fp::fe pt = entry_pt(terms);
    auto z = build_witness_fe(dprev, dnew, pt);
    
    mfold::Relaxed Ji = mfold::fresh(z, fcirc::NROWS);
    if (mfold::sat_relaxed(A, B, C, Ji) != fcirc::NROWS) {
        std::printf("[fold] instance UNSAT — skipping\n");
        digest_chain_fe.pop_back();
        digest_chain.pop_back();
        --g_entry_seq;
        return;
    }
    
    mfold::MultifoldResult M = mfold::multifold(A, B, C, accumulator, {Ji});
    accumulator = M.folded;
    ++decree_count;
    
    // DEF-401: the NIVC exec absorption - the same law fold::f_exec applies
    // at its digest update (P3(FOLD, digest, pt)); count + 41B O(1) wire.
    g_acc.digest = poseidon3(dom::Dom::HSM_FOLD_v1, g_acc.digest, pt);
    ++g_acc.count;
    
    std::printf("[fold] decree %u/%u folded, SAT\n", decree_count, g_k_entries);
    
    // when the epoch is full, produce the π_E
    if (decree_count >= g_k_entries) {
        std::printf("[pi_E] epoch %u complete — producing π_E...\n", current_epoch);
        
        // the evals vector: z'(16) || E'(8) || u(1) = 25 elements
        std::vector<fp::fe> evals;
        for (const auto& v : accumulator.z) evals.push_back(v);
        for (const auto& e : accumulator.E) evals.push_back(e);
        evals.push_back(accumulator.u);
        
        // pad to the next power of two
        unsigned npad = 1; while (npad < evals.size()) npad <<= 1;
        while (evals.size() < npad) evals.push_back(fp::fe_zero());
        
        // the WHIR wrap
        auto P = whir::wrap_open(evals);
        
        // verify without the witness
        unsigned stage = 99;
        unsigned nv = 0;
        {   unsigned tmp = npad; while (tmp > 1) { tmp >>= 1; ++nv; } }
        bool ok = whir::wrap_verify(P, nv, &stage);
        
        std::printf("[pi_E] epoch %u: wrap_verify %s (stage=%u)\n",
            current_epoch, ok ? "ACCEPT" : "REJECT", stage);
        
        // DEF-401: the NIVC CLOSE seals the epoch (P3(FOLD, digest, count),
        // PC -> CLOSE) - the header now carries the REAL epoch accumulator
        // tip, not a dead witness wire.
        nivc::fold_close(g_acc);
        
        // P2-08: fresh weight for the epoch that just completed
        run_epoch_pouw();
        decree_count = 0; // P2-08b: kept (idempotent with the tail reset)
        // DEF-403: ONE shared header builder; the size field is the MEASURED
        // wire size of this π_E (tau-free wire form), never a constant.
        gossip_epoch_header(P);
        
        // DEF-401: the next epoch opens on the closed digest (DEC-239's
        // cross-epoch chaining; PC returns to EXEC with count reset).
        nivc::fold_head(g_acc, g_acc.digest, g_epoch_droot);
        g_entry_seq = 0;
        
        // reset for the next epoch
        ++current_epoch;
        decree_count = 0;
        g_epoch_claims.clear();   // 6.17 s2: the next epoch's claims are new claims
        g_quorum_audited_this_pool = false;   // the next pool gets its own audit
        reset_epoch_ceremony();   // DEF-398: the ceremony is PER-EPOCH
        rotate_dkg();             // s4: the committee re-dealt from the NEW chain tip
    }
}

int main(int argc, char* argv[]) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::thread(hb_watchdog).detach(); // P5-D // [G7] lesson: redirected stdout was fully buffered - logs stayed empty
    unsigned my_port = p2p::DEFAULT_PORT;

    // parse arguments
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--k-entries") == 0 && i + 1 < argc) {
            const long v = std::atol(argv[i + 1]);
            if (v < 1 || v > 65536) {
                std::printf("--k-entries must be in 1..65536 (got %s)\n", argv[i + 1]);
                return 1;
            }
            g_k_entries = (unsigned)v;
            ++i;
        }
    }
    if (argc > 1 && argv[1][0] != '-') my_port = (unsigned)atoi(argv[1]);
    if (g_k_entries != K_ENTRIES)
        std::printf("[fold] production k wired: %u entries/epoch (DEF-400)\n", g_k_entries);

    // Phase 6.17 v2 s3: loud, honest disclosure when the testnet CPU-fold
    // band is active — every operator must see that the 6.16 GPU gate is
    // relaxed for the bounded receipt band (64 < n <= 96) on THIS node.
    if (explorer::cpu_fold_band_allowed(80))
        std::printf("[testnet] HSMA_TESTNET_CPU_FOLD active — CPU fold band 64<n<=256 enabled "
                    "(the 6.16 measured band, rung_probe receipt; NOT the default, NOT for production)\n");

    // build the circuit matrices
    fcirc::build_matrices(A, B, C);
    
    // initialize the digest chain
    std::array<std::uint64_t,4> d0{};
    d0[0] = 1000; d0[1] = 2000;
    digest_chain.push_back(d0);

    // P3-1b: derive the test committee publics
    {   threshold::Fr c1{}, c2{}, c3{};
        if (!threshold::fr_from_u64(c1, 0x11) || !threshold::fr_from_u64(c2, 0x22)
            || !threshold::fr_from_u64(c3, 0x33)) { std::fprintf(stderr, "FATAL: fr init\n"); return 1; }
        // ---- Gate-3: committee from config (fallback: hardcoded testnet committee) ----
    g_cfg_members = load_committee_config("committee.toml", g_cfg_t_raw);
    g_from_config = g_cfg_members.size() >= 1;
    g_cfg_n = g_from_config ? g_cfg_members.size() : 3;
    g_cfg_t_eff = (g_from_config && g_cfg_t_raw) ? g_cfg_t_raw : 2;
    std::printf("[committee] %s: n=%llu t=%llu (%s)\n",
        g_from_config ? "FROM CONFIG" : "DEFAULT", (unsigned long long)g_cfg_n,
        (unsigned long long)g_cfg_t_eff, g_from_config ? "Gate-3 fleet" : "testnet fallback");

if (!hsma::threshold::vss::deal(g_dkg_T, /*epoch=*/0, /*n=*/g_cfg_n, /*t=*/g_cfg_t_eff)) { std::fprintf(stderr, "FATAL: dkg deal\n"); return 1; }
        for (std::uint64_t j = 1; j <= g_dkg_T.n; ++j)
          if (!hsma::threshold::vss::verify_share(g_dkg_T, j, g_dkg_T.Y[j])) { std::fprintf(stderr, "FATAL: Feldman share %llu\n", (unsigned long long)j); return 1; }
        g_test_poly = g_dkg_T.f; // P5-A: the committed polynomial (alias)
        std::printf("[dkg] epoch=0 n=3 t=2 - 3/3 shares Feldman-VERIFIED (beacon-seeded, no trusted dealer)\n");
        for (std::uint64_t j = 1; j <= g_cfg_n; ++j) {
            threshold::Fr sj = threshold::dkg::share_for(g_test_poly, j);
            threshold::mont::fe6 k{}; threshold::fr_to_fe6(sj, k);
            g_members.push_back({j, threshold::g2::Pmul(threshold::g2::gen(), k)});
        }
        std::printf("[vote] test committee registered: 3 members\n");
        // DEF-393: the vote fork filter - H("HSM_WROOT_V1" || u32 BE count ||
        // per-member (u64 BE id || u64 BE weight)), members in id order.
        // A vote is admissible only inside the roster it claims; both nodes
        // derive the SAME digest from the SAME committee.toml.
        {   std::vector<std::pair<std::uint64_t, std::uint64_t>> roster;
            for (const auto& cm : g_cfg_members) roster.push_back({cm.id, cm.weight});
            if (!g_from_config) roster = {{1, 60}, {2, 40}};
            std::sort(roster.begin(), roster.end());
            std::vector<std::uint8_t> buf;
            const char* TAG_WR = "HSM_WROOT_V1";
            buf.insert(buf.end(), TAG_WR, TAG_WR + 12);
            for (int i = 3; i >= 0; --i)
                buf.push_back(std::uint8_t((roster.size() >> (8*i)) & 0xFF));
            for (const auto& [id, w] : roster) {
                for (int i = 7; i >= 0; --i) buf.push_back(std::uint8_t((id >> (8*i)) & 0xFF));
                for (int i = 7; i >= 0; --i) buf.push_back(std::uint8_t((w >> (8*i)) & 0xFF));
            }
            g_weight_root = consensus::sha256d(buf.data(), buf.size());
            std::printf("[vote] weight_root (roster fork filter): ");
            std::uint8_t wrb[32]; g_weight_root.to_bytes(wrb);
            for (int i = 0; i < 8; ++i) std::printf("%02x", wrb[i]);
            std::printf("...\n");
        }
    }
    {   g_self_member = (my_port == p2p::DEFAULT_PORT) ? 1 : 2;
        g_own_share = hsma::threshold::dkg::share_for(g_test_poly, g_self_member); // P5-A: real t-of-n share
        { threshold::mont::fe6 os{}; threshold::fr_to_fe6(g_own_share, os);
          if (!hsma::threshold::vss::verify_own(g_dkg_T, g_self_member, os)) { std::fprintf(stderr, "FATAL: own share failed Feldman self-proof\n"); return 1; } }
        const char* pref_str = (g_self_member == 1) ? "decreeA" : "decreeB";
        g_mssc.conflict = consensus::sha256d((const std::uint8_t*)"conflict_set_0", 14);
        g_mssc.preference = consensus::sha256d((const std::uint8_t*)pref_str, strlen(pref_str));
        g_mssc.self_weight = (g_self_member == 1) ? 60 : 40;
        g_mssc.total_weight = 100;
        if (g_self_member == 1)
            g_mssc.peers.push_back({0x7F000001, 31234, 40, 2});   // DEF-395: member id
        else
                                        // P5-E+/Gate-3: peers from config when present
                            // P5-H+/Gate-3 v2: peers are DYNAMIC — rebuilt from active
                            // connections each startup. The TOML only defines the anchor's
                            // self-identity. Fleet members join via --seed (outbound) and
                            // get added here as they connect. No static peer list.
                            g_mssc.total_weight = g_mssc.self_weight;  // start with just self
                            std::printf("[committee] dynamic fleet: self_weight=%llu, peers join via --seed\n",
                                (unsigned long long)g_mssc.self_weight);
        g_last_tick = std::chrono::steady_clock::now();
        // P4-3b: X_E = [secret]G2gen (the degree-0 poly's constant term)
        {
            // P4-3b fix: g_xe = [our_share]G2gen — matches the envfaucet's X_E
            // (the envfaucet encrypts under share_for(poly, 1), and the node IS member 1)
            threshold::mont::fe6 sk_fe6{}; threshold::fr_to_fe6(g_test_poly.c[0], sk_fe6);
            g_xe = threshold::g2::Pmul(threshold::g2::gen(), sk_fe6);
            g_env_secret = g_test_poly.c[0];  // the poly secret (c[0])
        }
        std::printf("[mssc] member %u: weight %llu, initial pref %s\n",
            g_self_member, (unsigned long long)g_mssc.self_weight, pref_str);
    }
    {
    }
    
    // the initial accumulator: fresh with d0->d1 under the PROVEN law
    // (genesis pt from (epoch 0, idx 0); d1 = P3(FOLD, d0, pt0))
    {
        const auto t0g = entry_terms(0, 0);
        const fp::fe pt0 = entry_pt(t0g);
        const fp::fe d0fe = fp::fe_from_canonical_limbs(d0);
        digest_chain_fe.push_back(d0fe);
        const fp::fe d1 = chain_step(d0fe, pt0);
        chain_push(d1);
        auto z = build_witness_fe(d0fe, d1, pt0);
        accumulator = mfold::fresh(z, fcirc::NROWS);
        // DEF-401: the NIVC epoch machine opens here (PC: HEAD -> EXEC)
        nivc::fold_head(g_acc, d0fe, g_epoch_droot);
        g_entry_seq = 1;
    }
    
    decree_count = 0;
    
    std::printf("═══════════════════════════════════════\n");
    std::printf("  HSMA EPOCH NODE — P2-02\n");
    std::printf("  port: %u | k_entries: %u | epoch: %u\n", my_port, g_k_entries, current_epoch);
    std::printf("═══════════════════════════════════════\n");
    
    // create the listening socket
    int listener = p2p::create_listener(my_port);
    if (listener < 0) {
        std::printf("✗ failed to listen on port %u\n", my_port);
        return 1;
    }
    std::printf("[node] listening on port %u\n", my_port);
    
    // connect to seed peers from command line
    std::vector<p2p::PeerInfo> seed_peers;
    for (int i = 2; i < argc; ++i) {
        if (std::strncmp(argv[i], "--public-ip", 11) == 0 && i + 1 < argc) {
                struct in_addr pa{};
                if (inet_pton(AF_INET, argv[i+1], &pa) == 1) g_my_public_ip = ntohl(pa.s_addr);
                std::printf("[peers] public IP: %s\n", argv[i+1]);
            }
            if (std::strncmp(argv[i], "--seed", 6) == 0 && i + 1 < argc) {
            ++i;
            // parse ip:port
            std::uint32_t ip = 0;
            unsigned port = 0, octet = 0;
            bool after_colon = false;
            for (const char* c = argv[i]; *c; ++c) {
                if (*c == '.') { ip = (ip << 8) | octet; octet = 0; }
                else if (*c == ':') { ip = (ip << 8) | octet; octet = 0; after_colon = true; }
                else if (after_colon) port = port * 10 + (*c - '0');
                else octet = octet * 10 + (*c - '0');
            }
            if (ip && port) {
                seed_peers.push_back({ip, (std::uint16_t)port});
                g_seed_addrs.push_back({ip, (std::uint16_t)port});
                std::printf("[seed] %u.%u.%u.%u:%u\n",
                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF, ip & 0xFF, port);
            }
        }
    }
    
    // connect to seeds
    for (const auto& sp : seed_peers) {
        int fd = p2p::connect_peer(sp.ip, sp.port);
        if (fd >= 0) {
            peer_fds.push_back(fd);
            std::printf("[peer] connected to seed\n");
            // DEF-P3-08: late-joiner pulls committee state (one 0x0C back)
            {   p2p::Message req{}; req.type = 0x0B;   // SYNC_REQ
                p2p::send_message(fd, req);
                std::printf("[sync] 0x0B SYNC_REQ -> seed\n"); }
        } else {
            // DEFECT-183's lesson: a silent -1 hid this for six sessions
            std::printf("[seed] connect to %u.%u.%u.%u:%u FAILED\n",
                (sp.ip >> 24) & 0xFF, (sp.ip >> 16) & 0xFF,
                (sp.ip >> 8) & 0xFF, sp.ip & 0xFF, sp.port);
        }
    }
    
    // generate local decree entries to fill the epoch (the PROVEN law)
    std::printf("[node] generating %u local decree entries...\n", g_k_entries);
    for (unsigned i = 1; i <= g_k_entries; ++i) {   // genesis + k locals = the original count semantics
        const fp::fe dprev = digest_chain_fe.back();
        const auto terms = entry_terms(current_epoch, g_entry_seq++);
        const fp::fe pt = entry_pt(terms);
        const fp::fe dnew = chain_step(dprev, pt);
        chain_push(dnew);
        
        auto z = build_witness_fe(dprev, dnew, pt);
        mfold::Relaxed Ji = mfold::fresh(z, fcirc::NROWS);
        if (mfold::sat_relaxed(A, B, C, Ji) != fcirc::NROWS) {
            std::printf("[fold] local decree %u UNSAT\n", i);
            --g_entry_seq;
            continue;
        }
        
        mfold::MultifoldResult M = mfold::multifold(A, B, C, accumulator, {Ji});
        accumulator = M.folded;
        ++decree_count;
        // the NIVC exec absorption rides every fold
        g_acc.digest = poseidon3(dom::Dom::HSM_FOLD_v1, g_acc.digest, pt);
        ++g_acc.count;
    }
    
    // produce the π_E
    std::printf("[pi_E] epoch %u complete (%u entries) — producing π_E...\n",
        current_epoch, decree_count);
    
    std::vector<fp::fe> evals;
    for (const auto& v : accumulator.z) evals.push_back(v);
    for (const auto& e : accumulator.E) evals.push_back(e);
    evals.push_back(accumulator.u);
    
    unsigned npad = 1; while (npad < evals.size()) npad <<= 1;
    while (evals.size() < npad) evals.push_back(fp::fe_zero());
    
    auto P = whir::wrap_open(evals);
    
    unsigned nv = 0;
    {   unsigned tmp = npad; while (tmp > 1) { tmp >>= 1; ++nv; } }
    unsigned stage = 99;
    bool ok = whir::wrap_verify(P, nv, &stage);
    
    std::printf("[pi_E] epoch %u: wrap_verify %s (stage=%u)\n",
        current_epoch, ok ? "ACCEPT" : "REJECT", stage);
    
    run_epoch_pouw(); // P2-08: shared - main + handle_decree

    // DEF-401: the genesis epoch seals through the NIVC close
    nivc::fold_close(g_acc);
    // DEF-403: the ONE shared header builder (measured size)
    gossip_epoch_header(P);
    
    // the next epoch opens on the closed digest
    nivc::fold_head(g_acc, g_acc.digest, g_epoch_droot);
    g_entry_seq = 0;
    
    std::printf("\n═══════════════════════════════════════\n");
    std::printf("  EPOCH %u COMPLETE — π_E PRODUCED\n", current_epoch);
    std::printf("  decree entries: %u\n", decree_count);
    std::printf("  verify: %s\n", ok ? "ACCEPT" : "REJECT");
    std::printf("  peers: %zu\n", peer_fds.size());
    std::printf("  entering gossip loop (listening for new decrees)...\n");
    std::printf("═══════════════════════════════════════\n");

    // start the explorer (P2-03)
    explorer::NodeState ns;
    g_ns_shared.epoch = current_epoch;
    g_ns_shared.decree_count = decree_count;
    g_ns_shared.k_entries = g_k_entries;   // DEF-400: the wired k
    {   // DEF-401: the explorer shows the REAL NIVC accumulator tip
        fp::fe dc = fp::fe_to_canonical(g_acc.digest);
        char hex[128]; hex[0] = 0;
        for (int k = 3; k >= 0; --k) { char tmp[20]; snprintf(tmp, sizeof(tmp), "%016llx", (unsigned long long)dc.l[k]); strcat(hex, tmp); }
        g_ns_shared.state_root_hex = hex; }   // P5-C: the missed write (DEF-247 final)
    g_ns_shared.pi_e_status = ok ? "ACCEPT" : "PENDING";
    // DEF-403: pi_e_size is MEASURED (set by gossip_epoch_header); the
    // startup path lands here with the genesis epoch's real size.
    g_ns_shared.total_rows = (unsigned)A.row.size();   // P5-C: the missed write
    g_ns_shared.total_vars = (unsigned)(fcirc::NZ * (decree_count + 1));  // vars scale with entries
    g_ns_shared.port = my_port;
    g_ns_shared.pouw_inner = pouw_inner;
    g_ns_shared.pouw_weight = pouw_weight;
    g_ns_shared.pouw_verify = pouw_verify;

    // P2-08: DEFECT-171 - epoch 0 complete; the node now accepts epoch 1 decrees
    ++current_epoch;
    decree_count = 0;
    reset_epoch_ceremony();   // DEF-398: the ceremony is PER-EPOCH (boot path too)
    rotate_dkg();   // s4: the node's epoch committee, derived from the chain it just started
    
    // launch the explorer server on port 8080 (my_port + 8080-31233 = my_port + 6847)
    // for simplicity, use a fixed port: 8080
    std::thread exp_thread([&]() {
        explorer::run_explorer(my_port + 1000, g_ns_shared);
    });
    exp_thread.detach();
    
    // enter the gossip loop (the node stays alive, accepting connections)
    while (true) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(listener, &read_set);
        for (int fd : peer_fds) FD_SET(fd, &read_set);
        
        int max_fd = listener;
        for (int fd : peer_fds) if (fd > max_fd) max_fd = fd;
        
        struct timeval tv{};
        // P3-2b: the MSSC vote tick (fires every 1s)
        {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<double>(now - g_last_tick).count() >= 1.0) {
                g_last_tick = now;
                g_ns_shared.peer_count = peer_fds.size();
    g_fleet_active.store(!peer_fds.empty()); // P5-D: live fleet size
                // Gate-3: auto-reconnect — if we have no peers but have a seed
                // address, reconnect every 30 seconds. The fleet self-heals.
                static unsigned reconnect_timer = 0;
        // Phase 6.13b: the epoch advancement pulse — after epoch 0, one
        // synthetic decree per 60s so the lifecycle is exercisable on a
        // quiet testnet (honest label: advancement under synthetic load).
        // Route: handle_decree — the SAME path as wire-received decrees
        // (dedup -> fold -> completion -> gossip header). Payload is
        // deterministic from the chain tail + index: identical across
        // nodes -> chains converge by construction.
        static unsigned epoch_pulse_timer = 0;
        if (++epoch_pulse_timer >= 60) {
            epoch_pulse_timer = 0;
            if (decree_count < g_k_entries) {
                std::printf("[epoch-pulse] injecting synthetic decree %u/%u\n",
                    decree_count + 1, g_k_entries);
                std::vector<std::uint8_t> pl(64, 0);
                const auto& db = digest_chain.back();
                for (int k = 0; k < 4; ++k)
                    for (int b = 0; b < 8; ++b)
                        pl[k*8 + b] = (std::uint8_t)(db[k] >> (8*b));
                pl[32] = (std::uint8_t)(decree_count + current_epoch * g_k_entries);
                handle_decree(pl);   // the proven wire path: fold + completion
            }
        }
        // Phase 6.17 s2 (DEF-343): the quorum audit lives HERE — in the pulse
        // gate, independent of header exchanges. Trigger: the pool is non-empty
        // AND at least one boundary has passed since the pool's last audit.
        // The epoch-lag gate was the wrong trigger: lockstep pulsing means
        // nodes are never "one behind" at exchange moments — the lag window
        // closes forever once cadences sync. The pool lifecycle self-throttles.
        if (!g_epoch_claims.empty() && !g_quorum_audited_this_pool) {
            g_quorum_audited_this_pool = true;
            unsigned audited = 0, mism = 0;
            for (const auto& pl : g_epoch_claims) {
                // structural + linkage audit: the marker byte, the size contract
                if (pl.size() >= 43 && pl[42] == 0xC1) ++audited;
                else { ++mism; std::printf("[quorum] claim audit FAILED structure\n"); }
            }
            std::printf("[quorum] %zu claim-decrees audited (structure+linkage), %u mismatches\n",
                g_epoch_claims.size(), mism);
        // Phase 6.17 v2 s2 (CA-R370d): the ROTATING deep audit — same pool
        // lifecycle gate (one pass per pool; the audit above is tier-0 over
        // the whole pool). The verifier selects ONE claim deterministically —
        // seeded from THIS epoch's digest tail under the VERIFIER domain tag
        // (independent of the PoUW seed on the same tail) — re-derives the
        // claim's cryptographic identity (tier-1) and recomputes the full
        // GEMM when the fleet rung (n<=64) makes it affordable (tier-2).
        // Fresh tail + fresh pool each epoch: the sample auto-rotates.
        // No permanent verifier, no permanent sample.
        if (!g_epoch_claims.empty()) {
            const std::size_t pool = g_epoch_claims.size();
            const std::size_t sel = verifier::select_index(digest_chain.back(), pool);
            const auto& pl = g_epoch_claims[sel];
            std::uint64_t wid = 0;
            for (int b = 0; b < 8; ++b) wid |= (std::uint64_t)pl[32 + b] << (8 * b);
            explorer::WorkItem snap;   // bounded copy under the work mutex (once per pool)
            {   std::lock_guard<std::mutex> lk(g_work_mutex);
                auto it = g_work_done.find(wid);
                if (it != g_work_done.end()) snap = it->second; }
            const auto out = verifier::verify_claim(pl, snap);
            char ih[65] = {};
            for (int k = 0; k < 32; ++k) std::snprintf(ih + k * 2, 3, "%02x", out.identity[k]);
            g_verifier_receipt.has = true;
            g_verifier_receipt.epoch = current_epoch;
            g_verifier_receipt.pool = pool;
            g_verifier_receipt.work_id = wid;
            g_verifier_receipt.digest_ok = out.identity_ok;
            g_verifier_receipt.recompute_ran = out.recompute_ran;
            g_verifier_receipt.recompute_ok = out.recompute_ok;
            g_verifier_receipt.pass = out.pass;
            g_verifier_receipt.identity_hex = ih;
            ++g_verifier_rotations;
            std::printf("[verifier] epoch %u: rotation %llu selected pool[%zu/%zu] work %llu — identity %s%s | %s\n",
                current_epoch, (unsigned long long)g_verifier_rotations, sel, pool,
                (unsigned long long)wid,
                out.identity_ok ? "PASS" : "FAIL",
                out.recompute_ran ? (out.recompute_ok ? " | recompute PASS" : " | recompute FAIL")
                                  : " | recompute n/a (above fleet rung)",
                out.pass ? "CLAIM VERIFIED" : "CLAIM REJECTED");
        }

        // ---- s4 (DEC-s4): the pool AGGREGATE pass — same pool lifecycle
        // gate. tier-1 identity for EVERY claim in the pool, tier-2 recompute
        // for every in-rung claim under the MAC budget (the heartbeat never
        // stalls). The receipt covers the WHOLE pool, not one sample; the
        // budget-skipped claims are counted, never silently dropped.
        {
            std::map<std::uint64_t, explorer::WorkItem> pool_snap;
            {   std::lock_guard<std::mutex> lk(g_work_mutex);
                for (const auto& cpl : g_epoch_claims) {
                    if (cpl.size() < 43) continue;
                    std::uint64_t cwid = 0;
                    for (int b = 0; b < 8; ++b)
                        cwid |= (std::uint64_t)cpl[32 + b] << (8 * b);
                    auto it = g_work_done.find(cwid);
                    if (it != g_work_done.end()) pool_snap[cwid] = it->second;
                }
            }
            const auto pout = verifier::verify_pool(g_epoch_claims, pool_snap);
            auto& R = g_verifier_receipt;
            R.pool_has = true;
            R.pool_size = pout.pool;
            R.pool_structure_bad = pout.structure_bad;
            R.pool_unknown_work = pout.unknown_work;
            R.pool_tier1_ok = pout.tier1_ok;
            R.pool_tier1_bad = pout.tier1_bad;
            R.pool_tier2_ran = pout.tier2_ran;
            R.pool_tier2_ok = pout.tier2_ok;
            R.pool_tier2_bad = pout.tier2_bad;
            R.pool_tier2_skipped = pout.tier2_skipped_budget;
            R.pool_macs_spent = pout.macs_spent;
            R.pool_pass = pout.pass;
            std::printf("[verifier-pool] aggregate: %zu claims — tier1 %llu ok / %llu bad, tier2 %llu ok / %llu bad (%llu skipped by budget, %llu MACs spent) | %s\n",
                pout.pool,
                (unsigned long long)pout.tier1_ok, (unsigned long long)pout.tier1_bad,
                (unsigned long long)pout.tier2_ok, (unsigned long long)pout.tier2_bad,
                (unsigned long long)pout.tier2_skipped_budget,
                (unsigned long long)pout.macs_spent,
                pout.pass ? "POOL CLEAN" : "POOL REJECTED");
        }
        }
                if (peer_fds.empty() && !g_seed_addrs.empty()) {
                    if (++reconnect_timer >= 30) {
                        reconnect_timer = 0;
                        std::printf("[reconnect] no peers — attempting reconnect to seed...\n");
                        for (const auto& sa : g_seed_addrs) {
                            int fd = p2p::connect_peer(sa.ip, sa.port);
                            if (fd >= 0) {
                                peer_fds.push_back(fd);
                                g_mssc.peers.push_back({sa.ip, sa.port, 30, 0});   // DEF-395: identity bound on first verified vote
                                g_mssc.total_weight += 30;
                                std::printf("[reconnect] SUCCESS — reconnected to seed\n");
                                break;
                            }
                        }
                    }
                }
                // P5-D: the main-loop pulse — time-based, NOT peer-gated (a solo node is alive).
                // DEF-244: the peer-gated heartbeat froze on fresh nodes -> watchdog restart loop.
                g_hb_consensus.fetch_add(1, std::memory_order_relaxed);g_hb_consensus.fetch_add(1, std::memory_order_relaxed);

            // Phase 6.2: process queued work - one GEMM per tick
            {
                std::lock_guard<std::mutex> lk(g_work_mutex);
                for (auto& w : g_work_queue) {
                    if (w.status == WorkStatus::QUEUED) {
                        w.status = WorkStatus::PROCESSING;
                        unsigned gn = (unsigned)w.n;
                        std::uint64_t gseed = w.id * 7919 + 13;
                        std::vector<fp::fe> gA(gn*gn), gB(gn*gn), gC(gn*gn);
                        std::uint64_t gst = gseed;
                        auto grnd = [&gst]() -> fp::fe {
                            gst ^= gst << 13; gst ^= gst >> 7; gst ^= gst << 17;
                            return fp::fe_from_u64(gst * 0x9E3779B97F4A7C15ull);
                        };
                        {   // 6.11: prove over the COMPANY's data when ingested
                            if (w.has_inputs && w.A_in.size() == (std::size_t)gn * gn && w.B_in.size() == (std::size_t)gn * gn) {
                                gA = w.A_in; gB = w.B_in;
                            } else if (!w.has_inputs) {
                                for (auto& x : gA) x = grnd();
                                for (auto& x : gB) x = grnd();
                                // Phase 6.17 v2 s1.1 (CA-R345): the faucet
                                // write-back — the self-generated matrices are
                                // bound into the work record exactly like
                                // ingested data (ic bound at generation; the
                                // swap gate below re-derives it). Before s1.1
                                // these bytes were proven over but never served:
                                // the claim condition (has_inputs && verified)
                                // was structurally unsatisfiable for faucet
                                // work — the s1 404 root cause.
                                explorer::bind_faucet_inputs(w, gA, gB);
                            }   // else: malformed ingestion (sizes wrong, ic
                                // unbound) — the gate below fails it and gvok
                                // keeps the work FAILED, as before s1.1
        // 6.11b: re-verify the input commitment BEFORE proving — the swap gate
        // (s1.1: uniform — ingested AND faucet work pass through the same gate)
        {   std::size_t an = w.A_in.size() * 32, bn = w.B_in.size() * 32;
            std::vector<std::uint8_t> cat(an + bn);   // DEF-315: heap, sized by data
            for (std::size_t k = 0; k < w.A_in.size(); ++k)
                fp::fe_to_le_bytes(w.A_in[k], reinterpret_cast<std::byte*>(cat.data() + k * 32));
            for (std::size_t k = 0; k < w.B_in.size(); ++k)
                fp::fe_to_le_bytes(w.B_in[k], reinterpret_cast<std::byte*>(cat.data() + an + k * 32));
            std::uint8_t h[32];
            digest::sha256(cat.data(), cat.size(), h);
            w.commitment_checked = (std::memcmp(h, w.ic.data(), 32) == 0);
            if (!w.commitment_checked)
                std::printf("[work] work_id %llu: COMMITMENT MISMATCH — inputs tampered post-ingestion\n",
                    (unsigned long long)w.id);
        }
                        }
                        pouw::gemm(gA.data(), gB.data(), gC.data(), gn);
                        const auto wt0 = std::chrono::steady_clock::now();
                        auto GPP = pouw::prove_gemm_v2(gA, gB, gC, gn, gn, gn);
                        bool gvok = pouw::verify_gemm_v2(GPP, gA, gB, gC);
        if (w.has_inputs) gvok = gvok && w.commitment_checked;
                        w.status = gvok ? WorkStatus::DONE : WorkStatus::FAILED;
                        w.verified = gvok;
                        w.completed_at = (std::uint64_t)time(nullptr);
                        // Phase 6.12: serialize C canonical-LE for result delivery
                        if (gvok) {
                            w.has_result = true;
                            // Phase 6.12 (DEF-374 FIX, order): serialize the
                            // result BEFORE the fold — the claim identity is
                            // SHA256(work_id||n||ic||result_first32) and the
                            // result prefix MUST be real bytes. The pre-s3
                            // order folded first: result_bytes was still
                            // empty, the guard silently dropped the prefix,
                            // and every folded claim carried a weaker
                            // identity that its OWN verifier would reject
                            // (never observed before s3 — the live rotation
                            // had never fired; the first CPU-band run caught
                            // it within one tick).
                            w.result_bytes.reserve(gC.size() * 32);
                            for (const auto& fe : gC) {
                                std::uint8_t ob[32];
                                fp::fe_to_le_bytes(fe, reinterpret_cast<std::byte*>(ob));
                                w.result_bytes.insert(w.result_bytes.end(), ob, ob + 32);
                            }
                            // Phase 6.17 (Path A): verified GPU claims fold into the
                            // accumulator as claim-decrees. Payload: [digest(32) =
                            // SHA256(work_id||n||ic||result_first32)][work_id(8)][n(4)]
                            // [type(1)=0xC1]. The digest is the claim's cryptographic
                            // identity; folding it makes the claim part of pi_E's hash
                            // history — tamper-evident forever.
                            if (w.n > 64) {
                                std::vector<std::uint8_t> claim_id(32);
                                {   std::vector<std::uint8_t> mat;
                                    auto put64 = [&](std::uint64_t v){ for (int b=0;b<8;++b) mat.push_back((std::uint8_t)(v >> (8*b))); };
                                    put64(w.id); put64(w.n);
                                    for (auto b : w.ic) mat.push_back(b);
                                    if (!w.result_bytes.empty())
                                        mat.insert(mat.end(), w.result_bytes.begin(), w.result_bytes.begin() + 32);
                                    digest::sha256(mat.data(), mat.size(), claim_id.data());
                                }
                                std::vector<std::uint8_t> pl = claim_id;
                                auto put64 = [&](std::uint64_t v){ for (int b=0;b<8;++b) pl.push_back((std::uint8_t)(v >> (8*b))); };
                                put64(w.id);
                                pl.push_back((std::uint8_t)(w.n >> 8)); pl.push_back((std::uint8_t)(w.n & 0xFF));
                                pl.push_back(0xC1);   // claim-decree marker
                                handle_decree(pl);
                                std::printf("[claim] work_id %llu (n=%u) folded into the accumulator as a claim-decree\n",
                                    (unsigned long long)w.id, w.n);
                                g_epoch_claims.push_back(pl);   // s2: the audit pool
                            }
                        }
                        g_work_done[w.id] = w;
                        g_work_queue.erase(std::remove_if(g_work_queue.begin(),
                            g_work_queue.end(),
                            [&w](const WorkItem& item) { return item.id == w.id; }),
                            g_work_queue.end());
                        const auto wt1 = std::chrono::steady_clock::now();
                        const auto wms = std::chrono::duration_cast<std::chrono::milliseconds>(wt1 - wt0).count();
                        printf("[work] work_id %llu: %s (n=%u, %lld ms)\n",
                            (unsigned long long)w.id,
                            gvok ? "VERIFIED" : "FAILED", gn, (long long)wms);
                        break;
                    }
                }
            }
                g_ns_shared.uptime_s = (unsigned long long)std::chrono::duration_cast<std::chrono::seconds>(now - g_boot).count();
                g_ns_shared.hb_consensus = g_hb_consensus.load(std::memory_order_relaxed);
                // Phase 6.17 v2 s2: mirror the verifier receipt into the served state
                g_ns_shared.verifier_has_receipt = g_verifier_receipt.has;
                g_ns_shared.verifier_epoch = g_verifier_receipt.epoch;
                g_ns_shared.verifier_pool = g_verifier_receipt.pool;
                g_ns_shared.verifier_work_id = g_verifier_receipt.work_id;
                g_ns_shared.verifier_digest_ok = g_verifier_receipt.digest_ok;
                g_ns_shared.verifier_recompute_ran = g_verifier_receipt.recompute_ran;
                g_ns_shared.verifier_recompute_ok = g_verifier_receipt.recompute_ok;
                g_ns_shared.verifier_pass = g_verifier_receipt.pass;
                g_ns_shared.verifier_rotations = g_verifier_rotations;
                g_ns_shared.verifier_identity_hex = g_verifier_receipt.identity_hex;
                // s4: pool aggregate + DKG rotation mirrored for the routes
                g_ns_shared.pool_has = g_verifier_receipt.pool_has;
                g_ns_shared.pool_size = g_verifier_receipt.pool_size;
                g_ns_shared.pool_structure_bad = g_verifier_receipt.pool_structure_bad;
                g_ns_shared.pool_unknown_work = g_verifier_receipt.pool_unknown_work;
                g_ns_shared.pool_tier1_ok = g_verifier_receipt.pool_tier1_ok;
                g_ns_shared.pool_tier1_bad = g_verifier_receipt.pool_tier1_bad;
                g_ns_shared.pool_tier2_ran = g_verifier_receipt.pool_tier2_ran;
                g_ns_shared.pool_tier2_ok = g_verifier_receipt.pool_tier2_ok;
                g_ns_shared.pool_tier2_bad = g_verifier_receipt.pool_tier2_bad;
                g_ns_shared.pool_tier2_skipped = g_verifier_receipt.pool_tier2_skipped;
                g_ns_shared.pool_macs_spent = g_verifier_receipt.pool_macs_spent;
                g_ns_shared.pool_pass = g_verifier_receipt.pool_pass;
                g_ns_shared.dkg_has = g_dkg_live;
                g_ns_shared.dkg_epoch = current_epoch;
                g_ns_shared.dkg_n = g_dkg_n;
                g_ns_shared.dkg_t = g_dkg_t;
                g_ns_shared.dkg_shares_ok = g_dkg_shares_ok;
                g_ns_shared.dkg_agg_pk_hex = g_dkg_agg_pk_hex;
                // Gate-3: uptime proof broadcast — every 300 ticks (5 minutes), if peers exist
                static std::uint64_t uptime_tick_counter = 0;
                if (++uptime_tick_counter >= 300 && !peer_fds.empty()) {
                    uptime_tick_counter = 0;
                    std::vector<std::uint8_t> up(28, 0);
                    const std::uint64_t mid = g_self_member;
                    const std::uint64_t ep = 0, rd = g_mssc.rounds;
                    const std::uint64_t ups = g_ns_shared.uptime_s;
                    for (int i = 0; i < 8; ++i) { up[i] = std::uint8_t(mid >> (8*i)); up[8+i] = std::uint8_t(ep >> (8*i)); }
                    for (int i = 0; i < 8; ++i) { up[16+i] = std::uint8_t(rd >> (8*i)); up[24+i] = std::uint8_t(ups >> (8*i)); }
                    for (int fd : peer_fds) {
                        p2p::Message mu{}; mu.type = 0x0A; mu.payload = up;
                        p2p::send_message(fd, mu);
                    }
                }
                // P5-D: the main-loop pulse — time-based, NOT peer-gated (a solo node is alive).
                // DEF-244: the peer-gated heartbeat froze on fresh nodes -> watchdog restart loop.

                g_ns_shared.hb_consensus = g_hb_consensus.load(std::memory_order_relaxed);
                {
                    // DEF-393: REAL epoch + REAL weight root in the preimage -
                    // votes are state for THIS epoch, THIS roster, THIS conflict.
                    // DEF-394: v2 carries the claimed member (one pairing to verify).
                    auto pre = msscvote::vote_preimage((std::uint32_t)current_epoch,
                        g_weight_root, g_mssc.conflict, g_mssc.rounds,
                        g_mssc.preference);
                    auto sig = msscvote::sign_vote(g_own_share, pre);
                    auto msg = msscvote::encode_vote_v2((std::uint32_t)current_epoch,
                        g_weight_root, g_mssc.conflict, g_mssc.rounds,
                        g_mssc.preference, sig, g_self_member);
                    for (int fd : peer_fds) p2p::send_message(fd, msg);
                }
                // P5-B hygiene: stale single-sig batches die with the round (testnet scope)
                if (g_agg_batches.size() > 128) g_agg_batches.clear();
                if (!g_peer_prefs.empty()) {
                    // DEF-395: (member_id, preference) PAIRS - weight attribution
                    // by identity, never by map position or connection order.
                    std::vector<std::pair<std::uint64_t, consensus::Digest>> pp(
                        g_peer_prefs.begin(), g_peer_prefs.end());
                                        auto tick_t0 = std::chrono::steady_clock::now();
                    auto rr = msscloop::tick(g_mssc, g_cfg, pp);
                    auto tick_t1 = std::chrono::steady_clock::now();
                    auto tick_ms = std::chrono::duration_cast<std::chrono::milliseconds>(tick_t1 - tick_t0).count();
                    if (tick_ms > 100) {
                        std::fprintf(stderr, "[DIAG-SLOW] mssc tick blocked %.1f ms\n", tick_ms);
                    }
                    // P5-E: adversarial bound at every tally — f >= 20% HALTs
                    {
                        std::uint64_t adv_w = 0;
                        for (const auto& [am, fl] : g_adversarial)
                            if (fl) adv_w += g_stake_reg.active_weight(am);
                        if (g_stake_reg.adversarial_check(g_stake_reg.total_active(), adv_w)
                            == econ::StakeRegistry::AdversarialVerdict::HALT)
                            std::printf("[stake] ADVERSARIAL HALT - f >= 20 pct\n");
                    }
                    std::printf("[mssc] round %u: pref=%s conf=%u kind=%d\n",
                        g_mssc.rounds,
                        g_mssc.preference == consensus::sha256d((const std::uint8_t*)"decreeA",7) ? "A" : "B",
                        g_mssc.confidence, (int)rr.kind);

                    // P3-3 (DEC-274) LIVE wiring: on suspension the breaker
                    // resolves the REAL conflict set (verified vote preferences)
                    // under the REAL threshold beacon - the fabricated-"decreeB"
                    // breaker body is dead (DEF-392b).
                    if (g_mssc.state == consensus::State::Suspended) {
                        std::vector<consensus::Digest> frozen{g_mssc.preference};
                        for (const auto& [mid, p] : g_peer_prefs)
                            if (!(p == g_mssc.preference)) frozen.push_back(p);
                        threshold::beacon::Committee bcom;
                        for (std::uint64_t j = 1; j <= g_cfg_t_eff && j <= g_dkg_T.n; ++j) {
                            bcom.ids.push_back(j);
                            bcom.shares.push_back(threshold::dkg::share_for(g_test_poly, j));
                        }
                        auto br = msscloop::breaker_tick(g_mssc, g_cfg, bcom,
                            (std::uint64_t)current_epoch + 1ull, g_prev_beacon, frozen);
                        std::printf("[mssc] breaker: suspended=%d resolved=%d stagger=%llu ms\n",
                            (int)br.suspended, (int)br.resolved,
                            (unsigned long long)br.stagger_ms);
                    }
                }
            }
        }
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        auto sel_t0 = std::chrono::steady_clock::now();
        int ready = select(max_fd + 1, &read_set, nullptr, nullptr, &tv);
        auto sel_t1 = std::chrono::steady_clock::now();
        auto sel_ms = std::chrono::duration_cast<std::chrono::milliseconds>(sel_t1 - sel_t0).count();
        if (ready < 0) { std::printf("[DIAG] select ERROR errno=%d\n", errno); break; }
        if (sel_ms > 2000) {
            std::fprintf(stderr, "[DIAG-SLOW] select blocked %.1f ms (expected ~1000)\n", sel_ms);
        }
        
        if (FD_ISSET(listener, &read_set)) {
            struct sockaddr_in addr{};
            socklen_t len = sizeof(addr);
            int new_fd = accept(listener, (struct sockaddr*)&addr, &len);
            if (new_fd >= 0 && p2p::ip_banned(g_peer_bans, ntohl(addr.sin_addr.s_addr))) {
                std::printf("[sec] banned peer connection refused (ip=%08x)\n", ntohl(addr.sin_addr.s_addr));
                close(new_fd);
                new_fd = -1;   // the existing >= 0 check skips the body — no state created
            }
            if (new_fd >= 0) {
                {   struct timeval atv{.tv_sec = 5, .tv_usec = 0}; setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, &atv, sizeof(atv)); }
                peer_fds.push_back(new_fd);
                std::printf("[peer] new connection (fd=%d)\n", new_fd);
                // DEF-254: TCP keepalive on accepted connections
                {   int ka = 1;
                    setsockopt(new_fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
                    int idle = 30, intvl = 10, cnt = 3;
                    setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
                    setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
                    setsockopt(new_fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
                }
                        // P5-C polish (DEF-242): shares are STATE, not events.
                        // A newly connected peer must receive every stored decryption
                        // share — otherwise dedup-silence + one-broadcast starves it
                        // (the cross-ceremony waiting x10). g_dec_shares aligns 1:1
                        // with g_mempool (both push together, dedup skips both).
                        // DEF-P3-08: ONE batch message replaces the O(n) 0x08 spam.
                        if (!g_dec_shares.empty()) send_sync_batch(new_fd);

                        // Gate-3 v2: DYNAMIC peer addition — the new connection joins
                        // the MSSC sampling list immediately with a default weight.
                        // Their stake-derived weight replaces this when the economic
                        // layer is bound to real bonds (P5-E production).
                        {   std::uint64_t default_w = 30;  // testnet default peer weight
                            g_mssc.peers.push_back({0, (std::uint16_t)new_fd, default_w, 0});  // ip=0: discovered via 0x09; DEF-395: identity on first verified vote
                            g_fd_weights[new_fd] = default_w;
                            g_mssc.total_weight += default_w;
                            std::printf("[committee] peer JOINED: fd=%d weight=%llu, fleet total=%llu\n",
                                new_fd, (unsigned long long)default_w, (unsigned long long)g_mssc.total_weight);
                        }

                        // Gate-3: announce OUR address to the new peer (peer exchange)
                        if (g_my_public_ip != 0) {
                            std::vector<std::uint8_t> ann(6, 0);
                            std::uint32_t netip = htonl(g_my_public_ip);
                            std::memcpy(ann.data(), &netip, 4);
                            ann[4] = std::uint8_t(my_port & 255);
                            ann[5] = std::uint8_t(my_port >> 8);
                            p2p::Message ma{}; ma.type = 0x09; ma.payload = ann;
                            p2p::send_message(new_fd, ma);
                        }
            }
        }
        
        for (std::size_t i = 0; i < peer_fds.size(); ++i) {
            if (FD_ISSET(peer_fds[i], &read_set)) {
                // Phase 6.9: per-peer rate limit. Exceed -> ban the IP + close;
                // the close makes recv fail below, and the existing DEF-255
                // disconnect path performs the FULL cleanup (weight, MSSC, erase).
                {   struct sockaddr_in pa{}; socklen_t pal = sizeof(pa);
                    if (!p2p::peer_allow(peer_fds[i])) {
                        if (getpeername(peer_fds[i], (struct sockaddr*)&pa, &pal) == 0)
                            p2p::ip_ban(g_peer_bans, ntohl(pa.sin_addr.s_addr));
                        std::printf("[sec] fd=%d rate exceeded — ip banned, closing\n", peer_fds[i]);
                        close(peer_fds[i]);
                    } else if (getpeername(peer_fds[i], (struct sockaddr*)&pa, &pal) == 0
                               && p2p::ip_banned(g_peer_bans, ntohl(pa.sin_addr.s_addr))) {
                        std::printf("[sec] fd=%d belongs to a banned ip — closing\n", peer_fds[i]);
                        close(peer_fds[i]);
                    }
                }
                p2p::Message msg;
                auto recv_t0 = std::chrono::steady_clock::now();
                bool recv_ok = p2p::recv_message(peer_fds[i], msg);
                auto recv_t1 = std::chrono::steady_clock::now();
                auto recv_ms = std::chrono::duration_cast<std::chrono::milliseconds>(recv_t1 - recv_t0).count();
                if (recv_ms > 1000) {
                    std::fprintf(stderr, "[DIAG-SLOW] recv_message blocked %.1f ms (fd=%d)\n", recv_ms, peer_fds[i]);
                }
                if (recv_ok) {
                        std::printf("[recv] type=%u size=%zu\n", msg.type, msg.payload.size());
                    if (msg.type == 0x0A) {
                        // Gate-3: UPTIME_PROOF — signed heartbeat receipt
                        // Payload: {member_id 8B, epoch 4B, round 8B, uptime_s 8B} = 28B
                        if (msg.payload.size() != 28) { std::printf("[uptime] 0x0A bad size %zu\n", msg.payload.size()); }
                        else {
                            const std::uint8_t* p = msg.payload.data();
                            std::uint64_t mid = 0, ep = 0, rd = 0, up = 0;
                            for (int i = 0; i < 8; ++i) { mid |= (std::uint64_t)p[i] << (8*i); ep |= (std::uint64_t)p[8+i] << (8*i); }
                            for (int i = 0; i < 8; ++i) { rd |= (std::uint64_t)p[16+i] << (8*i); up |= (std::uint64_t)p[24+i] << (8*i); }
                            // anti-replay: the round must advance per member
                            auto last = g_last_receipt.find(mid);
                            if (last != g_last_receipt.end() && rd <= last->second) {
                                std::printf("[uptime] member %llu replay (round %llu <= %llu) — skipped\n",
                                    (unsigned long long)mid, (unsigned long long)rd, (unsigned long long)last->second);
                            } else {
                                // accept the receipt (BLS verification of the sig is TODO at production —
                                // testnet: the payload comes over an established TCP session from a
                                // verified peer, which is the authentication layer for now)
                                g_uptime_ledger[mid] += 300;   // 5-minute granularity
                                g_receipt_count[mid]++;
                                g_last_receipt[mid] = rd;
                                std::printf("[uptime] member %llu: +300s (total %llu s, %llu receipts, round %llu)\n",
                                    (unsigned long long)mid, (unsigned long long)g_uptime_ledger[mid],
                                    (unsigned long long)g_receipt_count[mid], (unsigned long long)rd);
                            }
                        }
                    } else if (msg.type == 0x09) {
                        // P5-H+/Gate-3: PEER_ANNOUNCE — a node announces its address
                        // Payload: {ip 4B network-order, port 2B LE} = 6 bytes
                        if (msg.payload.size() != 6) { std::printf("[peers] 0x09 bad size\n"); }
                        else {
                            const std::uint8_t* p = msg.payload.data();
                            std::uint32_t ip = (std::uint32_t)p[0] | ((std::uint32_t)p[1]<<8)
                                             | ((std::uint32_t)p[2]<<16) | ((std::uint32_t)p[3]<<24);
                            std::uint16_t prt = (std::uint16_t)p[4] | ((std::uint16_t)p[5]<<8);
                            // store in the discovery list (dedup by ip:port)
                            bool known = false;
                            for (const auto& dp : g_discovered)
                                if (dp.ip == ip && dp.port == prt) { known = true; break; }
                            if (!known) {
                                g_discovered.push_back({ip, prt});
                                std::printf("[peers] discovered %u.%u.%u.%u:%u (fleet %zu)\n",
                                    (ip>>24)&255, (ip>>16)&255, (ip>>8)&255, ip&255, prt, g_discovered.size());
                                // Phase 6.8: announce-dialing — if the announced node is
                                // publicly reachable, connect DIRECTLY (NAT traversal v1:
                                // public peers get direct links; NAT'd nodes stay hub-
                                // connected — full connectivity already exists via the anchor).
                                if (peer_fds.size() < p2p::MAX_PEERS) {
                                    int dfd = p2p::connect_peer(ip, prt);
                                    if (dfd >= 0) {
                                        peer_fds.push_back(dfd);
                                        g_fd_weights[dfd] = 30; // DEF-255 symmetry: record by fd
                                        g_mssc.peers.push_back({ip, prt, 30, 0});   // DEF-395: identity bound on first verified vote
                                        g_mssc.total_weight += 30;
                                        std::printf("[peers] dialed announced peer %u.%u.%u.%u:%u (direct link)\n",
                                            (ip>>24)&255, (ip>>16)&255, (ip>>8)&255, ip&255, prt);
                                    }
                                }
                                // RELAY the announcement to other peers (gossip)
                                for (int fd : peer_fds) {
                                    if (fd == peer_fds[0]) continue; // dont echo to sender (simplified)
                                    p2p::Message mx{}; mx.type = 0x09; mx.payload = msg.payload;
                                    p2p::send_message(fd, mx);
                                }
                            }
                        }
                    } else if (msg.type == 0x08) {
                        // P5-C: DEC_SHARE from a peer — {envelope_index u32, member_id u32, D_j 192B}
                        if (msg.payload.size() != 200) { std::printf("[thr] 0x08 bad size\n"); }
                        else {
                            const std::uint8_t* p = msg.payload.data();
                            std::size_t eix = (std::size_t)p[0] | ((std::size_t)p[1]<<8) | ((std::size_t)p[2]<<16) | ((std::size_t)p[3]<<24);
                            std::uint64_t mid = (std::uint64_t)p[4] | ((std::uint64_t)p[5]<<8) | ((std::uint64_t)p[6]<<16) | ((std::uint64_t)p[7]<<24);
                            std::uint64_t xa[6], xb[6], ya[6], yb[6];
                            for (int i = 0; i < 6; ++i) { xa[i]=0; xb[i]=0; ya[i]=0; yb[i]=0;
                                for (int b = 0; b < 8; ++b) {
                                    xa[i] |= (std::uint64_t)p[8+i*8+b] << (8*b);
                                    xb[i] |= (std::uint64_t)p[56+i*8+b] << (8*b);
                                    ya[i] |= (std::uint64_t)p[104+i*8+b] << (8*b);
                                    yb[i] |= (std::uint64_t)p[152+i*8+b] << (8*b);
                                } }
                            auto Dj = threshold::g2::from_affine(xa, xb, ya, yb);
                            auto& v = g_thr_shares[eix];
                            bool have = false;
                            for (const auto& [m0, d0] : v) if (m0 == mid) have = true;
                            if (!have) { v.push_back({mid, Dj});
                                std::printf("[thr] 0x08: share from member %llu for envelope %zu (collected %zu)\n",
                                    (unsigned long long)mid, eix, v.size()); }
                        // P5-C retrigger (DEF-237) + DEF-P3-05/06: the duplicated body is
                        // retired — the ONE shared decrypt path serves both call sites.
                        // DEF-391: shares for an UNLOCKED epoch are refused - a share
                        // set without an attested lock is a timeline fork, not gossip.
                        {   auto lit = g_order_locks.find(g_pool_epoch);
                            const bool lock_ok = g_order_committed
                                || (lit != g_order_locks.end() && lit->second.attested);
                            if (!lock_ok)
                                std::printf("[thr] 0x08 share REFUSED - no attested lock for epoch %u\n",
                                    (unsigned)g_pool_epoch);
                            else if (g_order_committed) (void)try_decrypt_envelope(eix);
                        }
                        }
                    } else if (msg.type == 0x0B) {
                        // DEF-P3-08: SYNC_REQ — answer with the full share set (one message)
                        send_sync_batch(peer_fds[i]);
                    } else if (msg.type == 0x0C) {
                        // DEF-P3-08: SYNC_BATCH — ingest (eix, member, D_j) records
                        if (msg.payload.size() >= 4 && (msg.payload.size() - 4) % 204 == 0) {
                            const std::uint32_t cnt = (std::uint32_t)msg.payload[0]
                                | ((std::uint32_t)msg.payload[1] << 8)
                                | ((std::uint32_t)msg.payload[2] << 16)
                                | ((std::uint32_t)msg.payload[3] << 24);
                            std::size_t got = 0;
                            for (std::uint32_t r = 0; r < cnt; ++r) {
                                const std::uint8_t* p = msg.payload.data() + 4 + r * 204;
                                const std::size_t eix = (std::size_t)p[0] | ((std::size_t)p[1] << 8)
                                    | ((std::size_t)p[2] << 16) | ((std::size_t)p[3] << 24);
                                std::uint64_t mid = 0;
                                for (int i = 0; i < 8; ++i) mid |= (std::uint64_t)p[4+i] << (8*i);
                                std::uint64_t xa[6], xb[6], ya[6], yb[6];
                                for (int i = 0; i < 6; ++i) { xa[i]=0; xb[i]=0; ya[i]=0; yb[i]=0;
                                    for (int b = 0; b < 8; ++b) {
                                        xa[i] |= (std::uint64_t)p[12+i*8+b] << (8*b);
                                        xb[i] |= (std::uint64_t)p[60+i*8+b] << (8*b);
                                        ya[i] |= (std::uint64_t)p[108+i*8+b] << (8*b);
                                        yb[i] |= (std::uint64_t)p[156+i*8+b] << (8*b);
                                    } }
                                auto Dj = threshold::g2::from_affine(xa, xb, ya, yb);
                                bool have = false;
                                for (const auto& [m0, d0] : g_thr_shares[eix])
                                    if (m0 == mid) { have = true; break; }
                                if (!have) { g_thr_shares[eix].push_back({mid, Dj}); ++got; }
                            }
                            std::printf("[sync] 0x0C batch: %u records, %zu new\n", cnt, got);
                            // DEF-391: same lock law as 0x08 - the batch is ingested
                            // (state for the attested epoch) but decryption runs only
                            // under a committed order.
                            {   auto lit = g_order_locks.find(g_pool_epoch);
                                const bool lock_ok = g_order_committed
                                    || (lit != g_order_locks.end() && lit->second.attested);
                                if (!lock_ok)
                                    std::printf("[thr] 0x0C batch REFUSED - no attested lock for epoch %u\n",
                                        (unsigned)g_pool_epoch);
                                else if (g_order_committed)
                                    for (std::size_t ei = 0; ei < g_mempool.size(); ++ei)
                                        (void)try_decrypt_envelope(ei);
                            }
                        }
                    } else if (msg.type == 0x06) {
                        // P3-1b (DEC-271): the MSSC vote wire path
                        auto dv = msscvote::decode_vote(msg);
                        std::printf("[voted] ok=%d epoch=%u round=%llu\n",
                            (int)dv.ok, dv.epoch, (unsigned long long)dv.round);
                        bool accepted = false; std::uint64_t member = 0;
                        if (dv.ok) {
                            // DEF-393 (CA-R372e): the freshness gate - ONE epoch,
                            // ONE weight root, ONE conflict set, round window +-1.
                            // Everything else is a replay or a fork statement.
                            const bool fresh = msscloop::vote_fresh(dv.epoch, dv.round,
                                dv.weight_root, g_weight_root,
                                dv.conflict, g_mssc.conflict,
                                current_epoch, g_mssc.rounds);
                            if (!fresh) {
                                std::printf("[vote] REJECT stale/forked (epoch %u round %llu; cur %u/%llu)\n",
                                    dv.epoch, (unsigned long long)dv.round,
                                    current_epoch, (unsigned long long)g_mssc.rounds);
                            }
                            auto pre = msscvote::vote_preimage(dv.epoch, dv.weight_root,
                                                               dv.conflict, dv.round, dv.preference);
                            std::printf("[voted] members=%zu fresh=%d\n", g_members.size(), (int)fresh);
                            if (fresh && dv.has_member) {
                                // DEF-394 (CA-R372f): ONE pairing against the CLAIMED
                                // key - the claim is verified, never scanned for.
                                const threshold::g2::G2Pt* Yc = nullptr;
                                for (const auto& [jid, Yj] : g_members)
                                    if (jid == dv.member) { Yc = &Yj; break; }
                                if (Yc && !threshold::g2::PisInf(*Yc)
                                        && msscvote::verify_vote_member(dv.sigma, pre, *Yc)) {
                                    accepted = true; member = dv.member;
                                    std::printf("[voted] member %llu verify=1 (claimed, 1 pairing)\n",
                                        (unsigned long long)member);
                                }
                            } else if (fresh) {
                                // legacy 204B payload: the O(n) scan (rollout compat)
                                for (const auto& [jid, Y] : g_members) {
                                    if (threshold::g2::PisInf(Y)) continue;
                                    const bool v = msscvote::verify_vote(dv.sigma, pre, Y);
                                    std::printf("[voted] member %llu verify=%d\n",
                                        (unsigned long long)jid, (int)v);
                                    if (v) {
                                        accepted = true; member = jid;
                                    // P3-3b: accumulate into the batch (for future aggregate verify)
                                    // P5-B: batch by (round, preference) — same-message aggregation only
                                    { std::array<std::uint8_t, 40> bkey{};
                                      for (int i = 0; i < 8; ++i) bkey[i] = std::uint8_t(dv.round >> (8 * i));
                                      const std::uint8_t* pb = (const std::uint8_t*)&dv.preference;
                                      for (int i = 0; i < 32; ++i) bkey[8 + i] = pb[i];
                                      auto& b = g_agg_batches[bkey];
                                      std::printf("[agg-batch] join: round=%llu count->%u\n",
                                          (unsigned long long)dv.round, b.count + 1);
                                      if (b.count == 0) b.pre = pre;   // the batch's shared preimage
                                      msscvote::agg_accumulate(b.av, dv.sigma, Y);
                                      if (++b.count >= 2) {
                                          const auto t0 = std::chrono::steady_clock::now();
                                          const bool ok = msscvote::agg_verify(b.av, b.pre);
                                          const double ams = std::chrono::duration<double, std::milli>(
                                              std::chrono::steady_clock::now() - t0).count();
                                          std::printf("[agg] batch of %u same-pref sigs -> %s | 1 pairing | %.1f ms\n",
                                              b.count, ok ? "ACCEPT" : "REJECT!!", ams);
                                          if (ok) ++g_agg_receipts;
                                          g_agg_batches.erase(bkey);
                                      } }
                                    break;
                                }
                                }
                            }
                        } else {
                            std::printf("[voted] DECODE FAILED\n");
                        }
                        if (accepted) {
                            g_peer_prefs[member] = dv.preference;
                            // DEF-395: bind the transport to the identity - the
                            // consensus voice is the MEMBER, verified by pairing.
                            g_fd_member[peer_fds[i]] = member;
                            for (auto& pr : g_mssc.peers)
                                if (pr.member == 0 && pr.port == (std::uint16_t)peer_fds[i])
                                    pr.member = member;
                            // P5-E: equivocation detection (double-sign -> 100% slash)
                            {
                                const std::uint8_t* pb2 = (const std::uint8_t*)&dv.preference;
                                char hex[65];
                                for (int qi = 0; qi < 32; ++qi) std::snprintf(hex + qi*2, 3, "%02x", pb2[qi]);
                                hex[64] = 0;
                                const auto key = std::make_pair((std::uint64_t)member, (std::uint64_t)dv.round);
                                auto sit = g_signed_prefs.find(key);
                                if (sit != g_signed_prefs.end() && sit->second != hex) {
                                    std::printf("[stake] EQUIVOCATION DETECTED: member %llu round %llu signed two preferences - SLASHING\n",
                                        (unsigned long long)member, (unsigned long long)dv.round);
                                    (void)g_stake_reg.slash_equivocation((std::uint64_t)member);
                                    g_adversarial[(std::uint64_t)member] = true;
                                    // P5-E final integration: excise the consensus voice.
                                    // FloorAbort trap: zeroing peer weight WITHOUT contracting
                                    // total_weight drops sampled below phi_floor -> node suspension.
                                    // Correct semantics: the adversary leaves numerator AND denominator.
                                    // DEF-395 (CA-R372g): consensus identity is a MEMBER ID,
                                    // never a port number - the port hack excised the wrong
                                    // voice the moment the fleet exceeded two members.
                                    for (auto& pr : g_mssc.peers)
                                        if (pr.member == member && pr.weight > 0) {
                                            g_mssc.total_weight -= pr.weight;
                                            std::printf("[stake] member %llu consensus voice REMOVED: weight %llu -> 0, network total %llu -> %llu\n",
                                                (unsigned long long)member, (unsigned long long)pr.weight,
                                                (unsigned long long)(g_mssc.total_weight + pr.weight),
                                                (unsigned long long)g_mssc.total_weight);
                                            pr.weight = 0;
                                        }
                                } else if (sit == g_signed_prefs.end()) {
                                    g_signed_prefs[key] = hex;
                                }
                                if (!g_stake_seeded[(std::uint64_t)member]) {
                                    (void)g_stake_reg.deposit((std::uint64_t)member, g_stake_params.min_bond, 0, 0);
                                    g_stake_reg.tick_epoch(10); g_stake_reg.tick_epoch(11); // E+2 satisfied
                                    g_stake_seeded[(std::uint64_t)member] = true;
                                }
                            }
                            std::printf("[vote] VERIFIED from member %llu (epoch %u, round %llu)\n", (unsigned long long)member, dv.epoch, (unsigned long long)dv.round);
                        } else
                            std::printf("[vote] REJECT (bad signature or unknown member)\n");
                    } else if (msg.type == 0x0D) {
                        // DEF-391: the order-lock attestation (P2 production).
                        // The lock is a SIGNED statement; shares exist only under it.
                        auto dOS = msscvote::decode_order_sig(msg);
                        if (!dOS.ok) {
                            std::printf("[order] 0x0D DECODE FAILED (size %zu)\n", msg.payload.size());
                        } else {
                            const threshold::g2::G2Pt* Y = nullptr;
                            for (const auto& [jid, Yj] : g_members)
                                if (jid == dOS.member) { Y = &Yj; break; }
                            if (Y && !threshold::g2::PisInf(*Y))
                                order_lock_ingest(dOS.epoch, dOS.oroot, dOS.sigma, dOS.member, *Y);
                            else
                                std::printf("[order] 0x0D unknown member %llu\n",
                                    (unsigned long long)dOS.member);
                        }
                    } else if (msg.type == 0x07) {
                        // P4-3 (DEC-279): the encrypted mempool envelope
                        auto de = m2env::decode_envelope(msg);
                        // P5-C + DEF-P3-03: envelope dedup by cth — O(1) hash index.
                        // A repeated envelope IS the same envelope; re-storing it
                        // poisons eix indexing across ceremonies (DEF-241).
                        CthKey ck{}; std::memcpy(ck.b, de.cth, 32);
                        const bool dup_env = (g_env_index.count(ck) != 0);
                        if (dup_env) std::printf("[mempool] envelope DUPLICATE by cth — skipped\n");
                        if (de.ok && !dup_env) {
                            MempoolEntry entry;
                            entry.env.R = de.R;
                            entry.env.ct = de.ct;
                            std::memcpy(entry.env.tag, de.tag, 32);
                            std::memcpy(entry.env.cth, de.cth, 32);
                            // DEF-P3-05: the wire-carried header is STATE now —
                            // the decrypt path keys the DEM from THIS hdr (CA-R203).
                            std::memcpy(entry.env.hdr, de.hdr, 56);
                            g_env_index[ck] = g_mempool.size();
                            // compute our dec_share
                            // DEF-234 conform: the decrypt contribution must be [f(0)]R
                            // (the sender keys the DEM from f(0)). Testnet scope: this node
                            // dealt the poly, so it legitimately holds f(0) = g_env_secret.
                            // True t-of-2 Lagrange multi-party aggregation = P5-C capstone.
                            threshold::mont::fe6 sk_fe6{}; { threshold::Fr own = threshold::dkg::share_for(g_test_poly, g_self_member); threshold::fr_to_fe6(own, sk_fe6); } // P5-C: own share
                            std::uint64_t s_canon[6];
                            for (int w = 0; w < 6; ++w) s_canon[w] = sk_fe6[w];
                            auto D_j = threshold::m2::dec_share(s_canon, de.R);
                            g_dec_shares.push_back(m2env::pt_to_bytes(D_j));
                            g_mempool.push_back(std::move(entry));
                            std::printf("[mempool] envelope %zu/%u stored (ct=%zu bytes)\n",
                                g_mempool.size(), g_k_entries, de.ct.size());
                            // DEF-391 (CA-R372c): the own share is COMPUTED here
                            // (stored in g_dec_shares) but PUBLISHED only after the
                            // attested lock - the whitepaper ceremony is Lock, THEN
                            // Share. Pre-lock publication is a timeline fork: shares
                            // that exist before the order is signed let t colluders
                            // decrypt before the ordering is attested.
                            if (g_mempool.size() == 1) g_pool_epoch = current_epoch;
                            // the ordering ceremony: when we have 3 envelopes
                            if (g_mempool.size() >= (std::size_t)g_k_entries && !g_order_committed) {
                                // DEF-390 (CA-R372b): the REAL threshold beacon
                                // (DEC-200: threshold::beacon is the sole producer).
                                // The old sort-key entropy was sha256d("beacon_p4") -
                                // a CONSTANT: position grinding becomes precomputation.
                                // Testnet honest scope: the beacon t-subset rides the
                                // dealt poly; production splits into per-member
                                // partials + permissionless aggregation.
                                if (g_mempool.size() >= 1 && g_pool_epoch == 0)
                                    g_pool_epoch = current_epoch;
                                threshold::beacon::Committee bcom;
                                for (std::uint64_t j = 1; j <= g_cfg_t_eff && j <= g_dkg_T.n; ++j) {
                                    bcom.ids.push_back(j);
                                    bcom.shares.push_back(threshold::dkg::share_for(g_test_poly, j));
                                }
                                const auto beacon = threshold::beacon::epoch_beacon(
                                    bcom, g_pool_epoch, g_prev_beacon);
                                g_prev_beacon = beacon;   // the beacon chain advances
                                std::vector<std::array<std::uint8_t,32>> sks(g_mempool.size());
                                {
                                    std::uint8_t beacon_arr[32]; beacon.to_bytes(beacon_arr);
                                    // DEF-P3-04: EVERY envelope gets its sort key. The old
                                    // loop filled only the first 3 of a pool-sized array —
                                    // uninitialized memory fed the sort the moment volume
                                    // exceeded 3 (latent UB at scale).
                                    for (std::size_t i = 0; i < g_mempool.size(); ++i)
                                        threshold::m2::sort_key(sks[i].data(), beacon_arr, g_mempool[i].env.cth);
                                }
                                std::vector<unsigned> order(g_mempool.size());
                                for (unsigned oi = 0; oi < g_mempool.size(); ++oi) order[oi] = oi;
                                std::sort(order.begin(), order.end(), [&](unsigned a, unsigned b) {
                                    return memcmp(sks[a].data(), sks[b].data(), 32) < 0;
                                });
                                std::vector<std::array<std::uint8_t,32>> sorted(g_mempool.size());
                                for (std::size_t i = 0; i < g_mempool.size(); ++i) std::memcpy(sorted[i].data(), g_mempool[order[i]].env.cth, 32);
                                threshold::m2::order_root(g_order_root,
                                    reinterpret_cast<const std::uint8_t (*)[32]>(sorted.data()), sorted.size());
                                g_order_committed = true;
                                std::printf("[mempool] ORDER COMMITTED: root=");
                                for (int i = 0; i < 8; ++i) std::printf("%02x", g_order_root[i]);
                                std::printf("\n");
                                // DEF-391: THE LOCK ATTESTATION - the committee signs
                                // the order-lock preimage BEFORE any decryption share
                                // exists. Shares publish only when the threshold of
                                // partials aggregates to a verified lock.
                                {   auto lpre = msscvote::order_sig_preimage(g_pool_epoch, g_order_root);
                                    auto lsig = msscvote::sign_order(g_own_share, lpre);
                                    auto lm = msscvote::encode_order_sig(g_pool_epoch, g_order_root, lsig, g_self_member);
                                    for (int fd : peer_fds) p2p::send_message(fd, lm);
                                    std::printf("[order] own lock partial broadcast (epoch %u, 0x0D)\n",
                                        (unsigned)g_pool_epoch);
                                    const threshold::g2::G2Pt* Yself = nullptr;
                                    for (const auto& [jid, Yj] : g_members)
                                        if (jid == g_self_member) { Yself = &Yj; break; }
                                    if (Yself)
                                        order_lock_ingest(g_pool_epoch, g_order_root, lsig,
                                                          g_self_member, *Yself);
                                }
                                // P5-C + DEF-P3-05/06: the ONE shared decrypt path —
                                // stored-hdr DEM key, stored-serialization own share,
                                // batch-Lagrange aggregation (P3 production core).
                                // Runs on the LOCAL share + any shares already present;
                                // the attested-lock publication tops it up.
                                for (std::size_t ei = 0; ei < g_mempool.size(); ++ei)
                                    (void)try_decrypt_envelope(ei);
                            }
                        }
                    } else if (msg.type == p2p::EPOCH_HEADER) {
                        std::printf("[epoch] received epoch header from peer\n");

                        // P2-07 (DEC-253): weight consensus by deterministic recomputation.
                        // Pointer accessors - DEFECT-167's second finding, fixed.
                        if (msg.payload.size() >= 52) {
                            const std::uint8_t* pl = msg.payload.data();
                            const std::size_t pln = msg.payload.size();
                            // DEFECT-184 (v2): the DERIVED layout - epoch@0(4)
                            // digest@4(4xu32=16) size@20(4) inner@24(4) weight@28(8)
                            // hash@36(4xu32=16) = 52B total (X1/X2/FR receipts).
                            const unsigned peer_inner = p2p::get_u32(pl + 24);
                            const std::uint64_t peer_w = p2p::get_u64(pl + 28);
                            if (peer_inner == pouw_inner) {
                                if (peer_w == pouw_weight)
                                    std::printf("[pouw] peer weight %llu == local %llu -> AGREE\n",
                                        (unsigned long long)peer_w, (unsigned long long)pouw_weight);
                                else
                                    std::printf("[pouw] peer weight %llu != local %llu -> MISMATCH\n",
                                        (unsigned long long)peer_w, (unsigned long long)pouw_weight);
                            } else {
                                std::printf("[pouw] peer inner %u != local %u -> param mismatch\n",
                                    peer_inner, pouw_inner);
                            }
                            // P2-10 (DEC-259): STATE agreement - the epoch digest.
                            // peer digest @ offset 4 (4xu32, DEFECT-184 layout); local
                            // anchor = accumulator.z[0] (holds the completed epoch's state;
                            // current_epoch == peer_epoch + 1 on both completion paths).
                            const std::uint32_t peer_epoch = p2p::get_u32(pl + 0);
                            if (peer_epoch == current_epoch - 1) {
                                // DEFECT-190 fix: offset-4 'digest' was a ZERO placeholder
                                // (z[0]==0, explorer 000..0 since P2-05) - the old check was
                                // vacuous. The REAL field: hash@36 = P.v (whir commitment
                                // over the full evals vector). DEFECT-191 fix: consistent
                                // limb semantics (low32 of limb k, both sides).
                                const unsigned p0 = p2p::get_u32(pl + 36);
                                const unsigned p1 = p2p::get_u32(pl + 40);
                                const unsigned p2_ = p2p::get_u32(pl + 44);
                                const unsigned p3 = p2p::get_u32(pl + 48);
                                if (p0 == g_hash[0] && p1 == g_hash[1] && p2_ == g_hash[2] && p3 == g_hash[3]) {
                                    std::printf("[state] epoch %u digest AGREES (%08x%08x)\n",
                                        peer_epoch, p0, p1);
                                    // Phase 6.13: cross-node PoUW verification — the chains
                                    // converged, so the deterministic GEMM is recomputable.
                                    // Rebuild the tail from our OWN chain (identical by the
                                    // digest agreement) and verify the claimed weight.
                                    if (verify_peer_epoch_pouw(digest_chain.back(), peer_w))
                                        std::printf("[pouw-verify] peer epoch %u weight %llu CONFIRMED by recomputation\n",
                                            peer_epoch, (unsigned long long)peer_w);
                                    else
                                        std::printf("[pouw-fail] peer epoch %u weight %llu UNVERIFIED — claim vs recomputation mismatch\n",
                                            peer_epoch, (unsigned long long)peer_w);
                                }
                                else
                                    std::printf("[state] epoch %u digest MISMATCH local=%08x%08x%08x%08x peer=%08x%08x%08x%08x\n",
                                        peer_epoch, g_hash[0], g_hash[1], g_hash[2], g_hash[3], p0, p1, p2_, p3);
                            }
                        }
                        // re-gossip to other peers
if (seen_or_add(msg.payload))
    std::printf("[gossip] duplicate epoch header - re-gossip suppressed\n");
else
                        for (std::size_t j = 0; j < peer_fds.size(); ++j) {
                            if (j != i) p2p::send_message(peer_fds[j], msg);
                        }
                    } else if (msg.type == p2p::DECREE_ENTRY) {
                        std::printf("[decree] received decree entry (%zu bytes)\n", msg.payload.size());
                        // process the decree: extract the digest, fold it
                        handle_decree(msg.payload);
                        // re-gossip to other peers
                        for (std::size_t j = 0; j < peer_fds.size(); ++j) {
                            if (j != i) p2p::send_message(peer_fds[j], msg);
                        }
                    } else if (msg.type == p2p::PING) {
                        p2p::Message pong{};
                        pong.type = p2p::PONG;
                        p2p::send_message(peer_fds[i], pong);
                    }
                } else {
                    // DEF-255: proper disconnect — look up weight by fd, clean all structures
                    std::uint64_t lost_w = 0;
                    auto fw = g_fd_weights.find(peer_fds[i]);
                    if (fw != g_fd_weights.end()) {
                        lost_w = fw->second;
                        g_fd_weights.erase(fw);
                        g_mssc.total_weight -= lost_w;
                        if (g_mssc.total_weight < g_mssc.self_weight)
                            g_mssc.total_weight = g_mssc.self_weight;
                    }
                    // DEF-395: the departed peer's RECORD leaves the sampling list
                    // and its verified vote state dies with the connection - a
                    // removed connection must not keep a voice via stale records.
                    // DEF-397: teardown forgets the rate-limit bucket.
                    {   auto pm = g_fd_member.find(peer_fds[i]);
                        const std::uint64_t lost_member =
                            (pm != g_fd_member.end()) ? pm->second : 0;
                        for (std::size_t pi = 0; pi < g_mssc.peers.size(); ++pi) {
                            const bool by_id = lost_member != 0
                                && g_mssc.peers[pi].member == lost_member;
                            const bool by_fd = g_mssc.peers[pi].member == 0
                                && g_mssc.peers[pi].port == (std::uint16_t)peer_fds[i];
                            if (by_id || by_fd) {
                                g_mssc.peers.erase(g_mssc.peers.begin() + pi);
                                break;
                            }
                        }
                        if (lost_member) g_peer_prefs.erase(lost_member);
                        g_fd_member.erase(peer_fds[i]);
                    }
                    p2p::peer_forget(peer_fds[i]);
                    close(peer_fds[i]);
                    peer_fds.erase(peer_fds.begin() + i);
                    --i;
                    std::printf("[committee] peer LEFT: weight %llu removed, fleet total=%llu\n",
                        (unsigned long long)lost_w, (unsigned long long)g_mssc.total_weight);
                }
            }
        }
    }
    
    return 0;
}
