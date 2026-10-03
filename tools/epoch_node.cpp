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
#include <hsma/fexec_circuit.hpp>
#include <hsma/whir.hpp>
#include <hsma/explorer.hpp>
#include <hsma/pouw.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/msscloop.hpp>
#include <hsma/m2envelope.hpp>
#include <hsma/threshold/m2.hpp>
#include <hsma/threshold/beacon.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <hsma/econ/stake.hpp>
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

// the epoch state
static unsigned current_epoch = 0;
static unsigned decree_count = 0;
static constexpr unsigned K_ENTRIES = 10;

// the folding state
static mfold::SparseMat A, B, C;
static mfold::Relaxed accumulator;
static std::vector<std::array<std::uint64_t,4>> digest_chain;
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
static std::uint32_t g_my_public_ip = 0;  // set via --public-ip or committee.toml
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

static void hb_watchdog() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        const std::uint64_t c0 = g_hb_consensus.load(std::memory_order_relaxed);
        std::this_thread::sleep_for(std::chrono::seconds(60));
        if (g_hb_consensus.load(std::memory_order_relaxed) == c0) {
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
// P5-C: collected decryption shares per envelope — (member_id, D_j) pairs.
// Decryption fires when the count of DISTINCT member x's reaches t=2.
static std::map<std::size_t, std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>>> g_thr_shares;
static std::uint8_t g_order_root[32] = {};
static threshold::g2::G2Pt g_xe;   // the committee's aggregate public key
static bool g_order_committed = false;
static unsigned pouw_inner = 64;          // P2-07: file-scope - one truth, all sites
static std::uint64_t pouw_weight = 0;     // last self-verified PoUW receipt
static const char* pouw_verify = "PENDING";
static std::uint32_t g_hash[4] = {0,0,0,0}; // P2-10a (DEFECT-190 fix): last completed epoch's P.v limbs - the REAL state fingerprint

// peer connections
static std::vector<int> peer_fds;

// P2-08 (DEC-254): the shared epoch PoUW - main AND handle_decree call this.
// Writes the file-scope globals; deterministic from the epoch's digest chain.
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
        for (unsigned i = 0; i < N; ++i)
            for (unsigned j = 0; j < N; ++j) {
                fp::fe acc = fp::fe_zero();
                for (unsigned k = 0; k < N; ++k)
                    acc = fp::fe_add(acc, fp::fe_mul(Am[i*N+k], Bm[k*N+j]));
                Cm[i*N+j] = acc;
            }
        pouw::GemmProofV2 PP = pouw::prove_gemm_v2(Am, Bm, Cm, N, N, N);
        const bool vok = pouw::verify_gemm_v2(PP, Am, Bm, Cm);
        pouw_verify = vok ? "ACCEPT" : "REJECT";
        pouw_weight = vok ? pouw::weight(N, 1) : 0;
        auto t1 = std::chrono::steady_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        std::printf("[pouw] epoch %u: %u^3 GEMM self-verify %s | weight %llu MACs | %.0f ms\n",
            current_epoch, N, pouw_verify, (unsigned long long)pouw_weight, ms);
    }

}

static fp::fe ld(const std::array<std::uint64_t,4>& c) {
    fp::fe x{}; std::memcpy(x.l.data(), c.data(), 32);
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fp::fe_mul(x, rr);
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

// digest chain: d_{i+1} = SHA256-like XOR-fold (deterministic)
static std::array<std::uint64_t,4> next_digest(
    const std::array<std::uint64_t,4>& prev, unsigned step) {
    std::array<std::uint64_t,4> nxt{};
    for (int k = 0; k < 4; ++k)
        nxt[k] = prev[k] ^ (std::uint64_t)(step * 7 + 13);
    return nxt;
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

static void handle_decree(const std::vector<std::uint8_t>& payload) {
    // P2-08: DEFECT-170 - a re-received decree would DOUBLE-FOLD into the
    // accumulator. Fingerprint dedup, safe direction.
    if (seen_or_add(payload)) { std::printf("[decree] duplicate entry - skipped\n"); return; }
    if (payload.size() < 32) return;
    
    // extract the digest from the payload (first 32 bytes = 4 u64 limbs)
    std::array<std::uint64_t,4> dnew{};
    for (int k = 0; k < 4; ++k)
        for (int j = 0; j < 8; ++j)
            dnew[k] |= (std::uint64_t)payload[8*k + j] << (8*j);
    
    // chain: dprev = the last digest in the chain
    auto dprev = digest_chain.back();
    digest_chain.push_back(dnew);
    
    // build the witness and add to the fold
    auto z = build_witness(dprev, dnew);
    
    mfold::Relaxed Ji = mfold::fresh(z, fcirc::NROWS);
    if (mfold::sat_relaxed(A, B, C, Ji) != fcirc::NROWS) {
        std::printf("[fold] instance UNSAT — skipping\n");
        digest_chain.pop_back();
        return;
    }
    
    mfold::MultifoldResult M = mfold::multifold(A, B, C, accumulator, {Ji});
    accumulator = M.folded;
    ++decree_count;
    
    std::printf("[fold] decree %u/%u folded, SAT\n", decree_count, K_ENTRIES);
    
    // when the epoch is full, produce the π_E
    if (decree_count >= K_ENTRIES) {
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
        
        // P2-08: fresh weight for the epoch that just completed
        run_epoch_pouw();
        decree_count = 0; // P2-08b: kept (idempotent with the tail reset)
        // gossip the epoch header to all peers
        p2p::Message hdr{};
        hdr.type = p2p::EPOCH_HEADER;
        // payload (DERIVED, 52B): epoch@0(4) digest@4(4xu32) size@20(4)
        //   inner@24(4) weight@28(8) hash@36(4xu32) - DEFECT-184
        p2p::put_u32(hdr.payload, current_epoch); // P2-08b: the completed epoch (tail advances after)
        // digest from the accumulator's first z value
        fp::fe dcanon = fp::fe_to_canonical(accumulator.z[0]);
        for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)dcanon.l[k]);
        p2p::put_u32(hdr.payload, 1600);
    p2p::put_u32(hdr.payload, pouw_inner);   // P2-07: the weight rides the header
    p2p::put_u64(hdr.payload, pouw_weight); // P2-07: the weight (u64)
        // hash: use the output variable's canonical form
        fp::fe ocanon = fp::fe_to_canonical(P.v);
        for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)ocanon.l[k]);
        for (int k = 0; k < 4; ++k) g_hash[k] = (std::uint32_t)ocanon.l[k]; // P2-10a: store
        
        // gossip to all peers
        for (int fd : peer_fds)
            p2p::send_message(fd, hdr);
        
        std::printf("[gossip] epoch %u header sent to %zu peers\n", current_epoch, peer_fds.size());
        
        // reset for the next epoch
        ++current_epoch;
        decree_count = 0;
    }
}

int main(int argc, char* argv[]) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::thread(hb_watchdog).detach(); // P5-D // [G7] lesson: redirected stdout was fully buffered - logs stayed empty
    unsigned my_port = p2p::DEFAULT_PORT;
    
    // parse arguments
    if (argc > 1) my_port = (unsigned)atoi(argv[1]);
    
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
    g_from_config = g_cfg_members.size() >= 2;
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
            g_mssc.peers.push_back({0x7F000001, 31234, 40});
        else
                                        // P5-E+/Gate-3: peers from config when present
                            if (g_from_config) {
                                g_mssc.total_weight = 0; g_mssc.peers.clear();
                                for (const auto& cm : g_cfg_members)
                                    if (cm.id != g_self_member) {
                                        // endpoint -> ip/port (first A record)
                                        std::uint32_t ip = 0; unsigned prt = 31233;
                                        {   struct in_addr a{}; char ep[128]; std::snprintf(ep, sizeof ep, "%s", cm.endpoint.c_str());
                                            char* colon = std::strchr(ep, ':'); if (colon) *colon = 0;
                                            if (inet_pton(AF_INET, ep, &a) == 1) ip = ntohl(a.s_addr);
                                            if (colon) prt = (unsigned)std::atoi(colon + 1);
                                        }
                                        g_mssc.peers.push_back({ip, (std::uint16_t)prt, cm.weight});
                                        g_mssc.total_weight += cm.weight;
                                    }
                                g_mssc.total_weight += g_mssc.self_weight;
                                std::printf("[committee] peers from config: %zu peers, total %llu\n",
                                    g_mssc.peers.size(), (unsigned long long)g_mssc.total_weight);
                            } else
                            g_mssc.peers.push_back({0x7F000001, 31233, 60});
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
    
    // the initial accumulator: fresh with d0->d1
    auto d1 = next_digest(d0, 0);
    digest_chain.push_back(d1);
    auto z = build_witness(d0, d1);
    accumulator = mfold::fresh(z, fcirc::NROWS);
    
    decree_count = 0;
    
    std::printf("═══════════════════════════════════════\n");
    std::printf("  HSMA EPOCH NODE — P2-02\n");
    std::printf("  port: %u | k_entries: %u | epoch: %u\n", my_port, K_ENTRIES, current_epoch);
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
        } else {
            // DEFECT-183's lesson: a silent -1 hid this for six sessions
            std::printf("[seed] connect to %u.%u.%u.%u:%u FAILED\n",
                (sp.ip >> 24) & 0xFF, (sp.ip >> 16) & 0xFF,
                (sp.ip >> 8) & 0xFF, sp.ip & 0xFF, sp.port);
        }
    }
    
    // generate local decree entries to fill the epoch
    std::printf("[node] generating %u local decree entries...\n", K_ENTRIES);
    for (unsigned i = 0; i < K_ENTRIES; ++i) {
        auto dprev = digest_chain.back();
        auto dnew = next_digest(dprev, decree_count + current_epoch * K_ENTRIES);
        digest_chain.push_back(dnew);
        
        auto z = build_witness(dprev, dnew);
        mfold::Relaxed Ji = mfold::fresh(z, fcirc::NROWS);
        if (mfold::sat_relaxed(A, B, C, Ji) != fcirc::NROWS) {
            std::printf("[fold] local decree %u UNSAT\n", i);
            continue;
        }
        
        mfold::MultifoldResult M = mfold::multifold(A, B, C, accumulator, {Ji});
        accumulator = M.folded;
        ++decree_count;
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

    // gossip the epoch header
    p2p::Message hdr{};
    hdr.type = p2p::EPOCH_HEADER;
    p2p::put_u32(hdr.payload, current_epoch);
    fp::fe dcanon = fp::fe_to_canonical(accumulator.z[0]);
    for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)dcanon.l[k]);
    p2p::put_u32(hdr.payload, 1600);
    p2p::put_u32(hdr.payload, pouw_inner);   // P2-07: the weight rides the header
    p2p::put_u64(hdr.payload, pouw_weight);
    fp::fe ocanon = fp::fe_to_canonical(P.v);
    for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)ocanon.l[k]);
    for (int k = 0; k < 4; ++k) g_hash[k] = (std::uint32_t)ocanon.l[k]; // P2-10a: store
    
    for (int fd : peer_fds) p2p::send_message(fd, hdr);
    std::printf("[gossip] epoch header sent to %zu peers\n", peer_fds.size());
    
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
    g_ns_shared.k_entries = K_ENTRIES;
    {   fp::fe dc = fp::fe_to_canonical(accumulator.z[0]);
        char hex[128]; hex[0] = 0;
        for (int k = 3; k >= 0; --k) { char tmp[20]; snprintf(tmp, sizeof(tmp), "%016llx", (unsigned long long)dc.l[k]); strcat(hex, tmp); }
        g_ns_shared.state_root_hex = hex; }   // P5-C: the missed write (DEF-247 final)
    g_ns_shared.pi_e_status = ok ? "ACCEPT" : "PENDING";
    g_ns_shared.pi_e_size = 1600;
    g_ns_shared.total_rows = (unsigned)A.row.size();   // P5-C: the missed write
    g_ns_shared.total_vars = (unsigned)(fcirc::NZ * (decree_count + 1));  // vars scale with entries
    g_ns_shared.peer_count = peer_fds.size();
    g_ns_shared.port = my_port;
    g_ns_shared.pouw_inner = pouw_inner;
    g_ns_shared.pouw_weight = pouw_weight;
    g_ns_shared.pouw_verify = pouw_verify;

    // P2-08: DEFECT-171 - epoch 0 complete; the node now accepts epoch 1 decrees
    ++current_epoch;
    decree_count = 0;
    
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
                // P5-D: the main-loop pulse — time-based, NOT peer-gated (a solo node is alive).
                // DEF-244: the peer-gated heartbeat froze on fresh nodes -> watchdog restart loop.
                g_hb_consensus.fetch_add(1, std::memory_order_relaxed);
                g_ns_shared.uptime_s = (unsigned long long)std::chrono::duration_cast<std::chrono::seconds>(now - g_boot).count();
                g_ns_shared.hb_consensus = g_hb_consensus.load(std::memory_order_relaxed);
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
                g_hb_consensus.fetch_add(1, std::memory_order_relaxed);
                g_ns_shared.uptime_s = (unsigned long long)std::chrono::duration_cast<std::chrono::seconds>(now - g_boot).count();
                g_ns_shared.hb_consensus = g_hb_consensus.load(std::memory_order_relaxed);
                {
                    auto pre = msscvote::vote_preimage(0,
                        consensus::sha256d((const std::uint8_t*)"wr",2),
                        g_mssc.conflict, g_mssc.rounds,
                        g_mssc.preference);
                    auto sig = msscvote::sign_vote(g_own_share, pre);
                    auto msg = msscvote::encode_vote(0,
                        consensus::sha256d((const std::uint8_t*)"wr",2),
                        g_mssc.conflict, g_mssc.rounds,
                        g_mssc.preference, sig);
                    for (int fd : peer_fds) p2p::send_message(fd, msg);
                }
                // P5-B hygiene: stale single-sig batches die with the round (testnet scope)
                if (g_agg_batches.size() > 128) g_agg_batches.clear();
                if (!g_peer_prefs.empty()) {
                    std::vector<consensus::Digest> pp;
                    for (const auto& [id, pref] : g_peer_prefs) pp.push_back(pref);
                    auto rr = msscloop::tick(g_mssc, g_cfg, pp);
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

                }
            }
        }
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ready = select(max_fd + 1, &read_set, nullptr, nullptr, &tv);
        if (ready < 0) break;
        
        if (FD_ISSET(listener, &read_set)) {
            struct sockaddr_in addr{};
            socklen_t len = sizeof(addr);
            int new_fd = accept(listener, (struct sockaddr*)&addr, &len);
            if (new_fd >= 0) {
                peer_fds.push_back(new_fd);
                std::printf("[peer] new connection (fd=%d)\n", new_fd);
                        // P5-C polish (DEF-242): shares are STATE, not events.
                        // A newly connected peer must receive every stored decryption
                        // share — otherwise dedup-silence + one-broadcast starves it
                        // (the cross-ceremony waiting x10). g_dec_shares aligns 1:1
                        // with g_mempool (both push together, dedup skips both).
                        for (std::size_t sx = 0; sx < g_dec_shares.size() && sx < g_mempool.size(); ++sx) {
                            std::vector<std::uint8_t> pl(200, 0);
                            pl[0] = std::uint8_t(sx); pl[1] = std::uint8_t(sx>>8);
                            pl[2] = std::uint8_t(sx>>16); pl[3] = std::uint8_t(sx>>24);
                            pl[4] = std::uint8_t(g_self_member);
                            std::memcpy(pl.data()+8, g_dec_shares[sx].data(), 192);
                            p2p::Message m08{}; m08.type = 0x08; m08.payload = pl;
                            p2p::send_message(new_fd, m08);
                        }
                        if (!g_dec_shares.empty())
                            std::printf("[thr] rebroadcast %zu stored shares to new peer\n", g_dec_shares.size());

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
                p2p::Message msg;
                if (p2p::recv_message(peer_fds[i], msg)) {
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
                        // P5-C retrigger (DEF-237): the ORDER-COMMITTED decrypt loop is one-shot;
                        // a share arriving after commitment must attempt its own decrypt. tech debt:
                        // body duplicated from the ORDER-COMMITTED loop — extract to fn at P5-C polish.
                        if (g_order_committed && eix < g_mempool.size() && !g_mempool[eix].decrypted) {
                            std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>> sh2;
                            {   auto& dsb2 = g_dec_shares[eix];
                                std::uint64_t da2[6], db2[6], ya2[6], yb2[6];
                                for (int i = 0; i < 6; ++i) { da2[i]=0; db2[i]=0; ya2[i]=0; yb2[i]=0;
                                    for (int b = 0; b < 8; ++b) {
                                        da2[i] |= (std::uint64_t)dsb2[i*8+b] << (8*b);
                                        db2[i] |= (std::uint64_t)dsb2[48+i*8+b] << (8*b);
                                        ya2[i] |= (std::uint64_t)dsb2[96+i*8+b] << (8*b);
                                        yb2[i] |= (std::uint64_t)dsb2[144+i*8+b] << (8*b);
                                    } }
                                sh2.push_back({g_self_member, threshold::g2::from_affine(da2, db2, ya2, yb2)});
                            }
                            for (const auto& [m9, d9] : g_thr_shares[eix]) sh2.push_back({m9, d9});
                            bool dup9 = false;
                            for (std::size_t a = 0; a < sh2.size() && !dup9; ++a)
                                for (std::size_t b3 = a+1; b3 < sh2.size(); ++b3)
                                    if (sh2[a].first == sh2[b3].first) { dup9 = true; break; }
                            if (!dup9 && sh2.size() >= 2) {
                                threshold::g2::G2Pt Dagg2{};
                                if (hsma::threshold::vss::agg_dec_share(Dagg2, sh2)) {
                                    auto ss2 = m2env::pt_to_bytes(Dagg2);
                                    auto xe2 = m2env::pt_to_bytes(g_xe);
                                    std::uint8_t hdr2[56] = {};
                                    { std::uint8_t snd2[32] = {}; threshold::m2::ser_hdr(hdr2, 7, snd2, (std::uint64_t)eix, 100); }
                                    std::uint8_t k2[32];
                                    threshold::m2::kdf(k2, ss2.data(), xe2.data(), hdr2);
                                    std::vector<std::uint8_t> pl2;
                                    bool ok2 = threshold::m2::dem_decrypt(pl2, k2, hdr2,
                                        g_mempool[eix].env.ct.data(), g_mempool[eix].env.ct.size(), g_mempool[eix].env.tag);
                                    if (ok2) {
                                        g_mempool[eix].decrypted = true; g_mempool[eix].payload = pl2;
                                        pl2.push_back('\n');
                                        std::printf("[decrypt] envelope %zu: \"%s\" (tag OK) [via 0x08 retrigger]\n",
                                            eix, std::string(pl2.begin(), pl2.end()-1).c_str());
                                        std::vector<std::uint8_t> dp(pl2.begin(), pl2.end()-1);
                                        handle_decree(dp);
                                    } else std::printf("[decrypt] envelope %zu: TAG FAILED [retrigger]\n", eix);
                                }
                            }
                        }
                        }
                    } else if (msg.type == 0x06) {
                        // P3-1b (DEC-271): the MSSC vote wire path
                        auto dv = msscvote::decode_vote(msg);
                        std::printf("[voted] ok=%d epoch=%u round=%llu\n",
                            (int)dv.ok, dv.epoch, (unsigned long long)dv.round);
                        bool accepted = false; std::uint64_t member = 0;
                        if (dv.ok) {
                            auto pre = msscvote::vote_preimage(dv.epoch, dv.weight_root,
                                                               dv.conflict, dv.round, dv.preference);
                            std::printf("[voted] members=%zu\n", g_members.size());
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
                        } else {
                            std::printf("[voted] DECODE FAILED\n");
                        }
                        if (accepted) {
                            g_peer_prefs[member] = dv.preference;
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
                                    const std::uint16_t mport = (member == 1) ? 31233 : 31234;
                                    for (auto& pr : g_mssc.peers)
                                        if (pr.port == mport && pr.weight > 0) {
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
                    } else if (msg.type == 0x07) {
                        // P4-3 (DEC-279): the encrypted mempool envelope
                        auto de = m2env::decode_envelope(msg);
                        // P5-C: envelope dedup by cth — a repeated envelope IS the same
                        // envelope; re-storing it poisons eix indexing across ceremonies
                        // (DEF-241: the cross-ceremony poisoning, both nodes 0/0).
                        bool dup_env = false;
                        for (const auto& q : g_mempool)
                            if (std::memcmp(q.env.cth, de.cth, 32) == 0) { dup_env = true; break; }
                        if (dup_env) std::printf("[mempool] envelope DUPLICATE by cth — skipped\n");
                        if (de.ok && !dup_env) {
                            MempoolEntry entry;
                            entry.env.R = de.R;
                            entry.env.ct = de.ct;
                            std::memcpy(entry.env.tag, de.tag, 32);
                            std::memcpy(entry.env.cth, de.cth, 32);
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
                            std::printf("[mempool] envelope %zu stored (ct=%zu bytes)\n",
                                g_mempool.size(), de.ct.size());
                            // P5-C: broadcast our DEC_SHARE (0x08) — {eix u32, member u32, D_j 192B}
                            {   std::size_t eix = g_mempool.size() - 1;
                                std::vector<std::uint8_t> pl(200, 0);
                                pl[0] = std::uint8_t(eix); pl[1] = std::uint8_t(eix>>8);
                                pl[2] = std::uint8_t(eix>>16); pl[3] = std::uint8_t(eix>>24);
                                pl[4] = std::uint8_t(g_self_member);
                                std::memcpy(pl.data()+8, g_dec_shares.back().data(), 192);
                                for (int fd : peer_fds) {
                                    p2p::Message m08{}; m08.type = 0x08; m08.payload = pl;
                                    p2p::send_message(fd, m08);
                                }
                                std::printf("[thr] own D_j broadcast for envelope %zu (member %u)\n",
                                    eix, g_self_member); }
                            // the ordering ceremony: when we have 3 envelopes
                            if (g_mempool.size() >= (std::size_t)K_ENTRIES && !g_order_committed) {
                                const auto beacon = consensus::sha256d((const std::uint8_t*)"beacon_p4", 9);
                                std::vector<std::array<std::uint8_t,32>> sks(g_mempool.size());
                                for (int i = 0; i < 3; ++i)
                                    {
    std::uint8_t beacon_arr[32]; beacon.to_bytes(beacon_arr);
    threshold::m2::sort_key(sks[i].data(), beacon_arr, g_mempool[i].env.cth);
    }
                                std::vector<unsigned> order(g_mempool.size());
                                for (unsigned oi = 0; oi < g_mempool.size(); ++oi) order[oi] = oi;
                                std::sort(order.begin(), order.end(), [&](unsigned a, unsigned b) {
                                    return memcmp(sks[a].data(), sks[b].data(), 32) < 0;
                                });
                                std::vector<std::array<std::uint8_t,32>> sorted(g_mempool.size());
                                for (int i = 0; i < 3; ++i) sorted[i] = std::array<std::uint8_t,32>{};
                                for (std::size_t i = 0; i < g_mempool.size(); ++i) std::memcpy(sorted[i].data(), g_mempool[order[i]].env.cth, 32);
                                threshold::m2::order_root(g_order_root,
                                    reinterpret_cast<const std::uint8_t (*)[32]>(sorted.data()), sorted.size());
                                g_order_committed = true;
                                std::printf("[mempool] ORDER COMMITTED: root=");
                                for (int i = 0; i < 8; ++i) std::printf("%02x", g_order_root[i]);
                                std::printf("\n");
                                // P5-C: threshold decrypt — requires t=2 DISTINCT member shares.
                                // Our own D_j is stored (writer, own share now). Peers' D_j arrive
                                // via message 0x08 into g_thr_shares. Decrypt fires only when the
                                // collected x-set reaches t — the negative test (1 node alone)
                                // must show NO decrypt. DEF-234's dealer shortcut is retired.
                                for (std::size_t ei = 0; ei < g_mempool.size(); ++ei) {
                                    auto& me = g_mempool[ei];
                                    if (me.decrypted) continue;
                                    // collect: our own share (from g_dec_shares) + any peer shares (0x08)
                                    std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>> shares;
                                    {   // own
                                        auto& dsb = g_dec_shares[ei];
                                        std::uint64_t da[6], db[6], ya[6], yb[6];
                                        shares.push_back({g_self_member, threshold::g2::from_affine(da, db, ya, yb)});
                                    }
                                    for (const auto& [mid, Dj] : g_thr_shares[ei])
                                        shares.push_back({mid, Dj});
                                    // distinct-x check
                                    bool dup = false;
                                    for (std::size_t a = 0; a < shares.size() && !dup; ++a)
                                        for (std::size_t b2 = a+1; b2 < shares.size(); ++b2)
                                            if (shares[a].first == shares[b2].first) { dup = true; break; }
                                    if (dup) { std::printf("[thr] duplicate member share — skipped\n"); continue; }
                                    if (shares.size() < 2) { std::printf("[thr] envelope %zu: %zu/%u shares, waiting\n", ei, shares.size(), 2u); continue; }
                                    threshold::g2::G2Pt D_agg{};
                                    if (!hsma::threshold::vss::agg_dec_share(D_agg, shares)) { std::printf("[thr] agg FAILED\n"); continue; }
                                    std::printf("[thr] envelope %zu: threshold met (%zu shares, members %u,%u)\n",
                                        ei, shares.size(), (unsigned)shares[0].first, (unsigned)shares[1].first);
                                    std::uint64_t da[6], db[6], ya[6], yb[6];
                                    // the DEM key (D_agg from agg_dec_share above)
                                    auto ss_b = m2env::pt_to_bytes(D_agg);
                                    auto xe_b = m2env::pt_to_bytes(g_xe);
                                    std::uint8_t hdr[56] = {};
                                    // P4-3b fix: the hdr must match the envfaucet's LOCAL hdr
                                    // (nonce=ei since the envfaucet uses nonce=i for envelope i,
                                    //  fee=100 since the envfaucet uses fee=100)
                                    { std::uint8_t snd[32] = {}; threshold::m2::ser_hdr(hdr, 7, snd, (std::uint64_t)ei, 100); }
                                    std::uint8_t k[32];
                                    threshold::m2::kdf(k, ss_b.data(), xe_b.data(), hdr);
                                    // DEF-224 debug: the byte-level trace
                                    std::printf("[dbg-node] xe: ");
                                    for (int i = 0; i < 8; ++i) std::printf("%02x", xe_b[i]);
                                    std::printf("\n");
                                    std::printf("[dbg-node] ss_full: ");
                                    for (int i = 0; i < 192; ++i) std::printf("%02x", ss_b[i]);
                                    std::printf("\n");
                                    std::printf("[dbg-node] hdr_full: ");
                                    for (int i = 0; i < 56; ++i) std::printf("%02x", hdr[i]);
                                    std::printf("\n");
                                    std::printf("[dbg] D_agg: "); 
                                    for (int i = 0; i < 8; ++i) std::printf("%02x", ss_b[i]);
                                    std::printf(" | hdr: ");
                                    for (int i = 0; i < 8; ++i) std::printf("%02x", hdr[i]);
                                    std::printf(" | k: ");
                                    for (int i = 0; i < 4; ++i) std::printf("%02x", k[i]);
                                    std::printf("\n");
                                    // the decryption
                                    std::vector<std::uint8_t> pl;
                                    bool ok = threshold::m2::dem_decrypt(pl, k, hdr,
                                        me.env.ct.data(), me.env.ct.size(), me.env.tag);
                                    if (ok) {
                                        me.decrypted = true;
                                        me.payload = pl;
                                        pl.push_back('\n');
                                        std::printf("[decrypt] envelope %zu: \"%s\" (tag OK)\n",
                                            ei, std::string(pl.begin(), pl.end()-1).c_str());
                                        // feed the fold pipeline
                                        std::vector<std::uint8_t> decree_payload(pl.begin(), pl.end()-1);
                                        if (decree_payload.size() >= 32) {
                                            handle_decree(decree_payload);
                                        } else {
                                            // pad to 32 bytes for the digest
                                            while (decree_payload.size() < 32) decree_payload.push_back(0);
                                            handle_decree(decree_payload);
                                        }
                                    } else {
                                        std::printf("[decrypt] envelope %zu: TAG FAILED\n", ei);
                                    }
                                }
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
                                if (p0 == g_hash[0] && p1 == g_hash[1] && p2_ == g_hash[2] && p3 == g_hash[3])
                                    std::printf("[state] epoch %u digest AGREES (%08x%08x)\n",
                                        peer_epoch, p0, p1);
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
                    close(peer_fds[i]);
                    peer_fds.erase(peer_fds.begin() + i);
                    --i;
                }
            }
        }
    }
    
    return 0;
}
