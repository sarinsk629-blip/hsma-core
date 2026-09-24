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
static unsigned pouw_inner = 64;          // P2-07: file-scope - one truth, all sites
static std::uint64_t pouw_weight = 0;     // last self-verified PoUW receipt
static const char* pouw_verify = "PENDING";

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
        // P2-08: DEFECT-171 - advance AFTER the weight receipt
        ++current_epoch;
        decree_count = 0;
        // gossip the epoch header to all peers
        p2p::Message hdr{};
        hdr.type = p2p::EPOCH_HEADER;
        // payload: epoch_num(4B) + digest(32B) + pi_e_size(4B) + hash(32B)
        p2p::put_u32(hdr.payload, current_epoch - 1); // P2-08: the completed epoch
        // digest from the accumulator's first z value
        fp::fe dcanon = fp::fe_to_canonical(accumulator.z[0]);
        for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)dcanon.l[k]);
        p2p::put_u32(hdr.payload, 1600);
    p2p::put_u32(hdr.payload, pouw_inner);   // P2-07: the weight rides the header
    p2p::put_u64(hdr.payload, pouw_weight); // P2-07: the weight (u64)
        // hash: use the output variable's canonical form
        fp::fe ocanon = fp::fe_to_canonical(P.v);
        for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)ocanon.l[k]);
        
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
    std::setvbuf(stdout, nullptr, _IONBF, 0); // [G7] lesson: redirected stdout was fully buffered - logs stayed empty
    unsigned my_port = p2p::DEFAULT_PORT;
    
    // parse arguments
    if (argc > 1) my_port = (unsigned)atoi(argv[1]);
    
    // build the circuit matrices
    fcirc::build_matrices(A, B, C);
    
    // initialize the digest chain
    std::array<std::uint64_t,4> d0{};
    d0[0] = 1000; d0[1] = 2000;
    digest_chain.push_back(d0);
    
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
    ns.epoch = current_epoch;
    ns.decree_count = decree_count;
    ns.k_entries = K_ENTRIES;
    {   fp::fe dc = fp::fe_to_canonical(accumulator.z[0]);
        char hex[128]; hex[0] = 0;
        for (int k = 3; k >= 0; --k) { char tmp[20]; snprintf(tmp, sizeof(tmp), "%016llx", (unsigned long long)dc.l[k]); strcat(hex, tmp); }
        ns.state_root_hex = hex; }
    ns.pi_e_status = ok ? "ACCEPT" : "PENDING";
    ns.pi_e_size = 1600;
    ns.total_rows = (unsigned)A.row.size();
    ns.total_vars = (unsigned)(fcirc::NZ * (decree_count + 1));  // vars scale with entries
    ns.peer_count = peer_fds.size();
    ns.port = my_port;
    ns.pouw_inner = pouw_inner;
    ns.pouw_weight = pouw_weight;
    ns.pouw_verify = pouw_verify;

    // P2-08: DEFECT-171 - epoch 0 complete; the node now accepts epoch 1 decrees
    ++current_epoch;
    decree_count = 0;
    
    // launch the explorer server on port 8080 (my_port + 8080-31233 = my_port + 6847)
    // for simplicity, use a fixed port: 8080
    std::thread exp_thread([ns, my_port]() {
        explorer::run_explorer(my_port + 1000, ns);
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
        tv.tv_sec = 30;
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
            }
        }
        
        for (std::size_t i = 0; i < peer_fds.size(); ++i) {
            if (FD_ISSET(peer_fds[i], &read_set)) {
                p2p::Message msg;
                if (p2p::recv_message(peer_fds[i], msg)) {
                    if (msg.type == p2p::EPOCH_HEADER) {
                        std::printf("[epoch] received epoch header from peer\n");

                        // P2-07 (DEC-253): weight consensus by deterministic recomputation.
                        // Pointer accessors - DEFECT-167's second finding, fixed.
                        if (msg.payload.size() >= 52) {
                            const std::uint8_t* pl = msg.payload.data();
                            const std::size_t pln = msg.payload.size();
                            const unsigned peer_inner = p2p::get_u32(pl + pln - 12);
                            const std::uint64_t peer_w = p2p::get_u64(pl + pln - 8);
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
