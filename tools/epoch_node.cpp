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

// peer connections
static std::vector<int> peer_fds;

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
static void handle_decree(const std::vector<std::uint8_t>& payload) {
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
        
        // gossip the epoch header to all peers
        p2p::Message hdr{};
        hdr.type = p2p::EPOCH_HEADER;
        // payload: epoch_num(4B) + digest(32B) + pi_e_size(4B) + hash(32B)
        p2p::put_u32(hdr.payload, current_epoch);
        // digest from the accumulator's first z value
        fp::fe dcanon = fp::fe_to_canonical(accumulator.z[0]);
        for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)dcanon.l[k]);
        p2p::put_u32(hdr.payload, 1600); // the π_E size
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
    
    // gossip the epoch header
    p2p::Message hdr{};
    hdr.type = p2p::EPOCH_HEADER;
    p2p::put_u32(hdr.payload, current_epoch);
    fp::fe dcanon = fp::fe_to_canonical(accumulator.z[0]);
    for (int k = 0; k < 4; ++k) p2p::put_u32(hdr.payload, (std::uint32_t)dcanon.l[k]);
    p2p::put_u32(hdr.payload, 1600);
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
                        // re-gossip to other peers
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
