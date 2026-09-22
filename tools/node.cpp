// HSMA :: node.cpp - P2-02 (the testnet validator node CLI)
// Runs an HSMA validator: listens for connections, gossips epoch headers,
// accepts decree entries, folds them through the mfold pipeline.
//
// Usage: ./node [port] [--seed ip:port ...]
// Default port: 31233
//
// This is the FIRST HSMA binary that acts as a network node —
// not a test binary, not a probe, but a running validator.
#include <hsma/p2p.hpp>
#include <hsma/mfold.hpp>
#include <hsma/fexec_circuit.hpp>
#include "pallas_params_gen.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>
#include <thread>

using namespace hsma;

static std::vector<p2p::PeerInfo> known_peers;
static std::vector<int> peer_fds;

// handle a single incoming message from a peer
static void handle_message(int fd, const p2p::Message& msg, unsigned my_port) {
    switch (msg.type) {
    case p2p::PING:
        // respond with PONG
        {   p2p::Message pong{};
            pong.type = p2p::PONG;
            p2p::send_message(fd, pong);
        }
        break;
    case p2p::PONG:
        // peer is alive — nothing to do
        break;
    case p2p::PEER_LIST: {
        // parse and add new peers
        auto peers = p2p::parse_peer_list(msg.payload.data(), msg.payload.size());
        for (const auto& p : peers) {
            bool known = false;
            for (const auto& kp : known_peers)
                if (kp.ip == p.ip && kp.port == p.port) { known = true; break; }
            if (!known && known_peers.size() < p2p::MAX_PEERS) {
                known_peers.push_back(p);
                std::printf("[peer] new peer: %u.%u.%u.%u:%u\n",
                    (p.ip >> 24) & 0xFF, (p.ip >> 16) & 0xFF,
                    (p.ip >> 8) & 0xFF, p.ip & 0xFF, p.port);
            }
        }
        break;
    }
    case p2p::EPOCH_HEADER:
        // TODO: validate the epoch header and forward to peers
        std::printf("[epoch] received epoch header (%zu bytes)\n", msg.payload.size());
        break;
    case p2p::DECREE_ENTRY:
        // TODO: validate the decree and include it in the next epoch
        std::printf("[decree] received decree entry (%zu bytes)\n", msg.payload.size());
        break;
    default:
        std::printf("[warn] unknown message type: %u\n", msg.type);
    }
}

// gossip a message to all connected peers
static void gossip(const p2p::Message& msg) {
    for (int fd : peer_fds)
        p2p::send_message(fd, msg);
}

int main(int argc, char* argv[]) {
    unsigned my_port = p2p::DEFAULT_PORT;
    
    // parse arguments
    if (argc > 1) my_port = (unsigned)atoi(argv[1]);
    
    // seed peers from command line (--seed ip:port)
    for (int i = 2; i < argc; ++i) {
        if (std::strncmp(argv[i], "--seed", 6) == 0 && i + 1 < argc) {
            ++i;
            // parse ip:port
            std::uint32_t ip = 0;
            unsigned port = 0;
            unsigned octet = 0;
            for (const char* c = argv[i]; *c; ++c) {
                if (*c == '.') { ip = (ip << 8) | octet; octet = 0; }
                else if (*c == ':') { ip = (ip << 8) | octet; octet = 0; port = (unsigned)atoi(++c); break; }
                else octet = octet * 10 + (*c - '0');
                if (*c == '.') continue;
            }
            if (ip && port) {
                known_peers.push_back({ip, (std::uint16_t)port});
                std::printf("[seed] %u.%u.%u.%u:%u\n",
                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF, ip & 0xFF, port);
            }
        }
    }
    
    std::printf("═══════════════════════════════════════\n");
    std::printf("  HSMA NODE — P2-02 (testnet validator)\n");
    std::printf("  port: %u | peers: %zu\n", my_port, known_peers.size());
    std::printf("═══════════════════════════════════════\n");
    
    // create the listening socket
    int listener = p2p::create_listener(my_port);
    if (listener < 0) {
        std::printf("✗ failed to listen on port %u\n", my_port);
        return 1;
    }
    std::printf("[node] listening on port %u\n", my_port);
    
    // connect to seed peers
    for (const auto& p : known_peers) {
        int fd = p2p::connect_peer(p.ip, p.port);
        if (fd >= 0) {
            peer_fds.push_back(fd);
            std::printf("[peer] connected: %u.%u.%u.%u:%u\n",
                (p.ip >> 24) & 0xFF, (p.ip >> 16) & 0xFF,
                (p.ip >> 8) & 0xFF, p.ip & 0xFF, p.port);
        }
    }
    
    // the gossip loop: listen for connections and messages
    std::printf("[node] entering gossip loop...\n");
    
    while (true) {
        // check for new connections
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(listener, &read_set);
        for (int fd : peer_fds) FD_SET(fd, &read_set);
        
        int max_fd = listener;
        for (int fd : peer_fds) if (fd > max_fd) max_fd = fd;
        
        struct timeval tv{};
        tv.tv_sec = 5;  // 5-second timeout for periodic ping
        tv.tv_usec = 0;
        
        int ready = select(max_fd + 1, &read_set, nullptr, nullptr, &tv);
        if (ready < 0) break;  // error
        
        // accept new connections
        if (FD_ISSET(listener, &read_set)) {
            struct sockaddr_in addr{};
            socklen_t len = sizeof(addr);
            int new_fd = accept(listener, (struct sockaddr*)&addr, &len);
            if (new_fd >= 0) {
                peer_fds.push_back(new_fd);
                std::printf("[peer] new connection (fd=%d)\n", new_fd);
                
                // send our peer list to the new peer
                p2p::Message pl{};
                pl.type = p2p::PEER_LIST;
                pl.payload = p2p::build_peer_list(known_peers);
                p2p::send_message(new_fd, pl);
            }
        }
        
        // handle messages from peers
        for (std::size_t i = 0; i < peer_fds.size(); ++i) {
            if (FD_ISSET(peer_fds[i], &read_set)) {
                p2p::Message msg;
                if (p2p::recv_message(peer_fds[i], msg)) {
                    handle_message(peer_fds[i], msg, my_port);
                } else {
                    std::printf("[peer] disconnected (fd=%d)\n", peer_fds[i]);
                    close(peer_fds[i]);
                    peer_fds.erase(peer_fds.begin() + i);
                    --i;
                }
            }
        }
        
        // periodic PING to keep connections alive
        static auto last_ping = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_ping).count() >= 30) {
            p2p::Message ping{};
            ping.type = p2p::PING;
            gossip(ping);
            last_ping = now;
        }
    }
    
    return 0;
}
