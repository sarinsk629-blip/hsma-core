// HSMA :: p2p.hpp - P2-01 (the P2P networking layer, DEC-241).
// Minimal peer-to-peer networking for the HSMA testnet:
//   - TCP-based peer connections (IPv4)
//   - Peer discovery via seed nodes + peer exchange
//   - Gossip protocol for epoch headers and decree entries
//   - Message framing: length-prefixed binary serialization
//
// DESIGN PRINCIPLES:
//   - Minimal: no external dependencies, POSIX sockets only
//   - Deterministic: same messages produce same bytes (DEC-090 float-free)
//   - Simple: no NAT traversal, no encryption (crypto layer handles it)
//   - Testnet-grade: production hardening is P2-02+
//
// MESSAGE TYPES:
//   0x01 = PEER_LIST     (share known peers)
//   0x02 = EPOCH_HEADER  (epoch number, state root, pi_E digest)
//   0x03 = DECREE_ENTRY  (a decree to be folded)
//   0x04 = PING          (keepalive)
//   0x05 = PONG          (keepalive response)
//
// WIRE FORMAT:
//   [4 bytes: magic "HSMA"] [1 byte: msg_type] [4 bytes: payload_len] [payload]
//
// LAWS: CA-R90 (float-free numeric core), CA-R142 (canonical domain),
//       CA-R126 (self-check), CA-R158 (the domain law)
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#endif

namespace hsma::p2p {

// ---- constants ----
inline constexpr const char* MAGIC = "HSMA";
inline constexpr unsigned MAGIC_LEN = 4;
inline constexpr unsigned HEADER_LEN = MAGIC_LEN + 1 + 4; // magic + type + length
inline constexpr unsigned MAX_PAYLOAD = 1024 * 1024;      // 1 MB max payload
inline constexpr unsigned DEFAULT_PORT = 31233;
inline constexpr unsigned MAX_PEERS = 32;

// ---- message types ----
enum MsgType : std::uint8_t {
    PEER_LIST    = 0x01,
    EPOCH_HEADER = 0x02,
    DECREE_ENTRY = 0x03,
    PING         = 0x04,
    PONG         = 0x05,
};

// ---- peer info ----
struct PeerInfo {
    std::uint32_t ip{};      // IPv4 address (network byte order)
    std::uint16_t port{};    // port (host byte order)
};

// ---- message: the wire-format envelope ----
struct Message {
    std::uint8_t type{};
    std::vector<std::uint8_t> payload;
};

// ---- serialization helpers (deterministic, big-endian) ----

inline void put_u32(std::vector<std::uint8_t>& buf, std::uint32_t v) noexcept {
    buf.push_back((std::uint8_t)(v >> 24));
    buf.push_back((std::uint8_t)(v >> 16));
    buf.push_back((std::uint8_t)(v >> 8));
    buf.push_back((std::uint8_t)v);
}

inline std::uint32_t get_u32(const std::uint8_t* buf) noexcept {
    return ((std::uint32_t)buf[0] << 24) | ((std::uint32_t)buf[1] << 16) |
           ((std::uint32_t)buf[2] << 8) | (std::uint32_t)buf[3];
}

inline void put_u64(std::vector<std::uint8_t>& buf, std::uint64_t v) noexcept {
    for (int i = 7; i >= 0; --i) buf.push_back((std::uint8_t)(v >> (8 * i)));
}

inline std::uint64_t get_u64(const std::uint8_t* buf) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | buf[i];
    return v;
}

// ---- message serialization ----

inline std::vector<std::uint8_t> serialize(const Message& msg) noexcept {
    std::vector<std::uint8_t> buf;
    buf.insert(buf.end(), MAGIC, MAGIC + MAGIC_LEN);
    buf.push_back(msg.type);
    put_u32(buf, (std::uint32_t)msg.payload.size());
    buf.insert(buf.end(), msg.payload.begin(), msg.payload.end());
    return buf;
}

// returns true if a complete message was parsed
inline bool deserialize(const std::vector<std::uint8_t>& buf, Message& msg) noexcept {
    if (buf.size() < HEADER_LEN) return false;
    if (std::memcmp(buf.data(), MAGIC, MAGIC_LEN) != 0) return false;
    msg.type = buf[MAGIC_LEN];
    std::uint32_t payload_len = get_u32(buf.data() + MAGIC_LEN + 1);
    if (payload_len > MAX_PAYLOAD) return false;
    if (buf.size() < HEADER_LEN + payload_len) return false;
    msg.payload.assign(buf.begin() + HEADER_LEN, buf.begin() + HEADER_LEN + payload_len);
    return true;
}

// ---- payload builders ----

// PEER_LIST payload: [count(4B)] then [ip(4B) port(2B)] per peer
inline std::vector<std::uint8_t> build_peer_list(const std::vector<PeerInfo>& peers) noexcept {
    std::vector<std::uint8_t> buf;
    put_u32(buf, (std::uint32_t)peers.size());
    for (const auto& p : peers) {
        buf.push_back((std::uint8_t)(p.ip >> 24));
        buf.push_back((std::uint8_t)(p.ip >> 16));
        buf.push_back((std::uint8_t)(p.ip >> 8));
        buf.push_back((std::uint8_t)p.ip);
        buf.push_back((std::uint8_t)(p.port >> 8));
        buf.push_back((std::uint8_t)(p.port & 0xFF));
    }
    return buf;
}

inline std::vector<PeerInfo> parse_peer_list(const std::uint8_t* data, std::size_t len) noexcept {
    std::vector<PeerInfo> peers;
    std::size_t i = 0;
    while (i + 6 <= len && peers.size() < MAX_PEERS) {
        PeerInfo p;
        p.ip = ((std::uint32_t)data[i] << 24) | ((std::uint32_t)data[i+1] << 16) |
               ((std::uint32_t)data[i+2] << 8) | (std::uint32_t)data[i+3];
        p.port = ((std::uint16_t)data[i+4] << 8) | (std::uint16_t)data[i+5];
        peers.push_back(p);
        i += 6;
    }
    return peers;
}

// EPOCH_HEADER payload: [epoch_num(4B)] [digest(32B)] [pi_E_size(4B)] [pi_E_hash(32B)]
inline std::vector<std::uint8_t> build_epoch_header(
    std::uint32_t epoch_num, const std::uint8_t digest[32],
    std::uint32_t pi_e_size, const std::uint8_t pi_e_hash[32]) noexcept {
    std::vector<std::uint8_t> buf;
    put_u32(buf, epoch_num);
    buf.insert(buf.end(), digest, digest + 32);
    put_u32(buf, pi_e_size);
    buf.insert(buf.end(), pi_e_hash, pi_e_hash + 32);
    return buf;
}

// DECREE_ENTRY payload: [entry_data as raw bytes] (the decree to fold)

// ---- socket helpers (POSIX TCP) ----

// create a listening socket
inline int create_listener(unsigned port) noexcept {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((std::uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, 8) < 0) { close(fd); return -1; }
    return fd;
}

// connect to a peer (returns socket fd or -1)
inline int connect_peer(std::uint32_t ip, std::uint16_t port) noexcept {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = htons(port);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

// send a complete message on a socket
inline bool send_message(int fd, const Message& msg) noexcept {
    auto buf = serialize(msg);
    std::size_t sent = 0;
    while (sent < buf.size()) {
        auto n = send(fd, buf.data() + sent, buf.size() - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

// receive a complete message on a socket (blocking)
inline bool recv_message(int fd, Message& msg) noexcept {
    std::vector<std::uint8_t> header(HEADER_LEN);
    std::size_t got = 0;
    while (got < HEADER_LEN) {
        auto n = recv(fd, header.data() + got, HEADER_LEN - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    if (std::memcmp(header.data(), MAGIC, MAGIC_LEN) != 0) return false;
    msg.type = header[MAGIC_LEN];
    std::uint32_t payload_len = get_u32(header.data() + MAGIC_LEN + 1);
    if (payload_len > MAX_PAYLOAD) return false;
    msg.payload.resize(payload_len);
    got = 0;
    while (got < payload_len) {
        auto n = recv(fd, msg.payload.data() + got, payload_len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

// close a socket
inline void close_socket(int fd) noexcept {
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

} // namespace hsma::p2p
