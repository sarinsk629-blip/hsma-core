// HSMA :: explorer.hpp - P2-03 (GAP-07 testnet, DEC-243).
// A minimal HTTP server that serves the epoch node's state as JSON + HTML.
// Runs on a separate port from the P2P layer (default: 8080).
// No external dependencies — raw POSIX sockets, hand-built HTTP responses.
#pragma once
#include <hsma/p2p.hpp>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

namespace hsma::explorer {

// the epoch node's state (filled by the caller)
struct NodeState {
    unsigned epoch{};
    unsigned decree_count{};
    unsigned k_entries{};
    std::string state_root_hex;    // the current state root (hex)
    std::string pi_e_status;       // "ACCEPT" or "PENDING"
    unsigned pi_e_size{};
    unsigned total_rows{};
    unsigned total_vars{};
    std::size_t peer_count{};
    unsigned port{};
    std::string version{"0.1.0"};
    unsigned pouw_inner{};             // P2-06: the epoch GEMM inner dimension
    std::uint64_t pouw_weight{};       // verified MACs (0 if REJECT/PENDING)
    std::string pouw_verify;           // "ACCEPT" | "REJECT" | "PENDING"
};

// build the JSON API response
inline std::string build_json(const NodeState& ns) noexcept {
    char buf[4096];
    std::snprintf(buf, sizeof(buf),
        "{\n"
        "  \"network\": \"hsma-testnet\",\n"
        "  \"version\": \"%s\",\n"
        "  \"epoch\": %u,\n"
        "  \"decree_count\": %u,\n"
        "  \"k_entries\": %u,\n"
        "  \"state_root\": \"%s\",\n"
        "  \"pi_e_status\": \"%s\",\n"
        "  \"pi_e_size\": %u,\n"
        "  \"total_constraints\": %u,\n"
        "  \"total_vars\": %u,\n"
        "  \"peers\": %zu,\n"
        "  \"p2p_port\": %u,\n"
        "  \"pouw_inner\": %u,\n"
        "  \"pouw_weight\": %llu,\n"
        "  \"pouw_verify\": \"%s\"\n"
        "}",
        ns.version.c_str(), ns.epoch, ns.decree_count, ns.k_entries,
        ns.state_root_hex.c_str(), ns.pi_e_status.c_str(), ns.pi_e_size,
        ns.total_rows, ns.total_vars, ns.peer_count, ns.port,
        ns.pouw_inner, (unsigned long long)ns.pouw_weight, ns.pouw_verify.c_str());
    return std::string(buf);
}

// build the HTML dashboard
inline std::string build_html(const NodeState& ns) noexcept {
    char buf[8192];
    std::snprintf(buf, sizeof(buf),
        R"html(<!DOCTYPE html>
<html>
<head>
<title>HSMA Epoch Explorer</title>
<style>
body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 20px; }
h1 { color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }
.card { background: #16213e; border-radius: 8px; padding: 15px; margin: 10px 0; border-left: 4px solid #00ff88; }
.label { color: #888; font-size: 0.9em; }
.value { color: #00ff88; font-size: 1.2em; font-weight: bold; }
.accept { color: #00ff88; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
</style>
</head>
<body>
<h1>HSMA Epoch Explorer</h1>
<div class="grid">
<div class="card"><div class="label">Epoch</div><div class="value">%u</div></div>
<div class="card"><div class="label">Decree Entries</div><div class="value">%u / %u</div></div>
<div class="card"><div class="label">State Root</div><div class="value" style="font-size:0.8em; word-break:break-all;">%s</div></div>
<div class="card"><div class="label">pi_E Status</div><div class="value %s">%s</div></div>
<div class="card"><div class="label">pi_E Size</div><div class="value">%u bytes</div></div>
<div class="card"><div class="label">Total Constraints</div><div class="value">%u</div></div>
<div class="card"><div class="label">Total Variables</div><div class="value">%u</div></div>
<div class="card"><div class="label">Connected Peers</div><div class="value">%zu</div></div>
<div class="card"><div class="label">P2P Port</div><div class="value">%u</div></div>
<div class="card"><div class="label">PoUW Weight</div><div class="value">%llu <span style="font-size:0.55em;color:#888;">= %u&#179; verified MACs, %s</span></div></div>
<div class="card"><div class="label">Version</div><div class="value">%s</div></div>
</div>
<p style="color:#666; margin-top:20px;">HSMA Testnet — Holographic Spin-Manifold Architecture</p>
</body>
</html>)html",
        ns.epoch, ns.decree_count, ns.k_entries,
        ns.state_root_hex.c_str(),
        std::strstr(ns.pi_e_status.c_str(), "ACCEPT") ? "accept" : "pending",
        ns.pi_e_status.c_str(),
        ns.pi_e_size,
        ns.total_rows, ns.total_vars, ns.peer_count, ns.port,
        (unsigned long long)ns.pouw_weight, ns.pouw_inner, ns.pouw_verify.c_str(),
        ns.version.c_str());
    return std::string(buf);
}

// serve one HTTP request (blocking)
inline void serve_request(int fd, const NodeState& ns) noexcept {
    char req[4096] = {};
    recv(fd, req, sizeof(req) - 1, 0);
    
    std::string path;
    {   // extract the path from "GET /path HTTP/1.1"
        const char* get = std::strstr(req, "GET ");
        if (get) {
            const char* end = std::strstr(get + 4, " ");
            if (end) path.assign(get + 4, end - get - 4);
        }
    }
    
    std::string body, content_type;
    if (path == "/api" || path == "/api/") {
        body = build_json(ns);
        content_type = "application/json";
    } else {
        body = build_html(ns);
        content_type = "text/html";
    }
    
    char hdr[256];
    std::snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n", content_type.c_str(), body.size());
    
    std::string response(hdr);
    response += body;
    send(fd, response.data(), response.size(), 0);
}

// the explorer server: runs in a background thread
inline void run_explorer(unsigned port, const NodeState& ns) noexcept {
    // port is parameterized: Node 1 uses p2p_port (e.g. 31233 -> explorer 32233),
    // Node 2 uses p2p_port + 1000 (e.g. 31234 -> explorer 32234).
    // The caller (epoch_node.cpp) decides the explorer port based on the P2P port.
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((std::uint16_t)port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return; }
    if (listen(fd, 4) < 0) { close(fd); return; }
    
    std::printf("[explorer] HTTP server listening on port %u\n", port);
    std::printf("[explorer] open http://localhost:%u in a browser\n", port);
    
    while (true) {
        struct sockaddr_in client{};
        socklen_t clen = sizeof(client);
        int cfd = accept(fd, (struct sockaddr*)&client, &clen);
        if (cfd < 0) continue;
        serve_request(cfd, ns);
        close(cfd);
    }
}

} // namespace hsma::explorer
