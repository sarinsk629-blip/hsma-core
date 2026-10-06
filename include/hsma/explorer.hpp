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

// P6.1: PoUW + ModelCommit for the submission API routes
#include <hsma/pouw.hpp>
#include <hsma/pouw/model_commit.hpp>
// P6.1: the Pasta field parameters (for fp::fe operations in GEMM submission)
#include <pallas_params_gen.hpp>

namespace hsma::explorer {

// the epoch node's state (filled by the caller)
struct NodeState {
    std::uint64_t explorer_hb = 0;   // P5-D: explorer heartbeat
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
    unsigned long long uptime_s = 0;   // P5-D: node age in seconds (node-written)
    unsigned long long hb_consensus = 0; // P5-D: consensus heartbeat counter (node-written)
};

// ---- Phase 6.2: workload queue ----
enum class WorkStatus : std::uint8_t { QUEUED, PROCESSING, DONE, FAILED };
struct WorkItem {
    std::uint64_t id;
    std::uint64_t n;
    WorkStatus status;
    std::uint64_t submitted_at;
    std::uint64_t completed_at;
    bool verified;
    bool operator==(const WorkItem& o) const { return id == o.id; }
};
inline std::vector<WorkItem> g_work_queue;
inline std::map<std::uint64_t, WorkItem> g_work_done;
inline std::atomic<std::uint64_t> g_next_work_id{1};
inline std::mutex g_work_mutex;


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
        "  \"pouw_verify\": \"%s\",\n"
        "  \"uptime_s\": %llu,\n"
        "  \"hb_consensus\": %llu\n"
        "}",
        ns.version.c_str(), ns.epoch, ns.decree_count, ns.k_entries,
        ns.state_root_hex.c_str(), ns.pi_e_status.c_str(), ns.pi_e_size,
        ns.total_rows, ns.total_vars, ns.peer_count, ns.port,
        ns.pouw_inner, (unsigned long long)ns.pouw_weight, ns.pouw_verify.c_str(),
        (unsigned long long)ns.uptime_s, (unsigned long long)ns.hb_consensus);
    return std::string(buf);
}

// build the HTML dashboard
inline std::string build_html(const NodeState& ns) noexcept {
    char buf[8192];
    std::snprintf(buf, sizeof(buf),
        R"html(<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
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
</div>

<div class="card" style="margin-top:20px; border-left:4px solid #00aaff;">
<div class="label" style="color:#00aaff;">🚀 SUBMISSION API — Submit AI workloads</div>
<div style="margin-top:10px; font-size:0.85em; color:#aaa;">
<p><b>POST /submit_gemm</b> — Submit a GEMM verification workload</p>
<pre style="background:#0d0d1a; padding:8px; border-radius:4px; overflow-x:auto;">curl -X POST http://HOST:PORT/submit_gemm -d '{"n":64}'</pre>
<p><b>POST /register_model</b> — Register an AI model for verified inference</p>
<pre style="background:#0d0d1a; padding:8px; border-radius:4px;">curl -X POST http://HOST:PORT/register_model -d '{"model_id":1}'</pre>
<p><b>GET /fleet</b> — Fleet statistics</p>
<pre style="background:#0d0d1a; padding:8px; border-radius:4px;">curl http://HOST:PORT/fleet</pre>
<p><b>GET /api</b> — Full JSON status</p>
</div>
</div>

<div class="card" style="border-left:4px solid #ffaa00;">
<div class="label" style="color:#ffaa00;">🏗️ MORE ENDPOINTS COMING</div>
<div style="margin-top:5px; font-size:0.85em; color:#888;">
Workload queue · Model inference · Result verification · Payment integration
</div>
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
    ssize_t rlen = recv(fd, req, sizeof(req) - 1, 0);
    if (rlen <= 0) { close(fd); return; }   // recv failed or connection closed
    req[rlen] = '\0';   // null-terminate at the actual read length
    
    std::string method, path;
    {   // extract method + path from "METHOD /path HTTP/1.1"
        const char* sp1 = std::strstr(req, " ");
        if (sp1) {
            method.assign(req, sp1 - req);
            const char* sp2 = std::strstr(sp1 + 1, " ");
            if (sp2) path.assign(sp1 + 1, sp2 - sp1 - 1);
        }
    }
    
    std::string post_body;
    {   auto bp = std::strstr(req, "\r\n\r\n");
        if (bp) post_body = std::string(bp + 4);
    }
    std::string body, content_type;
    // ── POST routes (Phase 6.1: the submission API) ──
    if (method == "POST" && path == "/submit_gemm") {
        auto np = post_body.find("\"n\":");
        unsigned n = 64;
        if (np != std::string::npos) n = std::atoi(post_body.c_str() + np + 4);
        if (n == 0 || n > 256) n = 64;
                    // Phase 6.2: queue the work
            std::uint64_t wid = g_next_work_id.fetch_add(1);
            {
                std::lock_guard<std::mutex> lk(g_work_mutex);
                g_work_queue.push_back({wid, (std::uint64_t)64, WorkStatus::QUEUED,
                    (std::uint64_t)time(nullptr), 0, false});
            }
            char wbuf[128];
            snprintf(wbuf, sizeof(wbuf),
                "{\"work_id\":%llu,\"status\":\"queued\",\"n\":64}",
                (unsigned long long)wid);
            body = wbuf;
            content_type = "application/json";
    } else if (method == "POST" && path == "/register_model") {
        auto idp = post_body.find("\"model_id\":");
        if (idp == std::string::npos) {
            body = "{\"error\":\"missing model_id\"}";
            content_type = "application/json";
        } else {
            std::uint64_t mid = std::strtoull(post_body.c_str() + idp + 11, nullptr, 10);
            std::uint8_t w[64]; for (int i = 0; i < 64; ++i) w[i] = std::uint8_t(mid + i);
            auto D = pouw::mcommit::weight_digest(w, 64);
            auto rr = mid * 31 + 7;
            auto Cm = pouw::mcommit::commit(D, rr);
            extern void api_register_model(std::uint64_t, std::uint64_t);
            api_register_model(mid, Cm.C);
            char tmp[128];
            std::snprintf(tmp, sizeof(tmp), "{\"model_id\":%llu,\"registered\":true}", (unsigned long long)mid);
            body = tmp;
            content_type = "application/json";
        }
    } else if (method == "GET" && path.rfind("/result/", 0) == 0) {
        // Phase 6.2: result lookup
        std::uint64_t wid = std::strtoull(path.c_str() + 8, nullptr, 10);
        char rbuf[256];
        {   std::lock_guard<std::mutex> lk(g_work_mutex);
            auto it = g_work_done.find(wid);
            if (it != g_work_done.end()) {
                std::snprintf(rbuf, sizeof(rbuf),
                    "{\"work_id\":%llu,\"status\":\"%s\",\"verified\":%s}",
                    (unsigned long long)wid,
                    it->second.verified ? "DONE" : "FAILED",
                    it->second.verified ? "true" : "false");
                body = rbuf;
                content_type = "application/json";
            } else {
                // check pending queue
                bool found = false;
                for (const auto& w : g_work_queue) {
                    if (w.id == wid) {
                        std::snprintf(rbuf, sizeof(rbuf),
                            "{\"work_id\":%llu,\"status\":\"QUEUED\"}", (unsigned long long)wid);
                        body = rbuf;
                        content_type = "application/json";
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    body = "{\"error\":\"not found\"}";
                    content_type = "application/json";
                }
            }
        }    } else if (method == "GET" && path == "/fleet") {
        char tmp[256];
        std::snprintf(tmp, sizeof(tmp),
            "{\"peers\":%u,\"uptime_s\":%llu,\"hb_consensus\":%llu,"
            "\"pouw_weight\":%llu,\"pouw_verify\":\"%s\"}",
            ns.peer_count, (unsigned long long)ns.uptime_s,
            (unsigned long long)ns.hb_consensus,
            (unsigned long long)ns.pouw_weight, ns.pouw_verify.c_str());
        body = tmp;
        content_type = "application/json";
    } else if (path == "/api" || path == "/api/") {
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
        // P5-D: read timeout — a client that connects but never sends
        // a complete request must not freeze the explorer thread forever
        struct timeval rcv_tv{.tv_sec = 5, .tv_usec = 0};
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv));
        if (cfd < 0) continue;
        serve_request(cfd, ns);
        close(cfd);
    }
}

} // namespace hsma::explorer
