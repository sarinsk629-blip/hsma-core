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
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <array>

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
#include <hsma/sha256.hpp>
#include <hsma/pouw/gemm_backend.hpp>
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
    // Phase 6.11: external data ingestion (opt-in via "a"/"b" hex fields)
    bool has_inputs = false;
    std::vector<fp::fe> A_in, B_in;   // n*n each, Montgomery domain
    std::uint64_t ingest_tag_a = 0, ingest_tag_b = 0; // transport tag (FNV-1a); ModelCommit binding = 6.11b
    // Phase 6.12: result-data delivery — C serialized canonical LE (32B/fe)
    bool has_result = false;
    std::vector<std::uint8_t> result_bytes;
    // Phase 6.11b: cryptographic input commitments (DEF-315: heap-typed)
    std::array<std::uint8_t, 32> ic{};   // SHA256(A_bytes || B_bytes) — set at ingestion
    bool commitment_checked = false;     // worker re-verified at pickup
};
inline std::vector<WorkItem> g_work_queue;
inline std::map<std::uint64_t, WorkItem> g_work_done;
inline std::atomic<std::uint64_t> g_next_work_id{1};
inline std::mutex g_work_mutex;

// ---- Phase 6.3: API authentication ----
inline std::map<std::string, bool> g_valid_keys;  // key -> active
inline std::map<std::string, std::uint64_t> g_rate_limit;  // key -> request count
inline std::chrono::steady_clock::time_point g_rate_window_start;
static constexpr unsigned RATE_LIMIT_PER_MIN = 10;

inline bool validate_api_key(const std::string& key) {
    auto it = g_valid_keys.find(key);
    return it != g_valid_keys.end() && it->second;
}
inline bool check_rate_limit(const std::string& key) {
    // DEF-359: TRUE sliding window — AFE caught the original never
    // resetting (10 requests ever = blocked forever). Each key's count
    // resets after 60s (shared window, testnet-simple).
    auto now = std::chrono::steady_clock::now();
    auto it = g_rate_limit.find(key);
    if (it == g_rate_limit.end() ||
        std::chrono::duration_cast<std::chrono::seconds>(now - g_rate_window_start).count() >= 60) {
        g_rate_limit[key] = 1;
        g_rate_window_start = now;
        return true;
    }
    if (it->second >= RATE_LIMIT_PER_MIN) return false;
    it->second++;
    return true;
}


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
<p><b>GET /api_key</b> — Get your own API key instantly (self-serve, no signup)</p>
<pre style="background:#0d0d1a; padding:8px; border-radius:4px;">curl http://HOST:PORT/api_key</pre>
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
// DEF-301: defined IN the header (inline) — any TU linking serve_request,
// tests included, must resolve every symbol the header's code calls.
inline void api_register_model(std::uint64_t mid, std::uint64_t commitment) {
    std::printf("[api] model %llu registered (C=%llu)\n",
        (unsigned long long)mid, (unsigned long long)commitment);
}

// Phase 6.18-pre: partner API keys — loaded once from api_keys.txt at first
// request (restart-surviving). One key per line. The founder key is
// guaranteed too (testnet scope).
inline void load_api_keys_once() noexcept {
    static bool loaded = false;
    if (loaded) return;
    loaded = true;
    std::ifstream kf("api_keys.txt");
    std::string line;
    while (std::getline(kf, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (!line.empty()) g_valid_keys[line] = true;
    }
}
inline void serve_request(int fd, const NodeState& ns) noexcept {
    load_api_keys_once();
    // Phase 6.3: seed the founder's testnet key (idempotent)
    g_valid_keys["hsma_founder_testnet_key"] = true;

    // Phase 6.11: full-request read — the old single 4KB recv was the
    // ingestion wall (CA-R296). Headers until \r\n\r\n, then the
    // Content-Length body, capped. SO_RCVTIMEO (set at accept) bounds
    // every recv — the loop cannot hang.
    static constexpr std::size_t INGEST_CAP = 16u * 1024u * 1024u;
    std::string req;
    req.reserve(8192);
    {
        char tmp[16384];
        std::size_t hdr_end = std::string::npos, want = std::string::npos;
        while (req.size() < INGEST_CAP) {
            const ssize_t r = recv(fd, tmp, sizeof(tmp), 0);
            if (r <= 0) break;
            req.append(tmp, (std::size_t)r);
            if (hdr_end == std::string::npos) hdr_end = req.find("\r\n\r\n");
            if (hdr_end != std::string::npos && want == std::string::npos) {
                want = hdr_end + 4;
                std::size_t clp = req.find("Content-Length:");
                if (clp == std::string::npos || clp > hdr_end) clp = req.find("content-length:");
                if (clp != std::string::npos && clp < hdr_end)
                    want += (std::size_t)std::strtoul(req.c_str() + clp + 15, nullptr, 10);
            }
            if (want != std::string::npos && req.size() >= want) break;
        }
    }
    if (req.empty()) { close(fd); return; }
    const char* RQ = req.c_str(); // unified view (CA-R265)
    
    std::string method, path;
    {   // extract method + path from "METHOD /path HTTP/1.1"
        const char* sp1 = std::strstr(RQ, " ");
        if (sp1) {
            method.assign(RQ, sp1 - RQ);   // DEF-304: ptr+len form — the 2-arg string overload (str, pos) means 'pos to end', not 'len bytes'
            const char* sp2 = std::strstr(sp1 + 1, " ");
            if (sp2) path.assign(sp1 + 1, sp2 - sp1 - 1);
        }
    }
    
    std::string post_body;
    {   auto bp = std::strstr(RQ, "\r\n\r\n");
        if (bp) post_body = std::string(bp + 4);
    }
    std::string body, content_type;

    // Phase 6.3: extract Authorization header
    std::string auth_key;
    {   auto auth_hdr = std::strstr(RQ, "Authorization: Bearer ");
        if (auth_hdr) {
            const char* astart = auth_hdr + strlen("Authorization: Bearer ");
            const char* aend = std::strstr(astart, "\r\n");
            if (aend) auth_key.assign(astart, aend - astart);
        }
    }

    // Phase 6.3: auth check for POST routes
    if (method == "POST") {
        if (auth_key.empty() || !validate_api_key(auth_key)) {
            std::string err = "{\"error\":\"invalid API key\"}";
            std::string err_resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: "
                + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
            send(fd, err_resp.c_str(), err_resp.size(), 0);
            close(fd);
            return;
        }
        if (!check_rate_limit(auth_key)) {
            std::string err2 = "{\"error\":\"rate limit exceeded (10 submissions/min — GET routes are unlimited)\"}";
            std::string err_resp2 = "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 60\r\nContent-Length: "
                + std::to_string(err2.size()) + "\r\nConnection: close\r\n\r\n" + err2;
            send(fd, err_resp2.c_str(), err_resp2.size(), 0);
            close(fd);
            return;
        }
    }

    // Phase 6.18: SELF-SERVE API KEYS — the permissionless principle.
    // Anyone generates their own key instantly (the Bitcoin-address model:
    // no approval, no human). The key ties actions to an identity for
    // rate limiting + revocation. Spam defenses are the existing ones:
    // per-key rate limits + tier clamps + honest labels.
    if (method == "GET" && path == "/api_key") {
        std::uint8_t raw[24];
        {   // os-random key material
            std::ifstream urand("/dev/urandom", std::ios::binary);
            urand.read(reinterpret_cast<char*>(raw), sizeof(raw));
        }
        char khex[49] = {};
        for (int k = 0; k < 24; ++k)
            std::snprintf(khex + k*2, 3, "%02x", raw[k]);
        std::string key = std::string("hsma_") + khex;
        // persist: append to api_keys.txt (the loader picks it up for ALL
        // nodes on next restart; this node accepts it immediately)
        {   std::ofstream kf("api_keys.txt", std::ios::app);
            kf << key << "\n";
        }
        g_valid_keys[key] = true;   // this node: live now
        char kb[160];
        std::snprintf(kb, sizeof(kb),
            "{\"api_key\":\"%s\",\"note\":\"keep private; rate-limited 10/min; works on all nodes after next restart\"}",
            key.c_str());
        body = kb;
        content_type = "application/json";
        // fall through to the response — done
    } else // ── POST routes (Phase 6.1: the submission API) ── (Phase 6.1: the submission API) ──
    if (method == "POST" && path == "/submit_gemm") {
        auto np = post_body.find("\"n\":");
        unsigned n = 64;
        if (np != std::string::npos) n = std::atoi(post_body.c_str() + np + 4);
        if (n == 0 || n > 256) n = 64;
        // Phase 6.16 verdict: fleet-verifiable = 64 (615ms verify, fits epoch cadence).
// GPU nodes may submit up to 256 — anchor-verified only (9.8s/claim: too costly
// for fleet cross-verification; the response carries the honest label).
// n>256 = commit-then-deliver only (6.11c, the fold-routing era).
        if (n > 256) {
            std::string gb = "{\"error\":\"n>256 requires commit-then-deliver (6.11c)\",\"max_direct\":256}";
            std::string gr = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: "
                + std::to_string(gb.size()) + "\r\nConnection: close\r\n\r\n" + gb;
            send(fd, gr.c_str(), gr.size(), 0);
            close(fd);
            return;
        }
        if (n > 64 && !pouw::gpu_available()) {
            std::string gb = "{\"error\":\"n>64 requires GPU backend (CPU would stall the heartbeat)\"}";
            std::string gr = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: "
                + std::to_string(gb.size()) + "\r\nConnection: close\r\n\r\n" + gb;
            send(fd, gr.c_str(), gr.size(), 0);
            close(fd);
            return;
        }

                    // Phase 6.2: queue the work
            // Phase 6.11: external data ingestion — embedded matrices as hex
            // (canonical LE, n*n fes per matrix). fe_from_le_bytes REJECTS
            // non-canonical encodings (DEC-105): malleability closed at parse.
            // Tags are transport receipts (FNV-1a); ModelCommit binding = 6.11b.
            bool has_in = false;
            std::vector<fp::fe> Ain, Bin;
            std::uint64_t tag_a = 0, tag_b = 0;
            std::array<std::uint8_t, 32> ic{};   // 6.11b: filled inside the hex-parse block below
            {
                auto ap = post_body.find("\"a\":\"");
                auto bp2 = post_body.find("\"b\":\"");
                if (ap != std::string::npos || bp2 != std::string::npos) {
                    auto hexbytes = [](const std::string& t, std::size_t start) -> std::vector<std::uint8_t> {
                        std::vector<std::uint8_t> out;
                        std::size_t i = start;
                        auto hx = [](char c) -> int {
                            if (c >= '0' && c <= '9') return c - '0';
                            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                            return -1; };
                        while (i + 1 < t.size() && t[i] != '"') {
                            const int hi = hx(t[i]), lo = hx(t[i + 1]);
                            if (hi < 0 || lo < 0) { out.clear(); return out; }
                            out.push_back((std::uint8_t)((hi << 4) | lo));
                            i += 2;
                        }
                        return out;
                    };
                    auto rawA = (ap != std::string::npos) ? hexbytes(post_body, ap + 5) : std::vector<std::uint8_t>{};
                    auto rawB = (bp2 != std::string::npos) ? hexbytes(post_body, bp2 + 5) : std::vector<std::uint8_t>{};
                    {   // 6.11b: the commitment (heap, DEF-315) — fills the route-scope ic
                        std::vector<std::uint8_t> cat(rawA.size() + rawB.size());
                        std::memcpy(cat.data(), rawA.data(), rawA.size());
                        std::memcpy(cat.data() + rawA.size(), rawB.data(), rawB.size());
                        digest::sha256(cat.data(), cat.size(), ic.data());
                    }
                    const std::size_t need = (std::size_t)n * n * 32;
                    auto tofes = [&](const std::vector<std::uint8_t>& raw, std::vector<fp::fe>& out) -> bool {
                        if (raw.size() != need) return false;
                        out.resize(n * n);
                        for (std::size_t k = 0; k < n * n; ++k) {
                            const auto rr = fp::fe_from_le_bytes(reinterpret_cast<const std::byte*>(raw.data() + k * 32));
                            if (!rr.ok) return false;
                            out[k] = rr.value;
                        }
                        return true;
                    };
                    auto fnv = [](const std::vector<std::uint8_t>& raw) -> std::uint64_t {
                        std::uint64_t h = 14695981039346656037ull;
                        for (std::uint8_t b : raw) { h ^= b; h *= 1099511628211ull; }
                        return h;
                    };
                    if (rawA.size() == need && rawB.size() == need && tofes(rawA, Ain) && tofes(rawB, Bin)) {
                        has_in = true;
                        tag_a = fnv(rawA); tag_b = fnv(rawB);
                    } else {
                        const std::string eb = "{\"error\":\"ingestion failed: a/b must be hex of n*n canonical 32-byte field elements\"}";
                        const std::string er = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: "
                            + std::to_string(eb.size()) + "\r\nConnection: close\r\n\r\n" + eb;
                        send(fd, er.c_str(), er.size(), 0);
                        close(fd);
                        return;
                    }
                }
            }
            std::uint64_t wid = g_next_work_id.fetch_add(1);
            {
                std::lock_guard<std::mutex> lk(g_work_mutex);
                g_work_queue.push_back({wid, (std::uint64_t)n, WorkStatus::QUEUED,
                (std::uint64_t)time(nullptr), 0, false,
                has_in, std::move(Ain), std::move(Bin), tag_a, tag_b});
                if (has_in) g_work_queue.back().ic = ic;
            }
            char wbuf[128];
            snprintf(wbuf, sizeof(wbuf),
                "{\"work_id\":%llu,\"status\":\"queued\",\"n\":%u}",
                (unsigned long long)wid, n);
            body = wbuf;
            if (has_in) {
                char tb[320];
                std::snprintf(tb, sizeof(tb),
                    "{\"work_id\":%llu,\"status\":\"queued\",\"n\":%u,\"ingested\":true,\"tag_a\":\"%016llx\",\"tag_b\":\"%016llx\",\"commitment\":\"%s\",\"verification\":\"%s\"}",
                    (unsigned long long)wid, n, (unsigned long long)tag_a, (unsigned long long)tag_b,
                    (n <= 64 ? "fleet" : "anchor-only (verify cost 9.8s at 256)"),
                    [&]{ char h[65] = {}; for (int k = 0; k < 32; ++k) std::snprintf(h + k*2, 3, "%02x", ic[k]); return std::string(h); }().c_str());
                body = tb;
            }
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
            api_register_model(mid, Cm.C);
            char tmp[128];
            std::snprintf(tmp, sizeof(tmp), "{\"model_id\":%llu,\"registered\":true}", (unsigned long long)mid);
            body = tmp;
            content_type = "application/json";
        }
    } else     // Phase 6.17 v2: the claim preimage — served to the epoch-verifier.
    // AUTH REQUIRED (Bearer). Returns the matrices + result so an independent
    // node can re-verify the computation. The done-map holds everything.
    if (method == "GET" && path.rfind("/claim_inputs/", 0) == 0) {
        if (auth_key.empty() || !validate_api_key(auth_key)) {
            std::string e = "{\"error\":\"invalid API key\"}";
            std::string er = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: "
                + std::to_string(e.size()) + "\r\nConnection: close\r\n\r\n" + e;
            send(fd, er.c_str(), er.size(), 0);
            close(fd);
            return;
        }
        std::uint64_t cid = std::strtoull(path.c_str() + 14, nullptr, 10);
        {   std::lock_guard<std::mutex> lk(g_work_mutex);
            auto it = g_work_done.find(cid);
            if (it != g_work_done.end() && it->second.has_inputs && it->second.verified) {
                const auto& w = it->second;
                std::string hx = [](const std::vector<fp::fe>& v) {
                    static const char* d = "0123456789abcdef";
                    std::string out; out.reserve(v.size()*64);
                    for (const auto& f : v) {
                        std::uint8_t b[32];
                        fp::fe_to_le_bytes(f, reinterpret_cast<std::byte*>(b));
                        for (int k = 0; k < 32; ++k) { out += d[b[k] >> 4]; out += d[b[k] & 15]; }
                    }
                    return out;
                }(w.A_in);   // A only for size; B appended:
                std::string hxb = [](const std::vector<fp::fe>& v) {
                    static const char* d = "0123456789abcdef";
                    std::string out; out.reserve(v.size()*64);
                    for (const auto& f : v) {
                        std::uint8_t b[32];
                        fp::fe_to_le_bytes(f, reinterpret_cast<std::byte*>(b));
                        for (int k = 0; k < 32; ++k) { out += d[b[k] >> 4]; out += d[b[k] & 15]; }
                    }
                    return out;
                }(w.B_in);
                std::string hxc = [](const std::vector<std::uint8_t>& v) {
                    static const char* d = "0123456789abcdef";
                    std::string out; out.reserve(v.size()*2);
                    for (std::uint8_t b : v) { out += d[b >> 4]; out += d[b & 15]; }
                    return out;
                }(w.result_bytes);
                std::string j = "{\"work_id\":" + std::to_string(w.id) + ",\"n\":" + std::to_string(w.n)
                    + ",\"a\":\"" + hx + "\",\"b\":\"" + hxb + "\",\"c\":\"" + hxc + "\"}";
                std::string r = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + std::to_string(j.size()) + "\r\nConnection: close\r\n\r\n" + j;
                send(fd, r.c_str(), r.size(), 0);
                close(fd);
                return;
            }
        }
        std::string nf = "{\"error\":\"claim not found or lacks inputs\"}";
        std::string nr = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: "
            + std::to_string(nf.size()) + "\r\nConnection: close\r\n\r\n" + nf;
        send(fd, nr.c_str(), nr.size(), 0);
        close(fd);
        return;
    }
    if (method == "GET" && path.rfind("/result/", 0) == 0) {
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
                if (it->second.has_result && !it->second.result_bytes.empty()) {
                    static const char* hexd = "0123456789abcdef";
                    std::string hx; hx.reserve(it->second.result_bytes.size() * 2);
                    for (std::uint8_t b : it->second.result_bytes) { hx += hexd[b >> 4]; hx += hexd[b & 15]; }
                    const std::size_t cut = body.find_last_of('}');
                    if (cut != std::string::npos) body = body.substr(0, cut) + ",\"result\":\"" + hx + "\"}";
                }
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
    close(fd);   // DEF-302: Connection: close is DECLARED — honor it on every path
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
