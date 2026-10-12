// HSMA :: test_step47 - Phase 6.12: the COMPLETE round trip.
// submit company data -> (worker step) -> GET result -> decode -> verify
// the returned C equals the analytic answer. The loop, closed.
#include <hsma/explorer.hpp>
#include <hsma/fe.hpp>
#include <hsma/pouw.hpp>
#include <hsma/pouw/gemm_backend.hpp>
#include <cstdio>
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>
using namespace hsma;

static std::vector<std::uint8_t> to_canon_bytes(const fp::fe& x) {
    std::vector<std::uint8_t> out(32);
    fp::fe_to_le_bytes(x, reinterpret_cast<std::byte*>(out.data()));
    return out;
}
static std::string hex(const std::vector<std::uint8_t>& b) {
    static const char* d = "0123456789abcdef";
    std::string s; for (auto v : b) { s += d[v >> 4]; s += d[v & 15]; } return s;
}
static std::string http_call(const std::string& req) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return "SOCKETPAIR FAIL";
    {   struct timeval tv{.tv_sec = 10, .tv_usec = 0};
        setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }
    std::size_t off = 0;
    while (off < req.size()) {
        const ssize_t w = write(sv[1], req.data() + off, req.size() - off);
        if (w <= 0) break;
        off += (std::size_t)w;
    }
    explorer::serve_request(sv[0], explorer::NodeState{});
    std::string resp; char buf[8192]; ssize_t r;
    while ((r = read(sv[1], buf, sizeof(buf))) > 0) resp.append(buf, (std::size_t)r);
    close(sv[1]);
    return resp;
}

int main() {
    int fails = 0;
    auto C = [&](bool ok, const char* w) { if (!ok) { std::printf("FAIL: %s\n", w); ++fails; } };
    const unsigned n = 8;

    // company data: A[i][j]=i*n+j, B=1 -> C[i][j]=i*n*n + n(n-1)/2
    std::vector<std::uint8_t> rawA, rawB;
    std::vector<std::uint64_t> Aexp((std::size_t)n*n);
    for (unsigned i = 0; i < n; ++i)
        for (unsigned j = 0; j < n; ++j) {
            Aexp[i*n+j] = i*n+j;
            auto a = to_canon_bytes(fp::fe_from_u64(i * n + j));
            auto b = to_canon_bytes(fp::fe_from_u64(1));
            rawA.insert(rawA.end(), a.begin(), a.end());
            rawB.insert(rawB.end(), b.begin(), b.end());
        }

    // 1) submit with data
    const std::string body1 = "{\"n\":8,\"a\":\"" + hex(rawA) + "\",\"b\":\"" + hex(rawB) + "\"}";
    const std::string r1 = http_call("POST /submit_gemm HTTP/1.1\r\nHost: t\r\n"
        "Authorization: Bearer hsma_founder_testnet_key\r\n"
        "Content-Length: " + std::to_string(body1.size()) + "\r\n\r\n" + body1);
    C(r1.find("\"ingested\":true") != std::string::npos, "submission accepted with data");
    C(!explorer::g_work_queue.empty(), "item queued");
    if (explorer::g_work_queue.empty()) {
        std::printf("[diag] QUEUE EMPTY — submission failed; response: %.200s\n", r1.c_str());
        return 1;
    }

    // 2) the worker step — same code path as the node's pulse gate, run inline
    {
        auto& w = explorer::g_work_queue.back();
        w.status = explorer::WorkStatus::PROCESSING;
        const unsigned gn = (unsigned)w.n;
        std::vector<fp::fe> gA = w.has_inputs ? w.A_in : std::vector<fp::fe>{};
        std::vector<fp::fe> gB = w.has_inputs ? w.B_in : std::vector<fp::fe>{};
        std::vector<fp::fe> gC((std::size_t)gn * gn);
        pouw::gemm_cpu(gA.data(), gB.data(), gC.data(), gn);
        const auto PP = pouw::prove_gemm_v2(gA, gB, gC, gn, gn, gn);
        const bool gvok = pouw::verify_gemm_v2(PP, gA, gB, gC);
        w.verified = gvok;
        w.status = gvok ? explorer::WorkStatus::DONE : explorer::WorkStatus::FAILED;
        if (gvok) {
            w.has_result = true;
            w.result_bytes.reserve(gC.size() * 32);
            for (const auto& fe : gC) {
                std::uint8_t ob[32];
                fp::fe_to_le_bytes(fe, reinterpret_cast<std::byte*>(ob));
                w.result_bytes.insert(w.result_bytes.end(), ob, ob + 32);
            }
        }
        explorer::g_work_done[w.id] = w;
        explorer::g_work_queue.clear();
    }

    // 3) GET the result
    const std::string r2 = http_call("GET /result/1 HTTP/1.1\r\nHost: t\r\n\r\n");
    C(r2.find("200 OK") != std::string::npos, "result endpoint answered 200");
    C(r2.find("\"status\":\"DONE\"") != std::string::npos, "status DONE");
    C(r2.find("\"result\":\"") != std::string::npos, "result hex present");

    // 4) decode the returned C and verify against the analytic answer
    const std::size_t rp = r2.find("\"result\":\"");
    if (rp == std::string::npos) { std::printf("FAIL: no result field\n"); return 1; }
    const std::string hx = r2.substr(rp + 10, (std::size_t)n * n * 64);
    bool anal = true;
    for (unsigned i = 0; i < n; ++i)
        for (unsigned j = 0; j < n; ++j) {
            std::uint64_t v = 0;
            for (int k = 0; k < 8; ++k)
                v |= (std::uint64_t)std::stoi(hx.substr(((std::size_t)(i*n+j))*64 + k*2, 2), nullptr, 16) << (8*k);
            if (v != i*n*n + n*(n-1)/2) anal = false;
        }
    C(anal, "returned C matches the analytic value — THE LOOP IS CLOSED");

    // 5) unknown id -> 404-style miss (status missing but no crash)
    const std::string r3 = http_call("GET /result/999 HTTP/1.1\r\nHost: t\r\n\r\n");
    C(r3.find("200 OK") != std::string::npos || r3.find("404") != std::string::npos,
      "unknown id handled without crash");

    std::printf("%s\n", fails ? "test_step47: FAILED"
        : "test_step47: ALL PASS — the complete loop: company data in -> proven -> company result out, verified against the analytic answer");
    return fails ? 1 : 0;
}
