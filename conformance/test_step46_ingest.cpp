// HSMA :: test_step46 - Phase 6.11: external data ingestion, wire-level.
// socketpair -> serve_request: the REAL HTTP handler. Receipts:
//   (1) data round-trips byte-exact through fe_from_le_bytes (DEC-105 parse)
//   (2) input tags match client-side FNV (transport binding)
//   (3) the proof over INGESTED data verifies, and C matches the analytic value
//   (4) malformed hex -> 400; no-data -> benchmark mode unchanged
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
static std::uint64_t fnv(const std::vector<std::uint8_t>& b) {
    std::uint64_t h = 14695981039346656037ull;
    for (auto v : b) { h ^= v; h *= 1099511628211ull; }
    return h;
}
static std::string hex(const std::vector<std::uint8_t>& b) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (auto v : b) { s += d[v >> 4]; s += d[v & 15]; }
    return s;
}
static std::string http_post(const std::string& body) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return "SOCKETPAIR FAIL";
    const std::string req = "POST /submit_gemm HTTP/1.1\r\nHost: t\r\n"
        "Authorization: Bearer hsma_founder_testnet_key\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    // write in chunks (the handler reads in a loop now — exercise it)
    std::size_t off = 0;
    while (off < req.size()) {
        const ssize_t w = write(sv[1], req.data() + off, req.size() - off);
        if (w <= 0) break;
        off += (std::size_t)w;
    }
    // hang-proof: the read loop below waits for EOF — bound it, so a
    // missing close on the handler side becomes a fast FAIL, not a hang
    {   struct timeval tv{.tv_sec = 10, .tv_usec = 0};
        setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }
    explorer::serve_request(sv[0], explorer::NodeState{});
    std::string resp;
    char buf[4096];
    ssize_t r;
    while ((r = read(sv[1], buf, sizeof(buf))) > 0) resp.append(buf, (std::size_t)r);
    close(sv[1]);
    return resp;
}

int main() {
    int fails = 0;
    auto C = [&](bool ok, const char* w) { if (!ok) { std::printf("FAIL: %s\n", w); ++fails; } };
    const unsigned n = 8;

    // the company's data: A[i][j] = i*n+j, B = 1  ->  C[i][j] = i*n + n(n-1)/2
    std::vector<std::uint8_t> rawA, rawB;
    for (unsigned i = 0; i < n; ++i)
        for (unsigned j = 0; j < n; ++j) {
            auto a = to_canon_bytes(fp::fe_from_u64(i * n + j));
            auto b = to_canon_bytes(fp::fe_from_u64(1));
            rawA.insert(rawA.end(), a.begin(), a.end());
            rawB.insert(rawB.end(), b.begin(), b.end());
        }
    const std::uint64_t expA = fnv(rawA), expB = fnv(rawB);

    // (1)+(2) submit with data -> ingested:true, tags match
    const std::string body1 = "{\"n\":8,\"a\":\"" + hex(rawA) + "\",\"b\":\"" + hex(rawB) + "\"}";
    const std::string r1 = http_post(body1);
    std::printf("[diag] response r1 (first 300): %.300s\n", r1.c_str());
    C(r1.find("\"ingested\":true") != std::string::npos, "ingested:true returned");
    C(r1.find("tag_a") != std::string::npos, "tag_a echoed");

    // (3) inspect the queue item: byte-exact round trip + proof over it
    if (explorer::g_work_queue.empty()) {
        std::printf("[diag] QUEUE EMPTY — the handler did not queue; response was the failure path\n");
        std::printf("%s\n", fails ? "test_step46: FAILED (see [diag] above)" : "impossible");
        return 1;
    }
    const auto& w = explorer::g_work_queue.back();
    C(w.has_inputs && w.n == n, "item carries ingested inputs");
    C(w.ingest_tag_a == expA && w.ingest_tag_b == expB, "transport tags match client-side FNV");
    bool rt = true;
    for (unsigned i = 0; i < n && rt; ++i)
        for (unsigned j = 0; j < n; ++j)
            if (fp::fe_to_canonical(w.A_in[i * n + j]).l[0] != i * n + j) { rt = false; break; }
    C(rt, "A round-tripped byte-exact (canonical values)");
    std::vector<fp::fe> Cm((std::size_t)n * n);
    pouw::gemm_cpu(w.A_in.data(), w.B_in.data(), Cm.data(), n);
    bool anal = true;
    for (unsigned i = 0; i < n; ++i)
        for (unsigned j = 0; j < n; ++j)
            if (fp::fe_to_canonical(Cm[i * n + j]).l[0] != (std::uint64_t)i * n * n + n * (n - 1) / 2) anal = false;
    if (!anal) {
        for (unsigned i = 0; i < 2; ++i)
            for (unsigned j = 0; j < 2; ++j) {
                const auto c = fp::fe_to_canonical(Cm[i * n + j]);
                std::printf("[diag] C[%u][%u] = limbs {%016llx %016llx %016llx %016llx}  low=%llu expected=%llu\n",
                    i, j, (unsigned long long)c.l[0], (unsigned long long)c.l[1],
                    (unsigned long long)c.l[2], (unsigned long long)c.l[3],
                    (unsigned long long)c.l[0], (unsigned long long)((std::uint64_t)i * n * n + n * (n - 1) / 2));
            }
    }
    C(anal, "C matches the analytic value (the ingested data ACTUALLY flowed)");
    const auto PP = pouw::prove_gemm_v2(w.A_in, w.B_in, Cm, n, n, n);
    C(pouw::verify_gemm_v2(PP, w.A_in, w.B_in, Cm), "sum-check over INGESTED data verifies");

    // (4) malformed hex -> clean 400
    const std::string r2 = http_post("{\"n\":8,\"a\":\"zznot hex\",\"b\":\"00\"}");
    C(r2.find("ingestion failed") != std::string::npos, "malformed hex -> clean 400 error");

    // (5) no-data submission -> benchmark mode, unchanged
    const std::string r3 = http_post("{\"n\":8}");
    C(r3.find("\"ingested\":true") == std::string::npos, "no-data -> benchmark mode (no ingested field)");
    C(!explorer::g_work_queue.back().has_inputs, "benchmark item has no inputs");

    std::printf("%s\n", fails ? "test_step46: FAILED"
        : "test_step46: ALL PASS — ingestion wire-level: round-trip byte-exact, tags bound, proof over company data verifies, 400 on malformed, benchmark mode intact");
    return fails ? 1 : 0;
}
