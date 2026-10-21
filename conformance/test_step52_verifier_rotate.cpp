// HSMA :: test_step52 - Phase 6.17 v2 s2: the rotating epoch-verifier (CA-R370d).
// Properties under test:
//   P1 genuineness : a real fold-site-shaped claim verifies at BOTH tiers
//                    (structure + identity + full-GEMM recompute)
//   P2 tamper-evid : result flip  -> tier-1 AND tier-2 both fail
//                    ic flip     -> tier-1 fails (commitment binding), tier-2
//                    still holds (A/B unchanged) — the tiers separate cleanly
//   P3 linkage     : payload work_id / n / marker corruption -> structure FAIL
//   P4 rotation    : deterministic (same tail -> same index), bounded
//                    (index < pool), and genuinely rotating (24 synthetic
//                    epoch tails spread over a 5-claim pool, >= 2 distinct)
//   P5 zero state  : empty pool -> index 0, no-op
#include <hsma/verifier.hpp>
#include <cstdio>
#include <cstdint>
#include <vector>
using namespace hsma;

static std::vector<std::uint8_t> le64(std::uint64_t v) {
    std::vector<std::uint8_t> out(8);
    for (int b = 0; b < 8; ++b) out[(std::size_t)b] = (std::uint8_t)(v >> (8 * b));
    return out;
}

// build a genuine ingested+verified work record the way the node holds it
static explorer::WorkItem make_work(std::uint64_t id, unsigned n) {
    explorer::WorkItem w{};
    w.id = id;
    w.n = n;
    w.status = explorer::WorkStatus::DONE;
    w.verified = true;
    w.has_inputs = true;
    w.A_in.resize((std::size_t)n * n);
    w.B_in.resize((std::size_t)n * n);
    for (unsigned k = 0; k < n * n; ++k) {
        w.A_in[k] = fp::fe_from_u64((std::uint64_t)(k % 250) + 1 + id);
        w.B_in[k] = fp::fe_from_u64((std::uint64_t)(k % 13) + 1 + id);
    }
    // ic = SHA256(le(A) || le(B)) — byte-exact with the ingestion commitment
    std::vector<std::uint8_t> cat((std::size_t)2 * n * n * 32);
    for (unsigned k = 0; k < n * n; ++k) {
        fp::fe_to_le_bytes(w.A_in[k], reinterpret_cast<std::byte*>(cat.data() + (std::size_t)k * 32));
        fp::fe_to_le_bytes(w.B_in[k], reinterpret_cast<std::byte*>(
            cat.data() + ((std::size_t)n * n + k) * 32));
    }
    digest::sha256(cat.data(), cat.size(), w.ic.data());
    // result: the real GEMM, canonical-LE — byte-exact with the 6.12 serializer
    std::vector<fp::fe> C((std::size_t)n * n);
    pouw::gemm(w.A_in.data(), w.B_in.data(), C.data(), n);
    w.has_result = true;
    w.result_bytes.reserve(C.size() * 32);
    for (const auto& fe : C) {
        std::uint8_t ob[32];
        fp::fe_to_le_bytes(fe, reinterpret_cast<std::byte*>(ob));
        w.result_bytes.insert(w.result_bytes.end(), ob, ob + 32);
    }
    w.commitment_checked = true;
    return w;
}

// build the claim-decree payload exactly as the fold site (epoch_node.cpp) does
static std::vector<std::uint8_t> make_claim(const explorer::WorkItem& w) {
    std::vector<std::uint8_t> mat;
    auto p64 = [&](std::uint64_t v) { for (int b = 0; b < 8; ++b) mat.push_back((std::uint8_t)(v >> (8 * b))); };
    p64(w.id);
    p64(w.n);
    for (std::uint8_t b : w.ic) mat.push_back(b);
    mat.insert(mat.end(), w.result_bytes.begin(), w.result_bytes.begin() + 32);
    std::vector<std::uint8_t> pl(43);
    digest::sha256(mat.data(), mat.size(), pl.data());
    for (int b = 0; b < 8; ++b) pl[(std::size_t)(32 + b)] = (std::uint8_t)(w.id >> (8 * b));
    pl[40] = (std::uint8_t)((w.n >> 8) & 0xFF);
    pl[41] = (std::uint8_t)(w.n & 0xFF);
    pl[42] = 0xC1;
    return pl;
}

int main() {
    int fails = 0;
    auto chk = [&](bool ok, const char* what) {
        std::printf("[verifier-t52] %-58s %s\n", what, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    };

    // ---- P1: the genuine path, both tiers ----
    const explorer::WorkItem w = make_work(77, 8);
    const std::vector<std::uint8_t> pl = make_claim(w);
    const auto o = verifier::verify_claim(pl, w);
    chk(o.structure_ok, "P1 structure (43B + 0xC1 + id/n linkage)");
    chk(o.identity_ok, "P1 tier-1 identity re-derivation");
    chk(o.recompute_ran && o.recompute_ok, "P1 tier-2 full-GEMM recompute (fleet rung)");
    chk(o.pass, "P1 overall verdict PASS");
    {   // second record: the verifier is not keyed to one work id
        const explorer::WorkItem w2 = make_work(78, 16);
        const auto o2 = verifier::verify_claim(make_claim(w2), w2);
        chk(o2.pass, "P1 second record (n=16) PASS");
    }
    {   // tier-1 rederive matches the fold-site identity byte-for-byte
        std::uint8_t id2[32];
        verifier::rederive_identity(w, id2);
        chk(std::memcmp(id2, pl.data(), 32) == 0, "P1 rederive_identity == folded claim_id");
    }

    // ---- P2: tamper-evidence, tier separation ----
    {   explorer::WorkItem wt = w; wt.result_bytes[5] ^= 0x01;
        const auto ot = verifier::verify_claim(pl, wt);
        chk(!ot.identity_ok && !ot.pass, "P2 result flip: tier-1 FAIL");
        chk(ot.recompute_ran && !ot.recompute_ok, "P2 result flip: tier-2 FAIL");
    }
    {   explorer::WorkItem wt = w; wt.ic[0] ^= 0x01;
        const auto ot = verifier::verify_claim(pl, wt);
        chk(!ot.identity_ok && !ot.pass, "P2 ic flip: tier-1 FAIL (commitment binding)");
        chk(ot.recompute_ran && ot.recompute_ok, "P2 ic flip: tier-2 holds (A/B unchanged) — tiers separate");
    }

    // ---- P3: linkage / structure corruption ----
    {   auto p = pl; p[32] ^= 0x01;
        chk(!verifier::verify_claim(p, w).structure_ok, "P3 payload work_id corruption -> structure FAIL"); }
    {   auto p = pl; p[41] ^= 0x01;
        chk(!verifier::verify_claim(p, w).structure_ok, "P3 payload n corruption -> structure FAIL"); }
    {   auto p = pl; p[42] = 0xC2;
        chk(!verifier::verify_claim(p, w).structure_ok, "P3 marker corruption (0xC2) -> structure FAIL"); }

    // ---- P4: the rotation ----
    {   const std::array<std::uint64_t, 4> t{11, 22, 33, 44};
        chk(verifier::select_index(t, 5) == verifier::select_index(t, 5),
            "P4 determinism: same tail -> same index");
        chk(verifier::select_index(t, 5) < 5, "P4 bound: index < pool_size");
    }
    {   bool bounded = true;
        unsigned distinct_mask = 0;
        for (unsigned k = 1; k <= 24; ++k) {
            std::array<std::uint64_t, 4> t{k, 2 * k, 3 * k, 4 * k};   // synthetic epoch tails
            const std::size_t ix = verifier::select_index(t, 5);
            if (ix >= 5) bounded = false;
            distinct_mask |= (unsigned)(1u << ix);
        }
        unsigned distinct = 0;
        for (unsigned b = 0; b < 5; ++b) if (distinct_mask & (1u << b)) ++distinct;
        char buf[96];
        std::snprintf(buf, sizeof(buf), "P4 rotation walk: 24 epochs over pool 5 -> %u distinct indices", distinct);
        chk(bounded, "P4 rotation walk: all 24 indices < pool_size");
        chk(distinct >= 2, buf);
    }
    {   const std::array<std::uint64_t, 4> t{9, 9, 9, 9};
        chk(verifier::select_index(t, 0) == 0, "P5 empty pool -> index 0, no-op");
    }

    // ---- the end-to-end rotation: select then verify, the node's exact order ----
    {   std::vector<explorer::WorkItem> pool{make_work(201, 8), make_work(202, 8), make_work(203, 8)};
        std::vector<std::vector<std::uint8_t>> claims;
        for (const auto& wi : pool) claims.push_back(make_claim(wi));
        const std::array<std::uint64_t, 4> t{777, 888, 999, 1010};
        const std::size_t sel = verifier::select_index(t, claims.size());
        const auto os = verifier::verify_claim(claims[sel], pool[sel]);
        chk(os.pass, "E2E select->verify: the node's audit order verifies PASS");
    }

    std::printf("%s\n", "test_step52: DONE — the rotating epoch-verifier proven (CA-R370d: the sample moves with the beacon)");
    return fails;
}
