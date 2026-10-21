// HSMA :: test_step53 - Phase 6.17 v2 s1.1: the faucet write-back (CA-R345).
// Properties under test:
//   P1 binding     : bind_faucet_inputs stores A/B byte-identical, sets
//                    has_inputs=true, and ic == SHA256(le(A)||le(B)) —
//                    independently recomputed here, not read from the helper
//   P2 gate        : the worker's swap gate (re-derive SHA256 over A_in/B_in,
//                    memcmp against ic) PASSES on bound faucet data — the one
//                    uniform commitment invariant for both mint paths
//   P3 satisfiab.  : faucet work through the REAL proof path (pouw::gemm +
//                    prove_gemm_v2 + verify_gemm_v2) satisfies the claim
//                    condition (has_inputs && verified) — pre-s1.1 this was
//                    structurally unsatisfiable: the s1 404 root cause
//   P4 identity    : the fold-site identity re-derivation (verifier tier-1)
//                    and the full tier-2 recompute PASS on faucet-bound claims
//                    — faucet work is now fully auditable by the s2 verifier
//   P5 served      : fe_to_le_bytes round-trip of A_in/B_in equals the exact
//                    PRNG values the proof consumed — byte-exact with what
//                    GET /claim_inputs serves
//   P6 queue-time  : an unprocessed faucet item still has has_inputs=false —
//                    the write-back happens at PICKUP, never at enqueue (the
//                    test_step46 queue-time contract is untouched)
//   P7 tamper      : ic flip kills tier-1 (commitment binding) while tier-2
//                    holds (A/B unchanged) — the s2 tier separation extends
//                    to faucet-bound claims
#include <hsma/verifier.hpp>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <vector>
using namespace hsma;

// the node's faucet PRNG, replica-exact (epoch_node.cpp):
// gseed = id*7919+13; xorshift64 (L13,R7,L17); value = state * golden-ratio.
static void faucet_prng(std::uint64_t id, unsigned n,
                        std::vector<fp::fe>& A, std::vector<fp::fe>& B,
                        std::vector<std::uint64_t>& Av, std::vector<std::uint64_t>& Bv) {
    std::uint64_t gst = id * 7919 + 13;
    auto rnd = [&gst]() -> std::uint64_t {
        gst ^= gst << 13; gst ^= gst >> 7; gst ^= gst << 17;
        return gst * 0x9E3779B97F4A7C15ull;
    };
    A.resize((std::size_t)n * n); B.resize((std::size_t)n * n);
    Av.resize((std::size_t)n * n); Bv.resize((std::size_t)n * n);
    for (std::size_t k = 0; k < (std::size_t)n * n; ++k) { Av[k] = rnd(); A[k] = fp::fe_from_u64(Av[k]); }
    for (std::size_t k = 0; k < (std::size_t)n * n; ++k) { Bv[k] = rnd(); B[k] = fp::fe_from_u64(Bv[k]); }
}

// the worker's swap gate, replica-exact (epoch_node.cpp 6.11b block)
static bool swap_gate(explorer::WorkItem& w) {
    const std::size_t an = w.A_in.size() * 32, bn = w.B_in.size() * 32;
    std::vector<std::uint8_t> cat(an + bn);
    for (std::size_t k = 0; k < w.A_in.size(); ++k)
        fp::fe_to_le_bytes(w.A_in[k], reinterpret_cast<std::byte*>(cat.data() + k * 32));
    for (std::size_t k = 0; k < w.B_in.size(); ++k)
        fp::fe_to_le_bytes(w.B_in[k], reinterpret_cast<std::byte*>(cat.data() + an + k * 32));
    std::uint8_t h[32];
    digest::sha256(cat.data(), cat.size(), h);
    w.commitment_checked = (std::memcmp(h, w.ic.data(), 32) == 0);
    return w.commitment_checked;
}

// the fold-site claim payload, replica-exact (test_step52's make_claim form)
static std::vector<std::uint8_t> make_claim(const explorer::WorkItem& w) {
    std::vector<std::uint8_t> mat;
    auto p64 = [&](std::uint64_t v) { for (int b = 0; b < 8; ++b) mat.push_back((std::uint8_t)(v >> (8 * b))); };
    p64(w.id); p64(w.n);
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
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
        if (!ok) ++fails;
    };
    const unsigned n = 8;

    // --- P6: queue-time honesty — pickup is where the write-back happens ---
    explorer::WorkItem w{};
    w.id = 1; w.n = n;
    w.status = explorer::WorkStatus::QUEUED;
    w.submitted_at = (std::uint64_t)time(nullptr);
    chk(!w.has_inputs, "P6 faucet item at queue time: has_inputs=false (write-back is at pickup)");

    // --- the pickup: generate (faucet PRNG), bind, gate ---
    std::vector<fp::fe> gA, gB; std::vector<std::uint64_t> Av, Bv;
    faucet_prng(w.id, n, gA, gB, Av, Bv);
    explorer::bind_faucet_inputs(w, gA, gB);

    // --- P1: the binding ---
    bool a_same = true, b_same = true;
    std::uint8_t ob[32];
    for (std::size_t k = 0; k < gA.size() && a_same; ++k) {
        fp::fe_to_le_bytes(w.A_in[k], reinterpret_cast<std::byte*>(ob));
        std::uint8_t gb[32]; std::memcpy(gb, &Av[k], 8);
        std::memset(gb + 8, 0, 24);
        a_same = (std::memcmp(ob, gb, 32) == 0) && (w.A_in[k] == gA[k]);
    }
    for (std::size_t k = 0; k < gB.size() && b_same; ++k)
        b_same = (w.B_in[k] == gB[k]);
    chk(w.has_inputs, "P1 bind sets has_inputs=true");
    chk(a_same, "P1 A_in carries the exact generated bytes (canonical LE == PRNG u64)");
    chk(b_same, "P1 B_in carries the exact generated elements");
    {   // independent ic recomputation (not via the helper's code path)
        std::vector<std::uint8_t> cat((std::size_t)2 * n * n * 32);
        for (unsigned k = 0; k < n * n; ++k) {
            fp::fe_to_le_bytes(gA[k], reinterpret_cast<std::byte*>(cat.data() + (std::size_t)k * 32));
            fp::fe_to_le_bytes(gB[k], reinterpret_cast<std::byte*>(
                cat.data() + ((std::size_t)n * n + k) * 32));
        }
        std::uint8_t h[32];
        digest::sha256(cat.data(), cat.size(), h);
        chk(std::memcmp(h, w.ic.data(), 32) == 0, "P1 ic == SHA256(le(A)||le(B)) independently recomputed");
    }

    // --- P2: the uniform swap gate ---
    chk(swap_gate(w) && w.commitment_checked, "P2 swap gate PASSES on bound faucet data");

    // --- P3: the REAL proof path over the bound data ---
    std::vector<fp::fe> gC((std::size_t)n * n);
    pouw::gemm(gA.data(), gB.data(), gC.data(), n);
    auto GPP = pouw::prove_gemm_v2(gA, gB, gC, n, n, n);
    bool gvok = pouw::verify_gemm_v2(GPP, gA, gB, gC);
    gvok = gvok && w.commitment_checked;   // the node's exact gvok law (has_inputs now true)
    w.status = gvok ? explorer::WorkStatus::DONE : explorer::WorkStatus::FAILED;
    w.verified = gvok;
    w.has_result = gvok;
    for (const auto& fe : gC) {
        fp::fe_to_le_bytes(fe, reinterpret_cast<std::byte*>(ob));
        w.result_bytes.insert(w.result_bytes.end(), ob, ob + 32);
    }
    chk(gvok && w.verified, "P3 faucet work VERIFIES with the commitment law enforced");
    chk(w.has_inputs && w.verified, "P3 claim condition (has_inputs && verified) SATISFIED — the s1 404 is dead");
    {   // the old world: an unbound faucet item can never satisfy the condition
        explorer::WorkItem old{};
        old.id = 2; old.n = n; old.verified = true;
        chk(!(old.has_inputs && old.verified),
            "P3 regression anchor: pre-s1.1 record (has_inputs=false) fails the claim condition");
    }

    // --- P4: the s2 verifier audits faucet-bound claims (both tiers) ---
    auto pl = make_claim(w);
    auto out = verifier::verify_claim(pl, w);
    chk(out.structure_ok && out.identity_ok, "P4 tier-1 identity re-derivation PASSES on faucet claim");
    chk(out.recompute_ran && out.recompute_ok, "P4 tier-2 full-GEMM recompute PASSES on faucet claim (n<=64 rung)");
    chk(out.pass, "P4 verify_claim PASS — faucet work is fully auditable");

    // --- P7: the tier separation extends to faucet-bound claims ---
    {   auto w2 = w;
        auto pl2 = pl;
        w2.ic[0] ^= 0x01;   // commitment tampered post-verification
        auto o2 = verifier::verify_claim(pl2, w2);
        chk(!o2.identity_ok, "P7 ic flip -> tier-1 FAILS (commitment binding)");
        chk(o2.recompute_ran && o2.recompute_ok, "P7 ic flip -> tier-2 still HOLDS (A/B unchanged)");
        chk(!o2.pass, "P7 tampered faucet claim REJECTED overall");
    }

    // --- P5: what /claim_inputs would serve is byte-exact ---
    {   bool serve_ok = true;
        for (std::size_t k = 0; k < w.A_in.size() && serve_ok; ++k) {
            fp::fe_to_le_bytes(w.A_in[k], reinterpret_cast<std::byte*>(ob));
            std::uint8_t pb[32]; std::memcpy(pb, &Av[k], 8); std::memset(pb + 8, 0, 24);
            serve_ok = (std::memcmp(ob, pb, 32) == 0);
        }
        chk(serve_ok && w.result_bytes.size() == (std::size_t)n * n * 32,
            "P5 served preimage (A_in LE bytes + result_bytes) is the exact proof material");
    }

    std::printf(fails ? "step53: %d FAIL\n" : "step53: ALL PASS (%d fails)\n", fails);
    return fails ? 1 : 0;
}
