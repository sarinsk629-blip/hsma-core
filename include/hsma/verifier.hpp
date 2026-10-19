// HSMA :: verifier.hpp - Phase 6.17 v2 s2 (CA-R370d): the rotating epoch-verifier.
//
// s1 (c134379) served the claim preimage — GET /claim_inputs/{id} — so that
// epoch-verifiers CAN independently re-verify a claim. s2 closes the loop:
// the node itself becomes an epoch-verifier whose deep-audit sample ROTATES
// with the epoch beacon. g_epoch_claims is the natural feed.
//
// Two tiers per selected claim:
//   tier-1 identity  — re-derive the claim's cryptographic identity
//       claim_id = SHA256(le64(id) || le64(n) || ic || result[0..32))
//     byte-exact with the fold site in epoch_node.cpp (the put64 LE form).
//     Binds work_id, matrix size, the input commitment AND the result prefix —
//     any tampering with any of them breaks the derivation.
//   tier-2 recompute — full GEMM C' = A x B via pouw::gemm, canonical-LE
//     serialization, byte-compare against result_bytes. Runs when AFFORDABLE:
//     the fleet-verifiable rung n <= 64 (the 6.16 verdict). GPU nodes extend
//     naturally (gemm dispatches to the CUDA backend when present); above the
//     rung the receipt honestly labels the audit digest-tier ("recompute n/a").
//
// Rotation: select_index() mixes the CURRENT epoch's digest tail with the
// VERIFIER domain tag — deliberately distinct from the epoch-PoUW seed on the
// same tail, so the two samplings are independent (CA-R90: float-free, the
// xorshift64* house PRNG). Fresh tail + fresh pool each epoch (the pool is
// cleared at epoch completion) means the sample auto-rotates: no permanent
// verifier, no permanent sample, nothing to bribe twice the same way.
#pragma once
#include <hsma/explorer.hpp>   // WorkItem + field/pouw/digest deps (already wired)
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace hsma::verifier {

// "VERIFIER" as a u64 big-endian ASCII pack — the s2 domain separator.
static constexpr std::uint64_t VERIFIER_DOMAIN = 0x5645524946494552ull;

struct Outcome {
    bool structure_ok = false;    // 43B contract + 0xC1 marker + id/n linkage vs w
    bool identity_ok = false;     // tier-1: claim_id re-derivation byte-exact
    bool recompute_ran = false;   // tier-2 ran (preimage present + fleet rung)
    bool recompute_ok = false;    // tier-2: C' canonical-LE byte-identical
    bool pass = false;            // structure && identity && (recompute ? ok : true)
    std::uint64_t work_id = 0;
    unsigned n = 0;
    std::uint8_t identity[32] = {};   // the re-derived claim identity (hex-served)
};

// tier-1: re-derive the claim identity from the work record. Byte-exact with
// the fold site: put64 is LITTLE-endian (v >> (8*b)), n rides as le64 (not the
// be16 form used in the decree payload — the two layouts are fold-site law).
inline bool rederive_identity(const explorer::WorkItem& w, std::uint8_t out[32]) noexcept {
    if (!w.has_inputs || w.result_bytes.size() < 32) return false;
    std::vector<std::uint8_t> mat;
    mat.reserve(8 + 8 + 32 + 32);
    auto put64 = [&](std::uint64_t v) {
        for (int b = 0; b < 8; ++b) mat.push_back((std::uint8_t)(v >> (8 * b)));
    };
    put64(w.id);
    put64(w.n);
    for (std::uint8_t b : w.ic) mat.push_back(b);
    mat.insert(mat.end(), w.result_bytes.begin(), w.result_bytes.begin() + 32);
    digest::sha256(mat.data(), mat.size(), out);
    return true;
}

// tier-2: full GEMM recompute + canonical-LE byte compare over the WHOLE
// result (stronger than tier-1's 32-byte prefix). Affordability gate is the
// caller's — this function assumes the preimage is present and sized.
inline bool recompute_matches(const explorer::WorkItem& w) noexcept {
    const unsigned n = (unsigned)w.n;
    if (n == 0 || w.A_in.size() != (std::size_t)n * n || w.B_in.size() != (std::size_t)n * n
        || w.result_bytes.size() != (std::size_t)n * n * 32) return false;
    std::vector<fp::fe> C((std::size_t)n * n);
    pouw::gemm(w.A_in.data(), w.B_in.data(), C.data(), n);
    std::vector<std::uint8_t> ob(32);
    for (std::size_t k = 0; k < C.size(); ++k) {
        fp::fe_to_le_bytes(C[k], reinterpret_cast<std::byte*>(ob.data()));
        if (std::memcmp(ob.data(), w.result_bytes.data() + k * 32, 32) != 0) return false;
    }
    return true;
}

// the full two-tier verification of ONE claim payload against its work record.
// Never throws, never allocates unbounded: the only allocation is tier-1's
// 80-byte material and tier-2's C matrix (fleet rung => <= 128KB).
inline Outcome verify_claim(const std::vector<std::uint8_t>& pl,
                            const explorer::WorkItem& w) noexcept {
    Outcome o;
    o.work_id = w.id;
    o.n = (unsigned)w.n;
    // structure: the 43-byte contract, the 0xC1 marker, and the linkage —
    // the payload's work_id/n must name THIS work record.
    if (pl.size() >= 43 && pl[42] == 0xC1) {
        std::uint64_t pid = 0;
        for (int b = 0; b < 8; ++b) pid |= (std::uint64_t)pl[32 + b] << (8 * b);
        const unsigned pn = ((unsigned)pl[40] << 8) | (unsigned)pl[41];
        o.structure_ok = (pid == w.id && pn == (unsigned)w.n);
    }
    if (o.structure_ok) {
        std::uint8_t id2[32];
        if (rederive_identity(w, id2)) {
            std::memcpy(o.identity, id2, 32);
            o.identity_ok = (std::memcmp(id2, pl.data(), 32) == 0);
        }
        // tier-2 affordability: the fleet rung (n <= 64, the 6.16 verdict) and
        // the full preimage present. Above the rung: digest-tier, honestly
        // labeled via recompute_ran=false.
        if (w.n <= 64 && w.A_in.size() == (std::size_t)w.n * w.n
            && w.B_in.size() == (std::size_t)w.n * w.n
            && w.result_bytes.size() == (std::size_t)w.n * w.n * 32) {
            o.recompute_ran = true;
            o.recompute_ok = recompute_matches(w);
        }
    }
    o.pass = o.structure_ok && o.identity_ok && (!o.recompute_ran || o.recompute_ok);
    return o;
}

// the rotation: deterministic verifier selection from epoch beacon material.
// Same tail + same pool => same index (auditable, reproducible); a new epoch's
// tail moves the sample. Modulo bias is irrelevant at testnet pool sizes and
// the mapping is public by design — the schedule must be RE-DERIVABLE by any
// fleet member from the chain, which is the point.
inline std::size_t select_index(const std::array<std::uint64_t, 4>& epoch_tail,
                                std::size_t pool_size) noexcept {
    if (pool_size == 0) return 0;
    std::uint64_t st = VERIFIER_DOMAIN;
    for (int k = 0; k < 4; ++k) st = st * 0x9E3779B97F4A7C15ull + epoch_tail[k];
    st ^= st << 13; st ^= st >> 7; st ^= st << 17;   // xorshift64* (CA-R90)
    return (std::size_t)((st * 0x9E3779B97F4A7C15ull)
                         % (std::uint64_t)pool_size);
}

} // namespace hsma::verifier
