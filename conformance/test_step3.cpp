// Step-3 conformance: C++ Poseidon vs Python-bigint reference. Cross-language
// equality simultaneously proves: permutation correctness, Montgomery
// conversion fidelity, IV derivation parity, registry synchronization.
#include <hsma/params.hpp>
#include <hsma/fe.hpp>
#include <hsma/poseidon.hpp>
#include "poseidon_golden.hpp"
#include <cstdio>
#include <cstring>

using namespace hsma;
using fp::fe;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static fe canon_to_mont(const std::uint64_t v[4]) {
    fe c{}; std::memcpy(c.l.data(), v, 32);
    // canonical → Montgomery via the DEC-105 parse path
    std::byte buf[32]; std::memcpy(buf, v, 32);
    auto r = fp::fe_from_le_bytes(buf);
    return r.ok ? r.value : c /* unreachable on generator data */;
}
static bool same_canon(const fe& mont, const std::uint64_t canon[4]) {
    std::byte buf[32];
    fp::fe_to_le_bytes(mont, buf);
    return std::memcmp(buf, canon, 32) == 0;
}

int main() {
    // 1. IV derivation parity — every registered tag, against reference
    for (const auto& ic : golden::IV_CASES) {
        CHECK(same_canon(fp::iv_of(static_cast<dom::Dom>(ic.tag)), ic.canon),
              "iv_of parity");
    }
    // 2. Fixed-path poseidon3 — 48 triples
    for (const auto& tc : golden::P3_CASES) {
        const fe out = fp::poseidon3(static_cast<dom::Dom>(tc.tag),
                                     canon_to_mont(tc.l), canon_to_mont(tc.r));
        CHECK(same_canon(out, tc.out), "poseidon3 parity");
    }
    // 3. Sponge — variable-length vectors (incl. empty input edge)
    for (const auto& sc : golden::SPONGE_CASES) {
        fp::Sponge sp{static_cast<dom::Dom>(sc.tag)};
        if (sc.n > 0) sp.absorb(canon_to_mont(sc.a));
        if (sc.n > 1) sp.absorb(canon_to_mont(sc.b));
        for (unsigned k = 2; k < sc.n; ++k) sp.absorb(fp::fe_from_u64(k));
        CHECK(same_canon(sp.squeeze(), sc.out), "sponge parity");
    }
    // 4. Domain separation sanity: all IVs pairwise distinct (field-exact)
    for (std::size_t i = 0; i < dom::TAG_NAMES.size(); ++i)
        for (std::size_t j = i + 1; j < dom::TAG_NAMES.size(); ++j)
            CHECK(fp::iv_of(static_cast<dom::Dom>(i)) !=
                  fp::iv_of(static_cast<dom::Dom>(j)),
                  "IV collision");
    // 5. Fixed-path ≡ sponge on the canonical 2-element call shape? — NO by
    //    design (finalize adds count+ONE). This CHECK documents intent:
    //    divergence between the two APIs on equal input is EXPECTED, not a bug.
    const fe fast = fp::poseidon3(dom::Dom::IV_STATE_NODE,
                                  fp::fe_from_u64(7), fp::fe_from_u64(9));
    fp::Sponge sp{dom::Dom::IV_STATE_NODE};
    sp.absorb(fp::fe_from_u64(7)); sp.absorb(fp::fe_from_u64(9));
    CHECK(!(sp.squeeze() == fast), "API separation documented");

    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step3 conformance: ALL GREEN (%zu IVs, 48 perms, %zu sponge cases)\n",
                golden::IV_CASES.size(), golden::SPONGE_CASES.size());
    return 0;
}
