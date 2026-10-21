#include <hsma/params.hpp>
#include <hsma/vault.hpp>
#include <hsma/update.hpp>
#include "smt_golden.hpp"
#include <cstdio>
#include <cstring>
#include <filesystem>

using namespace hsma;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static fp::fe mkfe(const std::uint64_t v[4]) {
    std::byte b[32]; std::memcpy(b, v, 32);
    return fp::fe_from_le_bytes(b).value;
}
static bool fe_eq(fp::fe mont, const std::uint64_t canon[4]) {
    const fp::fe c = fp::fe_to_canonical(mont);
    return std::memcmp(c.l.data(), canon, 32) == 0;
}
static bool root_is(const smt::Vault& v, smt::Handle h, const std::uint64_t canon[4]) {
    if (h == smt::HEMPTY) return false;
    const smt::Entry* e = v.deref(h);
    if (!e) return false;
    return fe_eq(smt::Vault::entry_hash(*e), canon);
}

int main() {
    namespace fs = std::filesystem;
    const std::string dir = "build/test_vault";
    fs::remove_all(dir);

    const auto& G = golden::SMT_SCENARIO;

    const fp::fe keyA = smt::key_from_pk(mkfe(G.pkA0), mkfe(G.pkA1));
    const fp::fe keyB = smt::key_from_pk(mkfe(G.pkB0), mkfe(G.pkB1));
    CHECK(fe_eq(keyA, G.keyA), "keyA derivation");
    CHECK(fe_eq(keyB, G.keyB), "keyB derivation");

    smt::Vault vault;
    CHECK(vault.open(dir), vault.last_error().c_str());
    const auto& ET = vault.empty_table();
    CHECK(fe_eq(ET[0], G.E0), "empty leaf anchor");
    CHECK(fe_eq(ET[1], G.E1), "empty height-1 anchor");
    CHECK(fe_eq(ET[2], G.E2), "empty height-2 anchor");

    auto state_of = [&](const std::uint64_t w[4]) {
        const fp::fe packed = mkfe(w);
        const smt::AccountState st = smt::unpack_payload(packed);
        bool ok = false;
        CHECK((smt::pack_payload(st, &ok) == packed) && ok, "pack round-trip");
        return st;
    };
    const auto A0 = state_of(G.packA0), B0 = state_of(G.packB0);
    const auto A1 = state_of(G.packA1), B1 = state_of(G.packB1);

    smt::Updater up{vault};

    auto r1 = up.set_account(vault.latest_root(), keyA, A0);
    CHECK(!r1.stats.noop && !r1.stats.fault, "insert A clean");
    CHECK(r1.stats.total() == G.allocInsA, "alloc parity A");
    CHECK(root_is(vault, r1.new_root, G.rootA), "root after A");

    auto r2 = up.set_account(r1.new_root, keyB, B0);
    CHECK(r2.stats.total() == G.allocInsB, "alloc parity B");
    CHECK(root_is(vault, r2.new_root, G.rootAB), "root after B");

    auto r3 = up.set_account(r2.new_root, keyA, A1);
    CHECK(r3.stats.total() == G.allocTxA, "alloc parity Tx-A");
    CHECK(root_is(vault, r3.new_root, G.rootA1), "root after A-debit");

    auto r4 = up.set_account(r3.new_root, keyB, B1);
    CHECK(r4.stats.total() == G.allocTxB, "alloc parity Tx-B");
    CHECK(root_is(vault, r4.new_root, G.rootTX), "root after transfer");

    auto r5 = up.set_account(r4.new_root, keyA, A1);
    CHECK(r5.stats.noop && r5.stats.total() == G.allocNoop &&
          r5.new_root == r4.new_root, "no-op detection");

    CHECK(vault.fork_epoch(r4.new_root), "epoch fork commit");

    // DEC-134: proofs verify against the RAW DIGEST — no fe, no conversions,
    // no domain costumes. G.proofRoot IS the boundary representation.
    smt::Prover pv{vault};

    auto pa = pv.open(r4.new_root, keyA);
    CHECK(pa.occupied == bool(G.proofOccupied), "proof occupancy");
    CHECK(smt::verify_opening(G.proofRoot, keyA, &A1, pa), "opening A verifies");
    auto pb = pv.open(r4.new_root, keyB);
    CHECK(smt::verify_opening(G.proofRoot, keyB, &B1, pb), "opening B verifies");

    smt::AccountState forged = A1; forged.bal_mag += 1;
    CHECK(!smt::verify_opening(G.proofRoot, keyA, &forged, pa),
          "forged payload rejected");
    smt::OpeningProof junk{};
    junk.occupied = true; junk.leaf_hash = pa.leaf_hash;
    junk.sib[0] = fp::fe_zero();
    for (int q = 1; q < int(params::SMT_DEPTH); ++q) junk.sib[q] = pa.sib[q];
    CHECK(!smt::verify_opening(G.proofRoot, keyA, &A1, junk),
          "tampered sibling rejected");

    { smt::Vault v2; CHECK(v2.open(dir), v2.last_error().c_str());
      CHECK(v2.latest_root() == r4.new_root, "reopen preserves committed root"); }

    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step4 conformance: ALL GREEN "
                "(keys, anchors, 4 roots, alloc parity, no-op, fork, proofs+forgery, reopen)\n");
    return 0;
}
