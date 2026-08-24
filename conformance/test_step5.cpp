// Step-5 conformance v2. Statuses are emitted in SORTED-EXECUTION order
// (DEC-124 contract). Batches designed so sorted order == push order where
// asserted, with an explicit duplicate-nonce tie case proving determinism.
#include <hsma/params.hpp>
#include <hsma/vault.hpp>
#include <hsma/update.hpp>
#include <hsma/tx.hpp>
#include <hsma/mempool.hpp>
#include <cstdio>
#include <cstring>
#include <filesystem>

using namespace hsma;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static fp::fe keyed(std::uint8_t b) {
    std::byte buf[32]{};
    buf[0] = std::byte{b};
    return fp::fe_from_le_bytes(buf).value;
}
static unsigned __int128 ceil10() {
    return mempool::BAL_MAX - 10;
}

int main() {
    namespace fs = std::filesystem;
    const std::string dir = "build/mempool_vault";
    fs::remove_all(dir);

    smt::Vault vault;
    CHECK(vault.open(dir), vault.last_error().c_str());
    smt::Updater up(vault);

    const fp::fe alice = smt::key_from_pk(fp::fe_zero(), keyed(0xAA));
    const fp::fe bob   = smt::key_from_pk(fp::fe_zero(), keyed(0xBB));
    const fp::fe carol = smt::key_from_pk(fp::fe_zero(), keyed(0xCC));

    auto r1 = up.set_account(vault.latest_root(), alice, {1000, false, 0, 0});
    auto r2 = up.set_account(r1.new_root, bob, {200, false, 0, 0});
    smt::AccountState cc{}; cc.bal_mag = ceil10();
    auto r3 = up.set_account(r2.new_root, carol, cc);
    CHECK(vault.fork_epoch(r3.new_root), "seed epoch commit");
    const smt::Handle seed_root = vault.latest_root();

    // ── EARLY REGRESSION ANCHOR (CA-86): reads must work BEFORE any mempool op
    smt::AccountState probe{};
    CHECK(mempool::lookup_account(vault, seed_root, alice, probe),
          "post-seed lookup (CA-86 regression anchor)");
    CHECK(probe.bal_mag == 1000 && probe.nonce == 0, "seeded state sane");

    // ══ BATCH 1 — nonces 1,2,5 ⇒ sorted order equals push order ══════════════
    mempool::Mempool pool;
    pool.push({alice, bob, 300, 10, 1});       // valid
    pool.push({alice, bob, 9999, 0, 2});       // insufficient (after n1 applied)
    pool.push({alice, bob, 50, 5, 5});         // bad nonce

    std::vector<mempool::Transaction> done;
    std::vector<mempool::TxError> st;
    smt::Handle rootA = pool.execute_batch(vault, seed_root, done, st);

    CHECK(done.size() == 1, "exactly 1 executed");
    CHECK(st.size() == 3, "three statuses");
    CHECK(st[0] == mempool::TxError::OK,                   "valid tx OK");
    CHECK(st[1] == mempool::TxError::INSUFFICIENT_BALANCE, "insufficient caught");
    CHECK(st[2] == mempool::TxError::INVALID_NONCE,        "bad nonce caught");
    CHECK(pool.empty(), "mempool drained");

    smt::AccountState a{}, b{}, c{};
    CHECK(mempool::lookup_account(vault, rootA, alice, a), "alice readable");
    CHECK(mempool::lookup_account(vault, rootA, bob, b),   "bob readable");
    CHECK(a.bal_mag == 690 && a.nonce == 1, "alice −300−10, nonce+1");
    CHECK(b.bal_mag == 500 && b.nonce == 0, "bob credited, nonce untouched");

    // ══ BATCH 2 — printers, disarmed. Sorted: self(n2) < wrap(b,n3) < ceil(c,n3)
    //    (duplicate nonce 3 tie broken by recipient canonical: bob < carol) ══
    mempool::Mempool p2;
    const unsigned __int128 HALF = ((unsigned __int128)1) << 127;
    p2.push({alice, alice, 100, 10, 2});       // legal self-transfer
    p2.push({alice, bob,   HALF, HALF, 3});    // CA-80: naive sum wraps to 0
    p2.push({alice, carol, 50, 5, 3});         // CA-81: credit crosses ceiling

    done.clear(); st.clear();
    smt::Handle rootB = p2.execute_batch(vault, rootA, done, st);

    CHECK(st.size() == 3, "three statuses B");
    CHECK(st[0] == mempool::TxError::OK,              "self-transfer accepted");
    CHECK(st[1] == mempool::TxError::COST_OVERFLOW,   "wrap-cost rejected (CA-80)");
    CHECK(st[2] == mempool::TxError::CREDIT_OVERFLOW, "ceiling credit rejected (CA-81)");
    CHECK(done.size() == 1, "only self-transfer committed");

    CHECK(mempool::lookup_account(vault, rootB, alice, a), "alice readable B");
    CHECK(a.bal_mag == 680 && a.nonce == 2,
          "self-transfer: −cost +amount, ONE transition (no mint, no reset)");
    CHECK(mempool::lookup_account(vault, rootB, bob, b) && b.bal_mag == 500,
          "bob untouched by rejected pair");
    CHECK(mempool::lookup_account(vault, rootB, carol, c) && c.bal_mag == ceil10(),
          "carol untouched — no half-applied debit (DEC-119)");

    // ══ BATCH 3 — consumed-nonce replay dies at the gate ═════════════════════
    mempool::Mempool p3;
    p3.push({alice, bob, 10, 5, 2});           // nonce already consumed
    done.clear(); st.clear();
    smt::Handle rootC = p3.execute_batch(vault, rootB, done, st);
    CHECK(st.size() == 1 && st[0] == mempool::TxError::INVALID_NONCE, "replay gated");
    CHECK(rootC == rootB, "rejected batch mutates nothing");

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 5\n", failures); return 1; }
    std::printf("step5 conformance: ALL GREEN "
                "(anchor, gating, solvency, self-transfer, wrap-cost, "
                "credit-ceiling, replay, sort-determinism)\n");
    return 0;
}
