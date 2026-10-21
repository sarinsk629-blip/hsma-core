// Step-15 conformance: the CCS constraint layer (DEC-208).
// Oracle: pure Python constraint trace (ccs_golden.hpp).
#include <hsma/ccs.hpp>
#include <hsma/fold.hpp>
#include "fold_golden.hpp"
#include "ccs_golden.hpp"
#include <cstdio>
#include <filesystem>

using namespace hsma;
static bool feq(const fp::fe& a, const std::uint64_t g[4]) {
    auto c = fp::fe_to_canonical(a);
    return c.l[0] == g[0] && c.l[1] == g[1] && c.l[2] == g[2] && c.l[3] == g[3];
}

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static fp::fe gfe(const std::uint64_t g[4]) {
    std::array<std::uint64_t, 4> c{g[0], g[1], g[2], g[3]};
    return fp::fe_from_canonical_limbs(c);
}
static fold::DecreeEntry gent(unsigned i) {
    const auto& e = golden::G14F_ENT[i];
    fold::DecreeEntry r;
    r.sender_key = gfe(&e[0]); r.recipient_key = gfe(&e[4]);
    r.amount = ((unsigned __int128)e[9] << 64) | e[8];
    r.fee = ((unsigned __int128)e[11] << 64) | e[10];
    r.nonce = (std::uint64_t)e[12];
    r.status = (fold::Status)e[13];
    r.pt_hash = gfe(&e[14]);
    return r;
}

int main() {
    namespace fsys = std::filesystem;

    // 1. Set up the vault with the initial accounts (the fold machinery)
    const std::string dir = "build/test_ccs";
    fsys::remove_all(dir);
    smt::Vault vault;
    CHECK(vault.open(dir), "vault open");
    smt::Updater init(vault);
    smt::Handle root = smt::HEMPTY;
    for (unsigned i = 0; i < 3; ++i) {
        const auto& a = golden::G14F_ACC[i];
        smt::AccountState st{};
        st.bal_mag = ((unsigned __int128)a[5] << 64) | a[4];
        st.nonce = (std::uint64_t)a[6]; st.flags = 0;
        root = init.set_account(root, gfe(&a[0]), st).new_root;
    }

    // 2. Process entries, evaluate constraints, check the golden
    fold::FoldState fs{root, fold::f_head(gfe(golden::G14F_PREV), gfe(golden::G14F_DECREE))};
    unsigned total = 0;
    for (unsigned i = 0; i < 6; ++i) {
        fold::DecreeEntry e = gent(i);
        smt::AccountState s{};
        if (e.status != fold::Status::PAD)
            mempool::lookup_account(vault, fs.state_root, e.sender_key, s);
        const auto ec = ccs::evaluate(e, s);
        CHECK(ec.count == golden::G15F_TRACE[i], "G15F constraint count");
        CHECK(ec.all_satisfied, "G15F all satisfied");
        total += ec.count;
        // also run the fold (state + digest update)
        fold::f_exec(vault, fs, e);
    }
    CHECK(total == golden::G15F_TOTAL, "G15F total constraints");
    std::printf("[dbg] total=%u golden=%u\n", total, golden::G15F_TOTAL);
    CHECK(feq(fs.digest, golden::G14F_STEP[5]), "G15F fold digest still correct (Step-14 integration)");

    // 3. Adversarial traces: each violates exactly one named constraint
    {   // binding violation
        fold::DecreeEntry bad = gent(0);
        bad.pt_hash = fp::fe_from_u64(1);  // wrong hash
        smt::AccountState s{};
        mempool::lookup_account(vault, root, bad.sender_key, s);
        const auto ec = ccs::evaluate(bad, s);
        CHECK(!ec.all_satisfied, "G15F binding VIOLATED");
        CHECK(!ccs::check_binding(bad), "G15F check_binding directly");
    }
    {   // nonce violation
        fold::DecreeEntry bad = gent(0);
        bad.nonce = 99;
        bad.pt_hash = fold::pt_hash_of(bad.amount, bad.fee, 99);  // re-bind
        smt::AccountState s{};
        mempool::lookup_account(vault, root, bad.sender_key, s);
        const auto ec = ccs::evaluate(bad, s);
        CHECK(!ec.all_satisfied, "G15F nonce VIOLATED");
        CHECK(!ccs::check_nonce(bad, s), "G15F check_nonce directly");
    }
    {   // LT gate violation (insolvent EXEC)
        fold::DecreeEntry bad = gent(4);  // the insolvent entry
        bad.status = fold::Status::EXEC;   // forced to EXEC
        smt::AccountState s{};
        mempool::lookup_account(vault, root, bad.sender_key, s);
        const auto ec = ccs::evaluate(bad, s);
        CHECK(!ec.all_satisfied, "G15F LT gate VIOLATED (insolvent EXEC)");
        CHECK(!ccs::check_lt(bad, s), "G15F check_lt directly");
    }

    // 4. The PC matrix SAT-proof
    unsigned valid = 0, invalid = 0;
    for (unsigned f = 0; f < 3; ++f)
        for (unsigned t = 0; t < 3; ++t)
            if (ccs::pc_valid(static_cast<ccs::Step>(f), static_cast<ccs::Step>(t)))
                valid++;
            else
                invalid++;
    CHECK(valid == golden::G15F_VALID_PC, "G15F PC valid count");
    CHECK(invalid == golden::G15F_INVALID_PC, "G15F PC invalid count");
    CHECK(ccs::pc_valid(ccs::Step::HEAD, ccs::Step::EXEC), "PC HEAD→EXEC valid");
    CHECK(ccs::pc_valid(ccs::Step::EXEC, ccs::Step::CLOSE), "PC EXEC→CLOSE valid");
    CHECK(ccs::pc_valid(ccs::Step::HEAD, ccs::Step::CLOSE), "PC HEAD→CLOSE valid (empty)");
    CHECK(!ccs::pc_valid(ccs::Step::CLOSE, ccs::Step::EXEC), "PC CLOSE→EXEC unsat");
    CHECK(!ccs::pc_valid(ccs::Step::EXEC, ccs::Step::HEAD), "PC EXEC→HEAD unsat");
    CHECK(!ccs::pc_valid(ccs::Step::CLOSE, ccs::Step::CLOSE), "PC CLOSE→CLOSE unsat");

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 15\n", failures); return 1; }
    std::printf("step15 conformance: ALL GREEN (constraint trace x%u, binding+nonce+lt direct, "
                "PC matrix %u valid / %u unsat)\n", total, valid, invalid);
    return 0;
}
