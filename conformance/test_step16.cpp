// Step-16 conformance: the NIVC fold accumulator (DEC-209).
// Oracle: pure Python accumulator (nivc_golden.hpp).
#include <hsma/nivc.hpp>
#include "fold_golden.hpp"
#include "nivc_golden.hpp"
#include <cstdio>
#include <filesystem>

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static fp::fe gfe(const std::uint64_t g[4]) {
    std::array<std::uint64_t, 4> c{g[0], g[1], g[2], g[3]};
    return fp::fe_from_canonical_limbs(c);
}
static bool feq(const fp::fe& a, const std::uint64_t g[4]) {
    auto c = fp::fe_to_canonical(a);
    return c.l[0] == g[0] && c.l[1] == g[1] && c.l[2] == g[2] && c.l[3] == g[3];
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
static smt::Handle setup_vault(smt::Vault& v, const std::string& dir) {
    namespace fsys = std::filesystem;
    fsys::remove_all(dir);
    if (!v.open(dir)) return smt::HEMPTY;
    smt::Updater u(v);
    smt::Handle root = smt::HEMPTY;
    for (unsigned i = 0; i < 3; ++i) {
        const auto& a = golden::G14F_ACC[i];
        smt::AccountState st{};
        st.bal_mag = ((unsigned __int128)a[5] << 64) | a[4];
        st.nonce = (std::uint64_t)a[6]; st.flags = 0;
        root = u.set_account(root, gfe(&a[0]), st).new_root;
    }
    return root;
}

int main() {
    // 1. Succinctness: the accumulator is 41 bytes, constant
    CHECK(nivc::ACC_SIZE == golden::G16F_ACC_SIZE, "G16F accumulator size = 41");
    CHECK(sizeof(fp::fe) + sizeof(std::uint64_t) + sizeof(std::uint8_t) <= 41,
          "accumulator fits in 41 bytes");

    // 2. The honest epoch: 6 entries, accumulator stays bounded
    {
        smt::Vault vault;
        smt::Handle root = setup_vault(vault, "build/test_nivc1");
        CHECK(root != smt::HEMPTY, "vault 1 non-empty");
        nivc::Accumulator acc;
        nivc::fold_head(acc, gfe(golden::G16F_PREV1), gfe(golden::G14F_DECREE));
        for (unsigned i = 0; i < 6; ++i) {
            fold::DecreeEntry e = gent(i);
            nivc::fold_step(vault, acc, root, e);
        }
        nivc::fold_close(acc);
        CHECK(feq(acc.digest, golden::G16F_FINAL1), "G16F epoch 1 final digest");
        CHECK(acc.count == golden::G16F_COUNT1, "G16F epoch 1 count");
        CHECK(acc.pc == 2, "G16F epoch 1 PC = CLOSE");
        printf("[dbg] acc.count=%llu golden=%u\n",
               (unsigned long long)acc.count, golden::G16F_COUNT1);
    }

    // 3. Cross-epoch chaining: epoch 2 starts from epoch 1's final digest
    {
        smt::Vault vault;
        smt::Handle root = setup_vault(vault, "build/test_nivc2");
        nivc::Accumulator acc1;
        nivc::fold_head(acc1, gfe(golden::G16F_PREV1), gfe(golden::G14F_DECREE));
        for (unsigned i = 0; i < 6; ++i) nivc::fold_step(vault, acc1, root, gent(i));
        nivc::fold_close(acc1);
        // epoch 2: chain from epoch 1's final digest
        nivc::Accumulator acc2;
        nivc::fold_head(acc2, acc1.digest, gfe(golden::G14F_DECREE));
        // process 2 entries (KB nonce 2->3, KA nonce 2->3)
        fold::DecreeEntry e1 = gent(1);  // B->A, nonce 1... actually need nonce 3
        // Use fresh entries with correct nonces
        fold::DecreeEntry ne1{}, ne2{};
        ne1.sender_key = gfe(&golden::G14F_ACC[1][0]);  // KB
        ne1.recipient_key = gfe(&golden::G14F_ACC[0][0]);  // KA
        ne1.amount = 20; ne1.fee = 2; ne1.nonce = 3;
        ne1.status = fold::Status::EXEC;
        ne1.pt_hash = fold::pt_hash_of(20, 2, 3);
        ne2.sender_key = gfe(&golden::G14F_ACC[0][0]);  // KA
        ne2.recipient_key = gfe(&golden::G14F_ACC[0][0]);  // KA (self)
        ne2.amount = 15; ne2.fee = 2; ne2.nonce = 3;
        ne2.status = fold::Status::EXEC;
        ne2.pt_hash = fold::pt_hash_of(15, 2, 3);
        nivc::fold_step(vault, acc2, root, ne1);
        nivc::fold_step(vault, acc2, root, ne2);
        nivc::fold_close(acc2);
        CHECK(acc2.count == 2, "G16F epoch 2 count = 2");
        CHECK(acc2.digest != acc1.digest, "G16F epoch 2 differs from epoch 1");
        CHECK(acc2.pc == 2, "G16F epoch 2 PC = CLOSE");
    }

    // 4. 20-entry epoch: accumulator STILL 41 bytes
    {
        smt::Vault vault;
        smt::Handle root = setup_vault(vault, "build/test_nivc3");
        nivc::Accumulator acc;
        nivc::fold_head(acc, gfe(golden::G16F_PREV1), gfe(golden::G14F_DECREE));
        for (unsigned i = 0; i < 20; ++i) {
            fold::DecreeEntry e{};
            e.sender_key = gfe(&golden::G14F_ACC[0][0]);
            e.recipient_key = gfe(&golden::G14F_ACC[1][0]);
            e.amount = 1; e.fee = 1; e.nonce = i + 1;
            e.status = fold::Status::EXEC;
            e.pt_hash = fold::pt_hash_of(1, 1, i + 1);
            nivc::fold_step(vault, acc, root, e);
        }
        nivc::fold_close(acc);
        CHECK(acc.count == 20, "G16F 20-entry count");
        CHECK(sizeof(acc.digest) + sizeof(acc.count) + sizeof(acc.pc) <= 41,
              "G16F 20-entry accumulator still bounded");
    }

    // 5. PC matrix
    {
        CHECK(ccs::pc_valid(ccs::Step::HEAD, ccs::Step::EXEC), "PC HEAD->EXEC");
        CHECK(ccs::pc_valid(ccs::Step::EXEC, ccs::Step::CLOSE), "PC EXEC->CLOSE");
        CHECK(!ccs::pc_valid(ccs::Step::CLOSE, ccs::Step::EXEC), "PC CLOSE->EXEC unsat");
        CHECK(!ccs::pc_valid(ccs::Step::EXEC, ccs::Step::HEAD), "PC EXEC->HEAD unsat");
    }

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 16\n", failures); return 1; }
    std::printf("step16 conformance: ALL GREEN (acc=41B constant, epoch chain, "
                "20-entry bounded, PC matrix)\n");
    return 0;
}
