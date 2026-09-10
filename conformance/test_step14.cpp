// Step-14 conformance: the fold step family (DEC-207).
// Oracle: pure Python fold semantics (fold_golden.hpp).
#include <hsma/fold.hpp>
#include "fold_golden.hpp"
#include <cstdio>
#include <filesystem>
#include <cstring>

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
static bool acq(const smt::AccountState& s, const std::uint64_t g[8]) {
    return s.bal_mag == (((unsigned __int128)g[5] << 64) | g[4])
        && s.nonce == g[6] && s.bal_sign == false;
}
static fold::DecreeEntry gent(unsigned i) {
    const auto& e = golden::G14F_ENT[i];
    fold::DecreeEntry r;
    r.sender_key   = gfe(&e[0]);
    r.recipient_key = gfe(&e[4]);
    r.amount = ((unsigned __int128)e[9] << 64) | e[8];
    r.fee    = ((unsigned __int128)e[11] << 64) | e[10];
    r.nonce   = (std::uint64_t)e[12];
    r.status  = (fold::Status)e[13];
    r.pt_hash = gfe(&e[14]);
    return r;
}

int main() {
    // 1. build the initial state from the golden
    namespace fsys = std::filesystem;
    const std::string dir = "build/test_fold";
    std::filesystem::remove_all(dir);
    smt::Vault vault;
    CHECK(vault.open(dir), "vault open");
    smt::Updater init(vault);
    smt::Handle root = smt::HEMPTY;
    for (unsigned i = 0; i < 3; ++i) {
        const auto& a = golden::G14F_ACC[i];
        smt::AccountState st{};
        st.bal_mag = (((unsigned __int128)a[5] << 64) | a[4]);
        st.nonce = (std::uint64_t)a[6];
        st.flags = 0;
        auto rs = init.set_account(root, gfe(&a[0]), st);
        CHECK(!rs.stats.fault, "initial set_account");
        root = rs.new_root;
    }
    CHECK(root != smt::HEMPTY, "state non-empty");

    // 2. F_head
    fold::FoldState fs{root, fold::f_head(gfe(golden::G14F_PREV), gfe(golden::G14F_DECREE))};
    CHECK(feq(fs.digest, golden::G14F_HEAD), "G14F head digest");

    // 3. F_exec x 6 (the golden trace)
    for (unsigned i = 0; i < 6; ++i) {
        fold::DecreeEntry e = gent(i);
        const auto v = fold::f_exec(vault, fs, e);
        CHECK(static_cast<unsigned>(v) == golden::G14F_RES[i], "G14F verdict");
        CHECK(feq(fs.digest, golden::G14F_STEP[i]), "G14F step digest");
        { auto c = fp::fe_to_canonical(fs.digest);
          std::printf("[dig] e%u: %016llx%016llx%016llx%016llx vs %016llx%016llx%016llx%016llx\n",
            i, (unsigned long long)c.l[3],(unsigned long long)c.l[2],(unsigned long long)c.l[1],(unsigned long long)c.l[0],
            (unsigned long long)golden::G14F_STEP[i][3],(unsigned long long)golden::G14F_STEP[i][2],(unsigned long long)golden::G14F_STEP[i][1],(unsigned long long)golden::G14F_STEP[i][0]); }
    }

    std::printf("[dbg] fs.state_root=%lu fs.digest_ok=%d\n",
                (unsigned long)fs.state_root, feq(fs.digest, golden::G14F_STEP[5]));
    // 4. F_close
    const fp::fe final = fold::f_close(fs.digest, golden::G14F_COUNT);
    CHECK(feq(final, golden::G14F_FINAL), "G14F final digest");

    // 5. final accounts
    for (unsigned i = 0; i < 3; ++i) {
        const auto& a = golden::G14F_ACC[i];
        smt::AccountState st{};
        CHECK(mempool::lookup_account(vault, fs.state_root, gfe(&a[0]), st), "final lookup");
        CHECK(acq(st, golden::G14F_FIN[i]), "G14F final account state");
    }

    // 6. padding-neutrality: sans-PAD -> identical final
    {
        const std::string dir2 = "build/test_fold_np";
        std::filesystem::remove_all(dir2);
        smt::Vault v2; CHECK(v2.open(dir2), "vault v2 open");
        smt::Updater u2(v2); smt::Handle r2 = smt::HEMPTY;
        for (unsigned i = 0; i < 3; ++i) {
            const auto& a = golden::G14F_ACC[i];
            smt::AccountState st{}; st.bal_mag = ((unsigned __int128)a[5] << 64) | a[4];
            st.nonce = (std::uint64_t)a[6];
            r2 = u2.set_account(r2, gfe(&a[0]), st).new_root;
        }
        fold::FoldState f2{r2, fold::f_head(gfe(golden::G14F_PREV), gfe(golden::G14F_DECREE))};
        unsigned cnt = 0;
        for (unsigned i = 0; i < 6; ++i) {
            if (golden::G14F_ENT[i][13] == 2) continue;  // skip PAD
            fold::DecreeEntry e = gent(i);
            fold::f_exec(v2, f2, e);
            cnt++;
        }
        CHECK(feq(fold::f_close(f2.digest, cnt), golden::G14F_FINAL),
              "G14F padding-neutrality (identical final)");
    }

    // 7. chain dependency: different prev -> different final
    {
        fold::FoldState f3{root, fold::f_head(fp::fe_from_u64(999), gfe(golden::G14F_DECREE))};
        for (unsigned i = 0; i < 6; ++i) fold::f_exec(vault, f3, gent(i));
        CHECK(!feq(fold::f_close(f3.digest, golden::G14F_COUNT), golden::G14F_FINAL),
              "G14F chain dependency (different prev -> different final)");
    }

    // 8. negatives
    {
        fold::DecreeEntry bad = gent(0);
        bad.pt_hash = fp::fe_from_u64(1);  // wrong binding
        fold::FoldState fb{root, fold::f_head(gfe(golden::G14F_PREV), gfe(golden::G14F_DECREE))};
        CHECK(fold::f_exec(vault, fb, bad) == fold::Verdict::REJECT_BINDING,
              "G14F binding REJECTED");
    }
    {
        fold::DecreeEntry bad = gent(0);
        bad.nonce = 99;  // wrong nonce
        bad.pt_hash = fold::pt_hash_of(bad.amount, bad.fee, 99);  // re-bind for the nonce gate
        fold::FoldState fb{root, fold::f_head(gfe(golden::G14F_PREV), gfe(golden::G14F_DECREE))};
        CHECK(fold::f_exec(vault, fb, bad) == fold::Verdict::REJECT_NONCE,
              "G14F nonce REJECTED");
    }
    {
        fold::DecreeEntry bad = gent(4);  // the insolvent entry, forced to EXEC
        bad.status = fold::Status::EXEC;
        fold::FoldState fb{root, fold::f_head(gfe(golden::G14F_PREV), gfe(golden::G14F_DECREE))};
        CHECK(fold::f_exec(vault, fb, bad) == fold::Verdict::REJECT_INSOLVENT,
              "G14F insolvent-EXEC REJECTED");
    }

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 14\n", failures); return 1; }
    std::printf("step14 conformance: ALL GREEN (head + 6 entries + close, finals, "
                "neutrality, chain-dependency, 3 negatives)\n");
    return 0;
}
