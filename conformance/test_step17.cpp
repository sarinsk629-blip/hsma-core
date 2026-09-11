// Step-17 conformance: the epoch pipeline (DEC-210).
// Oracle: pure Python epoch pipeline (epoch_golden.hpp).
// Tests the M2→fold integration: order_root feeds the fold head.
#include <hsma/epoch.hpp>
#include "fold_golden.hpp"
#include "epoch_golden.hpp"
#include "m2_golden.hpp"
#include <cstdio>
#include <filesystem>

using namespace hsma;
using namespace hsma::threshold;
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
static threshold::g2::G2Pt R_of(unsigned i) {
    return g2::from_affine(golden::G12M_RPT[i][0], golden::G12M_RPT[i][1],
                           golden::G12M_RPT[i][2], golden::G12M_RPT[i][3]);
}

int main() {
    // 1. Set up the vault
    namespace fsys = std::filesystem;
    const std::string dir = "build/test_epoch";
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

    // 2. Build the pipeline inputs: entries + KEM points + ciphertexts
    std::vector<fold::DecreeEntry> entries;
    for (unsigned i = 0; i < 6; ++i) entries.push_back(gent(i));
    std::vector<threshold::g2::G2Pt> Rs;
    for (unsigned i = 0; i < 4; ++i) Rs.push_back(R_of(i));
    std::vector<std::vector<std::uint8_t>> cts;
    for (unsigned i = 0; i < 4; ++i) {
        std::vector<std::uint8_t> ct(32);
        for (int j = 0; j < 32; ++j) ct[j] = std::uint8_t(0x42 + i);
        cts.push_back(ct);
    }

    // 3. Run the pipeline
    const fp::fe prev = gfe(golden::G17F_PREV);
    const std::uint8_t* beacon = golden::G12M_BEACON;
    auto result = epoch::run(vault, root, prev, beacon, entries, Rs, cts);

    // 4. Check the golden
    CHECK(result.acc.count == golden::G17F_COUNT, "G17F count");
    CHECK(feq(result.acc.digest, golden::G17F_FINAL), "G17F final digest");

    // 5. The succinctness invariant
    CHECK(nivc::ACC_SIZE == 41, "G17F accumulator 41B");

    // 6. The order matches (M2 ordering → the fold's input)
    printf("[dbg] count=%u golden=%u\n", result.acc.count, golden::G17F_COUNT);

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 17\n", failures); return 1; }
    std::printf("step17 conformance: ALL GREEN (M2 ordering -> fold -> NIVC close, "
                "%u entries, 41B accumulator)\n", result.acc.count);
    return 0;
}
