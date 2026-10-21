// HSMA diag_step5 v2 — names the failing layer in ONE run.
#include <hsma/params.hpp>
#include <hsma/vault.hpp>
#include <hsma/update.hpp>
#include <hsma/tx.hpp>
#include <cstdio>
#include <cstring>
#include <filesystem>

using namespace hsma;
static void hex(const char* lbl, const std::uint64_t* l) {
    std::printf("%s = 0x%016llx%016llx%016llx%016llx\n", lbl,
        (unsigned long long)l[3],(unsigned long long)l[2],
        (unsigned long long)l[1],(unsigned long long)l[0]);
}
int main() {
    namespace fs = std::filesystem;
    const std::string dir = "build/diag_vault";
    fs::remove_all(dir);
    smt::Vault vault;
    if (!vault.open(dir)) { std::printf("VAULT OPEN FAILED: %s\n", vault.last_error().c_str()); return 1; }

    std::byte b[32]{}; b[0] = std::byte{0xAA};
    const fp::fe pk  = fp::fe_from_le_bytes(b).value;
    const fp::fe key = smt::key_from_pk(fp::fe_zero(), pk);
    const fp::fe kc  = fp::fe_to_canonical(key);

    smt::Updater up(vault);
    auto r = up.set_account(vault.latest_root(), key, {1000, false, 0, 0});
    std::printf("SEED: fault=%d allocs=%llu\n", (int)r.stats.fault,
                (unsigned long long)r.stats.total());

    smt::AccountState st{};
    const bool ok = mempool::lookup_account(vault, r.new_root, key, st);
    std::printf("LOOKUP: %s", ok ? "OK" : "FAIL");
    if (ok) std::printf("  bal=%llu nonce=%llu",
        (unsigned long long)(unsigned __int128)st.bal_mag,
        (unsigned long long)st.nonce);
    std::printf("\n");

    const std::uint64_t idx = smt::index_of(key);
    smt::Handle cur = r.new_root;
    for (int lvl = 63; lvl >= 0 && cur != smt::HEMPTY; --lvl)
        cur = ((idx >> lvl) & 1) ? vault.deref(cur)->w[1] : vault.deref(cur)->w[0];
    if (cur == smt::HEMPTY) { std::printf("DESCENT: EMPTY\n"); return 1; }
    const smt::Entry* tl  = vault.deref(cur);
    std::printf("TLEAF tag=%u (want %u)\n", tl->tag, (unsigned)smt::Tag::TLEAF);
    const smt::Entry* rec = vault.deref(tl->w[0]);
    std::printf("REC   tag=%u (want %u)  %s\n", rec->tag, (unsigned)smt::Tag::REC,
        rec->tag == std::uint8_t(smt::Tag::REC) ? "" :
        "  <-- TAG SEVERED (DEC-127 violation: memset after member set?)");
    hex("STORED ", rec->w);
    std::printf("VERDICT: %s\n",
        0 == std::memcmp(rec->w, kc.l.data(), 32) ? "canonical-at-rest (DEC-123 held)" :
        0 == std::memcmp(rec->w, key.l.data(), 32) ? "montgomery-at-rest (DEC-123 violated)" :
                                                     "garbage");
    return ok ? 0 : 1;
}
