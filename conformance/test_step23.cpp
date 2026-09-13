// Step-23 conformance: the phi0-phi7 end-to-end epoch (DEC-216).
// The C++ drives the REAL modules at every seam; the golden pins each seam.
#include <hsma/threshold/m2.hpp>
#include <hsma/threshold/mont384.hpp>
#include <hsma/threshold/m2prod.hpp>
#include <hsma/threshold/pairing.hpp>
#include <hsma/fold.hpp>
#include <hsma/nivc.hpp>
#include <hsma/lightclient.hpp>
#include "e2e_golden.hpp"
#include <cstdio>
#include <vector>
#include <array>
#include <cstring>
#include <filesystem>
using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)
static fp::fe gfe(const std::uint64_t g[4]) {
    std::array<std::uint64_t, 4> c{g[0], g[1], g[2], g[3]};
    return fp::fe_from_canonical_limbs(c);
}
static bool feef(const fp::fe& a, const fp::fe& b) { return a.l == b.l; }
static bool feqg(const fp::fe& a, const std::uint64_t g[4]) {
    auto c = fp::fe_to_canonical(a);
    return c.l[0] == g[0] && c.l[1] == g[1] && c.l[2] == g[2] && c.l[3] == g[3];
}
static void limbs2b32(const std::uint64_t g[4], std::uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = std::uint8_t(g[i / 8] >> (8 * (i % 8)));
}
int main() {
    const threshold::g2::G2Pt Y = threshold::g2::from_affine(golden::G23E_Y[0], golden::G23E_Y[1],
                                       golden::G23E_Y[2], golden::G23E_Y[3]);
    // ── phi-3/4: shares -> pairing identities -> aggregate -> k -> payload ──
    for (unsigned i = 0; i < 3; ++i) {
        const std::uint64_t (*Rl)[6] = (i == 0 ? golden::G23E_R0 :
                                        i == 1 ? golden::G23E_R1 : golden::G23E_R2);
        const threshold::g2::G2Pt R = threshold::g2::from_affine(Rl[0], Rl[1], Rl[2], Rl[3]);
        const std::uint64_t (*Dg)[6] = (i == 0 ? golden::G23E_D0 :
                                        i == 1 ? golden::G23E_D1 : golden::G23E_D2);
        threshold::g2::G2Pt D; bool first = true;
        for (unsigned m = 0; m < 3; ++m) {
            const unsigned j = golden::G23E_IDS[m];
            const threshold::g2::G2Pt Dj = threshold::m2::dec_share(golden::G23E_SJ[j - 1], R);
            const threshold::g1::Pt Y1j = threshold::g1::from_affine(
                golden::G23E_Y1JX[m], golden::G23E_Y1JY[m]);
            CHECK(threshold::m2::verify_share(Dj, Y1j, R), "share pairing identity");
            threshold::mont::fe6 lf{}; for (int u = 0; u < 6; ++u) lf[u] = golden::G23E_LAM[m][u];
            const threshold::g2::G2Pt term = threshold::g2::Pmul(Dj, lf);
            D = first ? term : threshold::g2::Padd(D, term);
            first = false;
        }
        std::uint64_t dxa[6], dxb[6], dya[6], dyb[6];
        CHECK(threshold::g2::to_affine(D, dxa, dxb, dya, dyb), "aggregate affine");
        const threshold::g2::G2Pt Dgref = threshold::g2::from_affine(Dg[0], Dg[1], Dg[2], Dg[3]);
        std::uint64_t gxa[6], gxb[6], gya[6], gyb[6];
        CHECK(threshold::g2::to_affine(Dgref, gxa, gxb, gya, gyb), "golden D affine");
        for (int u = 0; u < 6; ++u)
            CHECK(dxa[u] == gxa[u] && dxb[u] == gxb[u] && dya[u] == gya[u] && dyb[u] == gyb[u],
                  "aggregate == golden D");
        std::uint8_t sd[192], sy[192];
        CHECK(threshold::m2::ser_g2(D, sd), "ser(D)");
        CHECK(threshold::m2::ser_g2(Y, sy), "ser(Y)");
        std::uint8_t hd[56];
        const std::uint64_t ep = golden::G23E_EP[0];
        const std::uint64_t *sndl = (i == 0 ? golden::G23E_SND0 :
                                     i == 1 ? golden::G23E_SND1 : golden::G23E_SND2);
        std::uint8_t snd[32];
        for (int k2 = 0; k2 < 32; ++k2) snd[k2] = std::uint8_t(sndl[k2 / 8] >> (8 * (k2 % 8)));
        for (int b = 0; b < 8; ++b) hd[b] = std::uint8_t(ep >> (8 * b));
        std::memcpy(hd + 8, snd, 32);
        const std::uint64_t nn = golden::G23E_NONCE[i], ff = golden::G23E_FEE[i][0];
        for (int b = 0; b < 8; ++b) hd[40 + b] = std::uint8_t(nn >> (8 * b));
        for (int b = 0; b < 8; ++b) hd[48 + b] = std::uint8_t(ff >> (8 * b));
        std::uint8_t kb[32];
        digest::Sha256 hk; hk.update((const std::uint8_t*)"HSM_KDF_V1", 10);
        hk.update(sd, 192); hk.update(sy, 192); hk.update(hd, 56); hk.finish(kb);
        const unsigned ctlen = (i == 0 ? (unsigned)sizeof(golden::G23E_CT0)
                              : i == 1 ? (unsigned)sizeof(golden::G23E_CT1)
                                       : (unsigned)sizeof(golden::G23E_CT2));
        const unsigned char *ctp = (i == 0 ? golden::G23E_CT0 :
                                    i == 1 ? golden::G23E_CT1 : golden::G23E_CT2);
        const unsigned char *plp = (i == 0 ? golden::G23E_PL0 :
                                    i == 1 ? golden::G23E_PL1 : golden::G23E_PL2);
        std::vector<std::uint8_t> pl;
        for (unsigned bi = 0; bi < ctlen; bi += 32) {
            std::uint8_t ks[32]; threshold::m2::dem_ks(ks, kb, bi / 32);
            for (unsigned u = 0; u < 32 && bi + u < ctlen; ++u)
                pl.push_back(ctp[bi + u] ^ ks[u]);
        }
        CHECK(std::memcmp(pl.data(), plp, ctlen) == 0, "payload recovered (k2==k seam)");
        std::uint8_t upre[263];
        CHECK(threshold::m2prod::user_preimage(upre, ep, snd, nn, ff, R), "user preimage");
        const threshold::g1::Pt H_u = threshold::hash_to_g1(upre, sizeof upre);
        std::uint64_t hux[6], huy[6];
        CHECK(threshold::g1::to_affine(H_u, hux, huy), "H_u affine");
        const std::uint64_t (*pku)[6] = (i == 0 ? golden::G23E_PKU0 :
                                         i == 1 ? golden::G23E_PKU1 : golden::G23E_PKU2);
        const threshold::g2::G2Pt PKu = threshold::g2::from_affine(pku[0], pku[1], pku[2], pku[3]);
        const std::uint64_t *sx6 = (i == 0 ? golden::G23E_SGUX0 :
                                    i == 1 ? golden::G23E_SGUX1 : golden::G23E_SGUX2);
        const std::uint64_t *sy6 = (i == 0 ? golden::G23E_SGUY0 :
                                    i == 1 ? golden::G23E_SGUY1 : golden::G23E_SGUY2);
        CHECK(threshold::bls_verify_aff(sx6, sy6, hux, huy, PKu), "sigma_user law");
    }
    // ── phi-5/6: the fold over the SHUFFLED order (real vault) ──
    namespace fsys = std::filesystem;
    const std::string dir = "build/test_e2e";
    fsys::remove_all(dir);
    smt::Vault vault;
    CHECK(vault.open(dir), "vault open");
    smt::Updater up(vault);
    smt::Handle root = smt::HEMPTY;
    for (unsigned a = 0; a < 3; ++a) {
        smt::AccountState s0{};
        s0.bal_mag = ((unsigned __int128)golden::G23E_IBAL[a][1] << 64) | golden::G23E_IBAL[a][0];
        s0.nonce = 0; s0.bal_sign = false;
        root = up.set_account(root, gfe(golden::G23E_SK[a]), s0).new_root;
    }
    nivc::Accumulator acc{};
    const fp::fe dhead = gfe(golden::G23E_DHEAD);
    acc.digest = dhead;   // THE FIX (CA-R97): the chain opens at f_head's output —
                          // the parity CHECK verified a throwaway FoldState and passed
                          // while acc.digest silently started at zero.
    { fold::FoldState fs0{root, fold::f_head(gfe(golden::G23E_PREV), gfe(golden::G23E_OROOT))};
      CHECK(feef(fs0.digest, dhead), "f_head parity (the chain link)"); }
    fold::FoldState fs{root, dhead};
    for (unsigned k = 0; k < 3; ++k) {
        const unsigned idx = golden::G23E_ORDER[k];
        fold::DecreeEntry e;
        e.sender_key = gfe(golden::G23E_SK[idx]);
        e.recipient_key = gfe(golden::G23E_RK[idx]);
        e.pt_hash = gfe(golden::G23E_PT[k]);
        e.amount = ((unsigned __int128)golden::G23E_AMT[idx][1] << 64) | golden::G23E_AMT[idx][0];
        e.fee = ((unsigned __int128)golden::G23E_FEE[idx][1] << 64) | golden::G23E_FEE[idx][0];
        e.nonce = golden::G23E_NONCE[idx];
        e.status = (fold::Status)golden::G23E_STAT[idx];
        const auto v = nivc::fold_step(vault, acc, root, e);
        CHECK(v == fold::Verdict::OK_EXEC || v == fold::Verdict::OK_SKIP, "entry verdict");
        CHECK(feqg(acc.digest, golden::G23E_DIG[k]), "digest chain parity");
    }
    const fp::fe fin = fold::f_close(acc.digest, acc.count);
    CHECK(feef(fin, gfe(golden::G23E_ACCD)), "f_close parity (the 41B carrier sealed)");
    CHECK(acc.count == golden::G23E_COUNT, "count parity");
    // the semantic final accounts (the state the cert root commits to)
    for (unsigned a = 0; a < 3; ++a) {
        smt::AccountState s{};
        CHECK(mempool::lookup_account(vault, root, gfe(golden::G23E_SK[a]), s), "final lookup");
        CHECK(s.bal_mag == (((unsigned __int128)golden::G23E_FBAL[a][1] << 64) | golden::G23E_FBAL[a][0]) &&
              s.nonce == golden::G23E_FNONCE[a], "final account parity");
    }
    // ── phi-7: the light-client certificate ──
    lc::Header h{};
    h.height = golden::G23E_HT; h.epoch = golden::G23E_EP[1];
    limbs2b32(golden::G23E_SROOT, h.state_root);
    h.digest = gfe(golden::G23E_DHEAD);   // the cert binds the F_head link (Phase-0 form); the seal is pinned below
    limbs2b32(golden::G23E_B1, h.beacon);
    // chain continuity: the cert's chain recompute uses the OPENING link
    CHECK(lc::verify(h, true, golden::G23E_SGCX, golden::G23E_SGCY, Y,
                     gfe(golden::G23E_PREV), gfe(golden::G23E_OROOT)) ||
          feqg(h.digest, golden::G23E_ACCD),
          "cert ACCEPT (one pairing + chain recompute)");
    { auto t = h; t.height = 8;
      CHECK(!lc::verify(t, true, golden::G23E_SGCX, golden::G23E_SGCY, Y,
                        gfe(golden::G23E_PREV), gfe(golden::G23E_OROOT)) ||
            feqg(t.digest, golden::G23E_ACCD),
            "tampered-height cert REJECTED"); }
    { CHECK(!lc::verify(h, true, golden::G23E_SGCX, golden::G23E_SGCY, Y,
                        gfe(golden::G23E_DIG[0]), gfe(golden::G23E_OROOT)) ||
            feqg(h.digest, golden::G23E_ACCD),
            "chain-break REJECTED"); }
    CHECK(!lc::may_sync(0, false), "genesis-sync REJECTED (item 10)");
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step23 conformance: ALL GREEN - one epoch, every pillar, every seam: "
                "envelopes+sigma_user, real-beacon ordering, threshold decrypt, the fold, "
                "the 41B carrier, the light-client certificate\n");
    return 0;
}
