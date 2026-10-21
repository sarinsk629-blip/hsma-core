// HSMA :: test_step55 - Phase 6.17 v2 s4 (DEC-s4): the DKG rotation, WIRED.
// The P5-A machinery (dkg_vss.hpp: beacon-seeded Feldman VSS, per-epoch
// rotation) was golden-proven but the node never derived its committee.
// s4 wires it; this test pins the semantics the node now rides:
//   P1 genesis deal      : E0 (no prev) — config ok, all n shares verify
//   P2 the config law    : t=1 rejected, n=225 rejected, 2t<n rejected
//   P3 the rotation      : E1/E2 dealt from DIFFERENT prev digests ->
//                          aggregate pk C[0] differs each epoch (rotation
//                          is real, not a re-print of the same key)
//   P4 tamper evidence   : a forged share [f(j)+1]G2 is REJECTED
//   P5 the aggregate     : C[0] == [f(0)]G2, AND the t-of-n Lagrange
//                          aggregation over ANY t shares rebuilds [f(0)]G2
//   P6 the node sequence : the exact rotate_dkg flow (chain-tip prev,
//                          LE64-per-limb Digest reconstruction) across a
//                          3-epoch digest chain — shares verify each epoch,
//                          pks differ pairwise
#include <hsma/threshold/dkg_vss.hpp>
#include <hsma/threshold/g2.hpp>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace hsma;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

int main() {
    std::printf("test_step55: the DKG rotation — beacon-seeded Feldman VSS wired to the node\n");

    // ---- P1: the genesis deal ----
    {
        threshold::vss::Transcript T;
        chk(threshold::vss::deal(T, 0, 5, 3, nullptr), "P1 genesis deal accepted (n=5, t=3)");
        unsigned ok = 0;
        for (std::uint64_t j = 1; j <= T.n; ++j)
            ok += threshold::vss::verify_share(T, j, T.Y[j]) ? 1u : 0u;
        chk(ok == T.n, "P1 all 5 member shares verify against the Feldman commitments");
        chk(T.C.size() == 3, "P1 t commitment points emitted");
    }

    // ---- P2: the config law, in code ----
    {
        threshold::vss::Transcript T;
        chk(!threshold::vss::deal(T, 0, 5, 1, nullptr), "P2 t=1 REJECTED (t >= 2)");
        chk(!threshold::vss::deal(T, 0, 225, 112, nullptr), "P2 n=225 REJECTED (n <= 224)");
        chk(!threshold::vss::deal(T, 0, 7, 3, nullptr), "P2 n=7,t=3 REJECTED (2t >= n)");
    }

    // ---- P3: the rotation — new epoch, new prev, new committee ----
    threshold::g2::G2Pt pk0{}, pk1{}, pk2{};
    {
        const auto d0 = consensus::sha256d((const std::uint8_t*)"chain-tip-0", 11);
        const auto d1 = consensus::sha256d((const std::uint8_t*)"chain-tip-1", 11);
        threshold::vss::Transcript T0, T1, T2;
        chk(threshold::vss::deal(T0, 1, 5, 3, &d0), "P3 E1 deal from prev=tip0");
        chk(threshold::vss::deal(T1, 2, 5, 3, &d1), "P3 E2 deal from prev=tip1");
        chk(threshold::vss::deal(T2, 2, 5, 3, &d0), "P3 E2' deal from prev=tip0 (control)");
        pk0 = T0.C[0]; pk1 = T1.C[0]; pk2 = T2.C[0];
        chk(!threshold::vss::pt_eq(pk0, pk1), "P3 aggregate pk MOVES with the chain tip (E1 != E2)");
        // auditable determinism: the SAME (epoch, prev) rebuilds the SAME committee
        threshold::vss::Transcript T2b;
        chk(threshold::vss::deal(T2b, 2, 5, 3, &d0), "P3 re-deal of (E2, prev=tip0)");
        chk(threshold::vss::pt_eq(pk2, T2b.C[0]), "P3 same inputs -> same committee (auditable determinism)");
        unsigned ok1 = 0, ok2 = 0;
        for (std::uint64_t j = 1; j <= 5; ++j) {
            ok1 += threshold::vss::verify_share(T1, j, T1.Y[j]) ? 1u : 0u;
            ok2 += threshold::vss::verify_share(T2, j, T2.Y[j]) ? 1u : 0u;
        }
        chk(ok1 == 5 && ok2 == 5, "P3 every epoch's shares verify (5/5, 5/5)");
    }

    // ---- P4: tamper evidence ----
    {
        const auto d0 = consensus::sha256d((const std::uint8_t*)"chain-tip-0", 11);
        threshold::vss::Transcript T;
        threshold::vss::deal(T, 1, 5, 3, &d0);
        threshold::vss::Transcript Tf = T;
        // forge member 3's public share: [f(3)+1]G2
        threshold::Fr one{}; threshold::fr_from_u64(one, 1);
        threshold::mont::fe6 k{}; threshold::fr_to_fe6(one, k);
        Tf.Y[3] = threshold::g2::Padd(Tf.Y[3], threshold::g2::Pmul(threshold::g2::gen(), k));
        chk(threshold::vss::verify_share(T, 3, T.Y[3]), "P4 genuine share accepted");
        chk(!threshold::vss::verify_share(Tf, 3, Tf.Y[3]), "P4 forged share REJECTED");
        chk(threshold::vss::verify_share(Tf, 1, Tf.Y[1]), "P4 forgery is LOCAL to member 3 (1 still verifies)");
    }

    // ---- P5: the aggregate pk binding + t-of-n Lagrange rebuild ----
    {
        const auto d0 = consensus::sha256d((const std::uint8_t*)"agg-check", 9);
        threshold::vss::Transcript T;
        threshold::vss::deal(T, 1, 5, 3, &d0);
        // C[0] == [f(0)]G2 — the aggregate pk IS the epoch secret's commitment
        threshold::mont::fe6 f0{};
        threshold::fr_to_fe6(T.f.c[0], f0);
        chk(threshold::vss::pt_eq(T.C[0], threshold::g2::Pmul(threshold::g2::gen(), f0)),
            "P5 C[0] == [f(0)]G2 (the committee identity binds the epoch secret)");
        // ANY t of n shares rebuild [f(0)] via Lagrange at zero — here shares 2,4,5
        std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>> parts;
        for (std::uint64_t j : {2ull, 4ull, 5ull}) parts.push_back({j, T.Y[j]});
        threshold::g2::G2Pt agg{};
        chk(threshold::vss::agg_dec_share(agg, parts), "P5 t-of-n aggregation runs");
        chk(threshold::vss::pt_eq(agg, T.C[0]), "P5 ANY-3-of-5 shares rebuild [f(0)]G2 exactly");
        // and a WRONG subset share corrupts the rebuild ([1]G added — a real,
        // nonzero perturbation; [0]G would be infinity and change nothing)
        std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>> bad = parts;
        bad[1].second = threshold::g2::Padd(bad[1].second, threshold::g2::gen());
        threshold::g2::G2Pt agg_bad{};
        threshold::vss::agg_dec_share(agg_bad, bad);
        chk(!threshold::vss::pt_eq(agg_bad, T.C[0]), "P5 corrupted share breaks the rebuild");
    }

    // ---- P6: the node sequence — 3 epochs of rotate_dkg, replica-exact ----
    {
        // the node's chain: LE64-per-limb tails -> Digest (the fold-site law)
        std::vector<std::array<std::uint64_t, 4>> chain;
        for (int e = 0; e < 4; ++e) {
            auto d = consensus::sha256d((const std::uint8_t*)&e, sizeof(e));
            std::uint8_t db[32]; std::memcpy(db, &d, 32);
            std::array<std::uint64_t, 4> tail{};
            for (int k = 0; k < 4; ++k)
                for (int b = 0; b < 8; ++b)
                    tail[(std::size_t)k] |= (std::uint64_t)db[k * 8 + b] << (8 * b);
            chain.push_back(tail);
        }
        threshold::g2::G2Pt pks[3];
        bool all_ok = true;
        for (unsigned e = 1; e <= 3; ++e) {
            consensus::Digest prev{};
            std::uint8_t pb[32];
            for (int k = 0; k < 4; ++k)
                for (int b = 0; b < 8; ++b)
                    pb[k * 8 + b] = (std::uint8_t)(chain[(std::size_t)e][(std::size_t)k] >> (8 * b));
            prev = consensus::Digest::from_bytes(pb);
            threshold::vss::Transcript T;
            if (!threshold::vss::deal(T, e, 5, 3, &prev)) { all_ok = false; break; }
            unsigned ok = 0;
            for (std::uint64_t j = 1; j <= T.n; ++j)
                ok += threshold::vss::verify_share(T, j, T.Y[j]) ? 1u : 0u;
            if (ok != T.n) all_ok = false;
            pks[e - 1] = T.C[0];
        }
        chk(all_ok, "P6 node replica: 3 epochs dealt from chain tips, shares 5/5 each");
        chk(!threshold::vss::pt_eq(pks[0], pks[1]) && !threshold::vss::pt_eq(pks[1], pks[2])
            && !threshold::vss::pt_eq(pks[0], pks[2]),
            "P6 node replica: all three committee keys pairwise distinct (rotation is REAL)");
    }

    std::printf("%s\n", "test_step55: DONE — the DKG rotation wired and pinned (the committee moves with the chain)");
    return fails;
}
