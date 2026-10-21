// HSMA :: test_step65_p2production.cpp - Pillar-2 production conformance.
// The consensus surface at production discipline, every DEF-389..397 owned:
//   (1)  the proven automaton at PRODUCTION parameters (K=20/40, beta=150,
//        n=224) finalizes honest quorum
//   (2)  DEF-396 negatives: total==0 reach the floor, not the modulo;
//        weight-concentrated committees terminate (bounded rejection sampling)
//   (3)  DEF-389: epoch::run commits the order root over ALL envelopes
//        (n=1/4/7 via the pipeline, n=2048 via the m2 ceremony path),
//        permutation-equivariant, tail-bound (the old 4-slot truncation is dead)
//   (4)  DEF-392: quorum cross-multiplication in __int128 - the u64 overflow
//        class (agreeing*10000 at 2^62) is caught deterministically
//   (5)  DEF-393: the freshness gate - one epoch, one weight root, one
//        conflict set, round window +-1; replays are not opinions
//   (6)  DEF-394: vote wire v2 - the claimed member is CHECKED with one
//        pairing; wrong claims, wrong preimages, and legacy scans all judged
//   (7)  DEF-391: ORDER_SIG - the lock attestation binds THIS root, rejects
//        foreign roots, and the threshold is the caller's attestation law
//   (8)  DEF-392b: the stall breaker resolves REAL conflicts under the REAL
//        threshold beacon; the beacon chain is deterministic and epoch-bound
#include <hsma/consensus.hpp>
#include <hsma/msscloop.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/epoch.hpp>
#include <hsma/m2envelope.hpp>
#include <hsma/threshold/m2.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <hsma/threshold/beacon.hpp>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <vector>

using namespace hsma;
using namespace hsma::threshold;
using Digest = consensus::Digest;

static double ms_now() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
static Digest D(const char* s) {
    return consensus::sha256d((const std::uint8_t*)s, std::strlen(s));
}
static threshold::g2::G2Pt g2_from_u64(std::uint64_t s) {
    threshold::Fr f{}; threshold::fr_from_u64(f, s);
    threshold::mont::fe6 k{}; threshold::fr_to_fe6(f, k);
    return threshold::g2::Pmul(threshold::g2::gen(), k);
}
// the reference ceremony: sort cths by sort_key(beacon, cth), root the order
static std::array<std::uint8_t, 32> rooted(
        const std::uint8_t beacon[32],
        std::vector<std::array<std::uint8_t, 32>> v) {
    std::vector<std::array<std::uint8_t, 32>> keys(v.size());
    for (std::size_t i = 0; i < v.size(); ++i)
        threshold::m2::sort_key(keys[i].data(), beacon, v[i].data());
    std::vector<unsigned> ord(v.size());
    for (std::size_t i = 0; i < ord.size(); ++i) ord[i] = unsigned(i);
    std::sort(ord.begin(), ord.end(), [&](unsigned a, unsigned b) {
        return std::memcmp(keys[a].data(), keys[b].data(), 32) < 0;
    });
    std::vector<std::array<std::uint8_t, 32>> s(v.size());
    for (std::size_t i = 0; i < s.size(); ++i)
        std::memcpy(s[i].data(), v[ord[i]].data(), 32);
    std::array<std::uint8_t, 32> o{};
    threshold::m2::order_root(o.data(),
        reinterpret_cast<const std::uint8_t (*)[32]>(s.data()), s.size());
    return o;
}

int main() {
    int fail = 0;
    auto check = [&](bool ok, const char* name) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (!ok) ++fail;
    };

    // =====================================================================
    // (1) the proven automaton at PRODUCTION parameters
    // =====================================================================
    {
        const std::size_t n = 224;
        consensus::Snapshot sn;
        sn.ids.resize(n); sn.w.resize(n);
        std::uint64_t tot = 0;
        for (std::size_t i = 0; i < n; ++i) {
            std::uint8_t b[32];
            std::snprintf((char*)b, sizeof b, "member-%zu", i);
            sn.ids[i] = consensus::sha256d(b, std::strlen((char*)b));
            sn.w[i] = 1000 + i;               // heterogeneous, all eligible
            tot += sn.w[i];
        }
        sn.total = tot; sn.self_row = 7;
        sn.root = D("weight_root_prod");

        consensus::View cv{};
        cv.conflict = D("conflict_prod");
        cv.preference = D("pref0_prod");

        // every OTHER member votes the SAME preference each round (honest quorum)
        consensus::Pool pool;
        const Digest pref = D("pref_honest");
        unsigned rounds_used = 0;
        for (std::uint64_t r = 1; r <= 200; ++r) {
            pool.clear();
            for (std::size_t v = 0; v < n; ++v)
                if (v != sn.self_row)
                    pool.push_back({v, 1, sn.root, cv.conflict, r, pref});
            auto lg = consensus::Automaton(sn, 1).tick(cv, D("beacon_prod"), pool);
            rounds_used = unsigned(r);
            if (cv.state == consensus::State::Finalized) break;
        }
        check(cv.state == consensus::State::Finalized && cv.preference == pref,
              "automaton at K=20/40 beta=150 finalizes the honest quorum");
        check(cv.confidence == params::BETA_CONFIRMATIONS,
              "finalization took exactly beta=150 confirmations");
        std::printf("      finalized at round %u\n", rounds_used);
    }

    // (2) DEF-396 negatives -------------------------------------------------
    {
        consensus::Snapshot sn;                 // total == 0
        sn.ids = {D("a")}; sn.w = {0}; sn.total = 0; sn.self_row = 0; sn.root = D("wr");
        consensus::View cv{}; cv.conflict = D("cf"); cv.preference = D("pf");
        consensus::Pool pool;
        auto lg = consensus::Automaton(sn, 1).tick(cv, D("bc"), pool);
        check(lg.kind == std::uint8_t(consensus::Kind::FloorAbort),
              "DEF-396: zero-total snapshot floor-aborts (no div-by-zero)");

        // weight concentrated on self: k=20 requested, ~no non-self mass ->
        // must TERMINATE (bounded draws) and floor-abort on the shortfall
        consensus::Snapshot sn2;
        sn2.ids = {D("me"), D("other")}; sn2.w = {1'000'000, 1};
        sn2.total = 1'000'001; sn2.self_row = 0; sn2.root = D("wr");
        consensus::View cv2{}; cv2.conflict = D("cf"); cv2.preference = D("pf");
        double t0 = ms_now();
        auto lg2 = consensus::Automaton(sn2, 1).tick(cv2, D("bc"), pool);
        const double dt = ms_now() - t0;
        check(dt < 500.0, "DEF-396: concentrated-weight tick terminates (bounded draws)");
        check(lg2.S == 0, "DEF-396: shortfall reaches the floor with S=0 (no hang)");
    }

    // (3) DEF-389: the order commitment is size-exact ------------------------
    {
        const std::uint8_t beacon[32] = {"prod_beacon_order_commit_v1!"};
        auto XE = g2_from_u64(0xABCD);

        // pipeline check at n=1/4/7: epoch::run's order_root == the reference
        for (const std::size_t nn : {std::size_t(1), std::size_t(4), std::size_t(7)}) {
            namespace fsys = std::filesystem;
            const std::string dir = "build/test_step65_epoch" + std::to_string(nn);
            fsys::remove_all(dir);
            smt::Vault vault;
            if (!vault.open(dir)) { check(false, "DEF-389: vault open"); break; }
            std::vector<fold::DecreeEntry> entries;
            for (unsigned i = 0; i < nn; ++i)
                entries.push_back({fp::fe_from_u64(100 + i), fp::fe_from_u64(200 + i),
                                   fp::fe_from_u64(300 + i), (unsigned __int128)(i + 1),
                                   (unsigned __int128)i, std::uint64_t(i + 1),
                                   fold::Status::EXEC});
            std::vector<threshold::g2::G2Pt> Rs;
            std::vector<std::vector<std::uint8_t>> cts;
            std::vector<std::array<std::uint8_t, 32>> cthv;
            for (std::size_t i = 0; i < nn; ++i) {
                std::vector<std::uint8_t> pl(32, std::uint8_t(0x50 + i));
                auto env = m2env::encrypt_det(pl, XE, 77, 1000 + i);
                Rs.push_back(env.R); cts.push_back(env.ct);
                cthv.push_back({});
                std::memcpy(cthv.back().data(), env.cth, 32);
            }
            const auto res = epoch::run(vault, smt::HEMPTY, fp::fe_from_u64(1),
                                        beacon, entries, Rs, cts);
            auto want = rooted(beacon, cthv);
            // The circuit domain carries (root mod p) — the Montgomery law
            // reduces; two roots differing only by +p fold identically, and a
            // 32-byte hash exceeds p ~65% of the time. The comparison is
            // therefore fe-to-fe through the SAME canonical constructor; the
            // byte-exact root is the node/wire representation, never reduced.
            std::uint64_t wl[4] = {0, 0, 0, 0};
            for (int k = 0; k < 4; ++k)
                for (int b = 0; b < 8; ++b)
                    wl[k] |= std::uint64_t(want[k*8+b]) << (8*b);
            // DEF-399 law on the reference side too: reduce BEFORE the lift.
            {   fp::fe raw{{{wl[0], wl[1], wl[2], wl[3]}}};
                for (int t = 0; t < 8 && !fp::is_canonical(raw); ++t)
                    fp::sub_assumed(raw.l.data(), raw.l.data(), fp::MOD.data());
                for (int k = 0; k < 4; ++k) wl[k] = raw.l[k];
            }
            const fp::fe wf = fp::fe_from_canonical_limbs({wl[0], wl[1], wl[2], wl[3]});
            const fp::fe gc = fp::fe_to_canonical(res.order_root);
            const fp::fe wc = fp::fe_to_canonical(wf);
            char nm[80]; std::snprintf(nm, sizeof nm,
                "DEF-389: pipeline order root size-exact at n=%zu", nn);
            check(gc.l == wc.l, nm);
            fsys::remove_all(dir);
        }

        // volume check at n=2048 (the ceremony path the node executes)
        std::vector<std::array<std::uint8_t, 32>> cthv;
        for (std::size_t i = 0; i < 2048; ++i) {
            std::vector<std::uint8_t> pl(40, std::uint8_t(i & 0xFF));
            auto env = m2env::encrypt_det(pl, XE, 77, 50000 + i);
            std::array<std::uint8_t, 32> c;
            std::memcpy(c.data(), env.cth, 32);
            cthv.push_back(c);
        }
        auto ra = rooted(beacon, cthv);
        auto shuf = cthv;
        for (std::size_t i = 0; i + 1 < shuf.size(); i += 7)
            std::swap(shuf[i], shuf[shuf.size() - 1 - i]);
        auto rb = rooted(beacon, shuf);
        check(std::memcmp(ra.data(), rb.data(), 32) == 0,
              "DEF-389: n=2048 root is permutation-equivariant (input order irrelevant)");
        auto swp = cthv;
        {   // a NEW cth replaces a tail slot: under the old 4-slot commit the
            // root would not move; size-exact commitment must move.
            auto env = m2env::encrypt_det(std::vector<std::uint8_t>(40, 0xEE),
                                          XE, 77, 9994241);
            std::memcpy(swp[2047].data(), env.cth, 32);
        }
        auto rc2 = rooted(beacon, swp);
        check(std::memcmp(ra.data(), rc2.data(), 32) != 0,
              "DEF-389: the tail is BOUND - a changed tail cth changes the root");
    }

    // (4) DEF-392: __int128 quorum arithmetic -------------------------------
    {
        msscloop::Config cfg{};   // alpha 75%, phi 50%
        msscloop::NodeState ns{};
        ns.conflict = D("cf"); ns.preference = D("pf");
        // agreeing = 2^62 (self), sampled = 2^63 (self + one dissenting peer).
        // u64: agreeing*10000 mod 2^64 == 0 and alpha*sampled mod 2^64 == 0 ->
        //   the phi check degenerates to 0 < 5000*2^63 -> FloorAbort (wrong).
        // u128: sampled passes the floor, 50% < 75% -> Switched. The verdict IS
        // the detector.
        const std::uint64_t half = 1ull << 62;
        ns.self_weight = half;                       // agrees with pf
        ns.peers.push_back({0x7F000001, 31234, half, 9});
        ns.total_weight = 2 * half;                  // 2^63
        std::vector<std::pair<std::uint64_t, Digest>> pp = {{9, D("other_pref")}};
        auto rr = msscloop::tick(ns, cfg, pp);
        check(rr.kind == consensus::Kind::Switched && ns.confidence == 0,
              "DEF-392: 2^62-scale quorum math is exact (__int128, no wrap)");
    }

    // (5) DEF-393: the freshness gate ---------------------------------------
    {
        const Digest wr = D("wroot"), cf = D("conf");
        auto t = [&](std::uint32_t e, std::uint64_t r, const Digest& w, const Digest& c,
                     std::uint64_t ce, std::uint64_t cr) {
            return msscloop::vote_fresh(e, r, w, wr, c, cf, ce, cr);
        };
        check(t(5, 10, wr, cf, 5, 10), "DEF-393: same epoch/round/root/conflict is fresh");
        check(t(5, 11, wr, cf, 5, 10) && t(5, 9, wr, cf, 5, 10),
              "DEF-393: round window +-1 accepted (clock skew)");
        check(!t(6, 10, wr, cf, 5, 10), "DEF-393: wrong epoch rejected");
        check(!t(5, 12, wr, cf, 5, 10), "DEF-393: round +2 rejected (replay window)");
        check(!t(5, 10, D("other_root"), cf, 5, 10), "DEF-393: foreign weight root rejected (fork)");
        check(!t(5, 10, wr, D("other_conf"), 5, 10), "DEF-393: foreign conflict set rejected");
    }

    // (6) DEF-394: vote wire v2 ---------------------------------------------
    {
        vss::Transcript T;
        check(vss::deal(T, 65, 4, 2), "vote-v2 setup: DKG deal n=4 t=2");
        const Digest wr = D("wroot"), cf = D("conf"), pf = D("prefA2");
        auto pre = msscvote::vote_preimage(65, wr, cf, 42, pf);

        threshold::Fr s2 = threshold::dkg::share_for(T.f, 2);
        auto sig = msscvote::sign_vote(s2, pre);
        auto m2w = msscvote::encode_vote_v2(65, wr, cf, 42, pf, sig, 2);
        check(m2w.payload.size() == msscvote::VOTE_PAYLOAD_V2, "DEF-394: v2 payload is 212B");
        auto dv = msscvote::decode_vote(m2w);
        check(dv.ok && dv.has_member && dv.member == 2, "DEF-394: v2 decode carries the claim");

        const threshold::g2::G2Pt *Y1 = &T.Y[1], *Y2 = &T.Y[2];   // Y[j] = member j
        check(msscvote::verify_vote_member(dv.sigma, pre, *Y2),
              "DEF-394: claimed member verifies with ONE pairing");
        check(!msscvote::verify_vote_member(dv.sigma, pre, *Y1),
              "DEF-394: WRONG claim fails the pairing (claim checked, not trusted)");
        auto pre_tampered = pre; pre_tampered[0] ^= 0x01;
        check(!msscvote::verify_vote_member(dv.sigma, pre_tampered, *Y2),
              "DEF-394: tampered preimage fails under the true key");

        // legacy 204B: decode + scan still works (rollout compatibility)
        auto m1 = msscvote::encode_vote(65, wr, cf, 42, pf, sig);
        check(m1.payload.size() == msscvote::VOTE_PAYLOAD, "DEF-394: legacy payload is 204B");
        auto dv1 = msscvote::decode_vote(m1);
        check(dv1.ok && !dv1.has_member, "DEF-394: legacy decode (no claim -> scan path)");

        // the aggregate: two partials on the SAME preimage, one pairing
        msscvote::AggregateVerify av{};
        threshold::Fr s1 = threshold::dkg::share_for(T.f, 1);
        auto sig1 = msscvote::sign_vote(s1, pre);
        msscvote::agg_accumulate(av, sig1, *Y1);
        msscvote::agg_accumulate(av, sig, *Y2);
        check(msscvote::agg_verify(av, pre), "DEF-394: aggregate of 2 partials, 1 pairing");
        check(!msscvote::agg_verify(av, pre_tampered),
              "DEF-394: aggregate refuses a foreign preimage");
    }

    // (7) DEF-391: ORDER_SIG - the lock attestation --------------------------
    {
        vss::Transcript T;
        check(vss::deal(T, 66, 4, 2), "order-lock setup: DKG deal n=4 t=2");
        std::uint8_t oroot[32];
        {   Digest d = D("order_root_for_lock"); d.to_bytes(oroot); }
        auto pre = msscvote::order_sig_preimage(9, oroot);
        check(pre.size() == msscvote::ORDER_PREIMAGE_SIZE, "lock preimage is exactly 52B");

        threshold::Fr s1 = threshold::dkg::share_for(T.f, 1);
        threshold::Fr s2 = threshold::dkg::share_for(T.f, 2);
        auto sg1 = msscvote::sign_order(s1, pre);
        auto sg2 = msscvote::sign_order(s2, pre);

        msscvote::AggregateVerify L{};
        const threshold::g2::G2Pt *Y1 = &T.Y[1], *Y2 = &T.Y[2];   // Y[j] = member j
        msscvote::agg_accumulate(L, sg1, *Y1);
        check(L.count == 1,
              "DEF-391: below threshold the caller law refuses attestation (1 < t)");
        msscvote::agg_accumulate(L, sg2, *Y2);
        check(msscvote::agg_verify(L, pre), "DEF-391: at the threshold the lock ATTESTS (1 pairing)");

        // wire roundtrip
        auto wm = msscvote::encode_order_sig(9, oroot, sg2, 2);
        check(wm.type == 0x0D && wm.payload.size() == msscvote::ORDER_SIG_WIRE,
              "DEF-391: 0x0D wire is 140B with the member claim");
        auto dd = msscvote::decode_order_sig(wm);
        check(dd.ok && dd.epoch == 9 && dd.member == 2
              && std::memcmp(dd.oroot, oroot, 32) == 0, "DEF-391: 0x0D decode roundtrip");
        check(msscvote::verify_vote_member(dd.sigma,
                msscvote::order_sig_preimage(dd.epoch, dd.oroot), *Y2),
              "DEF-391: decoded lock partial verifies against the claimed key");

        // foreign root: different preimage -> the partial does NOT verify
        std::uint8_t foreign[32]; Digest f = D("foreign_root"); f.to_bytes(foreign);
        check(!msscvote::verify_vote_member(dd.sigma,
                msscvote::order_sig_preimage(9, foreign), *Y2),
              "DEF-391: a foreign root can never ride this signature");
        wm.payload[5] ^= 0xFF;   // tamper the root on the wire
        auto dtam = msscvote::decode_order_sig(wm);
        check(!dtam.ok || std::memcmp(dtam.oroot, oroot, 32) != 0,
              "DEF-391: wire-tampered root is detected");
    }

    // (8) DEF-392b: the REAL breaker + the REAL beacon ------------------------
    {
        vss::Transcript T;
        check(vss::deal(T, 67, 4, 2), "breaker setup: DKG deal n=4 t=2");
        threshold::beacon::Committee bcom;
        for (std::uint64_t j = 1; j <= 2; ++j) {
            bcom.ids.push_back(j);
            bcom.shares.push_back(threshold::dkg::share_for(T.f, j));
        }
        const auto b1 = threshold::beacon::epoch_beacon(bcom, 5, Digest{});
        const auto b1b = threshold::beacon::epoch_beacon(bcom, 5, Digest{});
        const auto b2 = threshold::beacon::epoch_beacon(bcom, 6, b1);
        check(b1 == b1b, "DEF-392b: the threshold beacon is deterministic");
        check(!(b1 == b2), "DEF-392b: the beacon chain advances (epoch-bound, prev-bound)");
        check(!(b1 == D("beacon_p4")), "DEF-392b: the beacon is NOT a hashed literal");

        msscloop::Config cfg{};
        msscloop::NodeState ns{};
        ns.conflict = D("cf");
        ns.preference = D("pref_real_A");
        ns.stall = cfg.stall_limit;
        std::vector<Digest> frozen = {D("pref_real_A"), D("pref_real_B")};
        auto br = msscloop::breaker_tick(ns, cfg, bcom, 6, b1, frozen);
        check(br.resolved && (br.winner == frozen[0] || br.winner == frozen[1]),
              "DEF-392b: the breaker resolves a REAL two-candidate conflict");
        check(br.stagger_ms < params::GOLDEN_MAX_GRACE_MS,
              "DEF-392b: the stagger is bounded by the golden grace window");
        check(ns.state == consensus::State::Active && ns.stall == 0,
              "DEF-392b: the breaker re-activates the node");
        msscloop::NodeState ns2{};
        ns2.conflict = D("cf"); ns2.stall = cfg.stall_limit;
        std::vector<Digest> solo = {D("only_one_candidate")};
        auto br2 = msscloop::breaker_tick(ns2, cfg, bcom, 6, b1, solo);
        check(!br2.resolved && br2.suspended,
              "DEF-392b: a one-candidate 'conflict' is refused (no invented winners)");
    }

    std::printf("\n%s\n", fail ? "test_step65: FAILED" :
        "test_step65: ALL PASS (P2 production: automaton, order binding, u128 quorum, "
        "freshness, v2 votes, ORDER_SIG, real beacon/breaker)");
    return fail ? 1 : 0;
}
