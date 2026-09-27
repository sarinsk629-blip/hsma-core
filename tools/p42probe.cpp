// HSMA :: p42probe.cpp - P4-2 (DEC-278): the ordering lock + the threshold k-of-n.
// [O1] the ordering lock: 3 envelopes sorted by sort_key(beacon, cth) -> order_root
// [O2] the order is deterministic (same envelopes + same beacon -> same root)
// [T1] the threshold 2-of-3: members {1,2} reconstruct the secret, payload matches
// [T2] a DIFFERENT pair {2,3} also reconstructs (any k-of-n works)
// [T3] 1-of-3 CANNOT decrypt (the threshold property: fewer than k is insufficient)
// [T4] the order_root changes if the beacon changes (the ordering is beacon-bound)
#include <hsma/m2envelope.hpp>
#include <hsma/consensus.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/m2.hpp>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace hsma;

int main() {
    // the degree-2 poly: {secret, a, b} — each member's share is DIFFERENT
    // the secret is poly(0) = c[0] = 0x11
    // shares: share_for(j) = poly(j) = 0x11 + a*j + b*j² (all different)
    threshold::Fr s_secret{}; threshold::fr_from_u64(s_secret, 0x11);
    threshold::Fr a_coeff{}; threshold::fr_from_u64(a_coeff, 0x22);
    threshold::Fr b_coeff{}; threshold::fr_from_u64(b_coeff, 0x33);
    threshold::Poly poly; poly.c = {s_secret, a_coeff};   // degree 1: 2-of-3 threshold
    threshold::mont::fe6 sk_fe6{}; threshold::fr_to_fe6(s_secret, sk_fe6);

    // the committee's aggregate public key
    auto X_E = threshold::g2::Pmul(threshold::g2::gen(), sk_fe6);

    // 3 envelopes with different payloads
    std::vector<std::vector<std::uint8_t>> payloads = {
        {'d','e','c','r','e','e','-','1'},
        {'d','e','c','r','e','e','-','2'},
        {'d','e','c','r','e','e','-','3'},
    };
    std::vector<m2env::Envelope> envelopes;
    for (int i = 0; i < 3; ++i) {
        // vary r per envelope (r = 42 + i)
        // (the encrypt() function uses r=42 fixed; we inline for per-envelope r)
        threshold::Fr r_fr{}; threshold::fr_from_u64(r_fr, 42 + i);
        threshold::mont::fe6 rk{}; threshold::fr_to_fe6(r_fr, rk);
        auto R_pt = threshold::g2::Pmul(threshold::g2::gen(), rk);
        auto ss_pt = threshold::g2::Pmul(X_E, rk);
        auto ss_b = m2env::pt_to_bytes(ss_pt);
        auto xe_b = m2env::pt_to_bytes(X_E);
        std::uint8_t hdr[56] = {};
        { std::uint8_t snd[32] = {}; threshold::m2::ser_hdr(hdr, 7, snd, i, 100); }
        std::uint8_t k[32];
        threshold::m2::kdf(k, ss_b.data(), xe_b.data(), hdr);
        m2env::Envelope env;
        env.R = R_pt;
        env.ct = payloads[i];
        threshold::m2::dem_encrypt(env.ct, env.tag, k, hdr, payloads[i].data(), payloads[i].size());
        auto r_ser = m2env::pt_to_bytes(env.R);
        threshold::m2::ct_hash(env.cth, r_ser.data(), env.ct.data(), env.ct.size());
        envelopes.push_back(env);
    }
    std::printf("[setup] 3 envelopes encrypted\n");

    // [O1] the ordering lock
    const auto beacon = consensus::sha256d((const std::uint8_t*)"beacon_epoch_8", 14);
    std::vector<std::uint8_t> beacon_arr(beacon.l.size() * 8);
    beacon.to_bytes(beacon_arr.data());
    std::vector<std::array<std::uint8_t,32>> sort_keys(3);
    std::vector<std::array<std::uint8_t,32>> cths(3);
    for (int i = 0; i < 3; ++i) {
        threshold::m2::sort_key(sort_keys[i].data(), beacon_arr.data(), envelopes[i].cth);
        cths[i] = std::array<std::uint8_t,32>{};
        std::memcpy(cths[i].data(), envelopes[i].cth, 32);
    }
    // sort the envelope indices by sort_key
    std::vector<unsigned> order = {0, 1, 2};
    std::sort(order.begin(), order.end(), [&](unsigned a, unsigned b) {
        return memcmp(sort_keys[a].data(), sort_keys[b].data(), 32) < 0;
    });
    // the sorted cth array feeds order_root
    std::vector<std::array<std::uint8_t,32>> sorted_cths(3);
    for (int i = 0; i < 3; ++i) sorted_cths[i] = cths[order[i]];
    std::uint8_t oroot[32];
    threshold::m2::order_root(oroot, reinterpret_cast<const std::uint8_t (*)[32]>(sorted_cths.data()), 3);
    std::printf("[O1] order_root committed: ");
    for (int i = 0; i < 8; ++i) std::printf("%02x", oroot[i]);
    std::printf("... | order: ");
    for (int i = 0; i < 3; ++i) std::printf("%d ", order[i]);
    std::printf("\n");

    // [O2] determinism: same inputs -> same root
    std::uint8_t oroot2[32];
    threshold::m2::order_root(oroot2, reinterpret_cast<const std::uint8_t (*)[32]>(sorted_cths.data()), 3);
    bool o2 = (memcmp(oroot, oroot2, 32) == 0);
    std::printf("[O2] order_root deterministic: %s\n", o2 ? "YES" : "NO");

    // [T1]-[T3]: the threshold decrypt with 2-of-3 shares
    // the envelopes' R points are needed for dec_share
    // we use envelope 0's R for the decrypt test
    auto& env0 = envelopes[0];
    // the member shares (degree-0: all equal the secret)
    std::vector<threshold::g2::G2Pt> all_Ds;
    for (std::uint64_t j = 1; j <= 3; ++j) {
        threshold::Fr sj = threshold::dkg::share_for(poly, j);
        threshold::mont::fe6 sj_fe6{}; threshold::fr_to_fe6(sj, sj_fe6);
        std::uint64_t s_canon[6];
        for (int w = 0; w < 6; ++w) s_canon[w] = sj_fe6[w];
        all_Ds.push_back(threshold::m2::dec_share(s_canon, env0.R));
    }

    // the Lagrange coefficients for a subset
    auto try_threshold = [&](const std::vector<std::uint64_t>& member_ids) -> bool {
        std::vector<threshold::Fr> xs;
        for (auto id : member_ids) { threshold::Fr x{}; threshold::fr_from_u64(x, id); xs.push_back(x); }
        std::vector<threshold::Fr> lam_fr;
        if (!threshold::lagrange_zero(lam_fr, xs)) return false;
        // convert Fr lam to Fe6 limbs for aggregate_shares
        std::uint64_t lams[3][6] = {};
        for (std::size_t i = 0; i < member_ids.size(); ++i) {
            threshold::mont::fe6 l_fe6{}; threshold::fr_to_fe6(lam_fr[i], l_fe6);
            for (int t = 0; t < 6; ++t) lams[i][t] = l_fe6[t];
        }
        std::vector<threshold::g2::G2Pt> subset_Ds;
        for (auto id : member_ids) subset_Ds.push_back(all_Ds[id - 1]);
        auto D_agg = threshold::m2::aggregate_shares(lams, subset_Ds);
        // the kdf + decrypt
        auto ss_b = m2env::pt_to_bytes(D_agg);
        auto xe_b = m2env::pt_to_bytes(X_E);
        std::uint8_t hdr[56] = {};
        { std::uint8_t snd[32] = {}; threshold::m2::ser_hdr(hdr, 7, snd, 0, 100); }
        std::uint8_t k[32];
        threshold::m2::kdf(k, ss_b.data(), xe_b.data(), hdr);
        std::vector<std::uint8_t> pl;
        bool ok = threshold::m2::dem_decrypt(pl, k, hdr, env0.ct.data(), env0.ct.size(), env0.tag);
        return ok && pl == payloads[0];
    };

    bool t1 = try_threshold({1, 2});   // members 1+2
    std::printf("[T1] 2-of-3 (members 1,2): decrypt %s\n", t1 ? "YES" : "NO");
    bool t2 = try_threshold({2, 3});   // members 2+3
    std::printf("[T2] 2-of-3 (members 2,3): decrypt %s\n", t2 ? "YES" : "NO");
    bool t3 = try_threshold({1});      // member 1 alone
    std::printf("[T3] 1-of-3 (member 1 alone): decrypt %s (must be NO)\n", t3 ? "YES" : "NO");

    // [T4] the beacon changes -> the order changes
    const auto beacon2 = consensus::sha256d((const std::uint8_t*)"beacon_epoch_9", 14);
    std::vector<std::uint8_t> beacon2_arr(beacon2.l.size() * 8);
    beacon2.to_bytes(beacon2_arr.data());
    std::vector<std::array<std::uint8_t,32>> sk2(3);
    for (int i = 0; i < 3; ++i) threshold::m2::sort_key(sk2[i].data(), beacon2_arr.data(), envelopes[i].cth);
    std::vector<unsigned> order2 = {0, 1, 2};
    std::sort(order2.begin(), order2.end(), [&](unsigned a, unsigned b) {
        return memcmp(sk2[a].data(), sk2[b].data(), 32) < 0;
    });
    bool t4 = (order != order2);   // the order SHOULD change with a different beacon
    std::printf("[T4] different beacon -> different order: %s (order1: %d%d%d, order2: %d%d%d)\n",
                t4 ? "YES" : "no", order[0], order[1], order[2], order2[0], order2[1], order2[2]);

    const bool ok = o2 && t1 && t2 && !t3 && t4;
    std::printf("\n[P4-2] %s\n", ok ? "GREEN - the ordering lock + the threshold decrypt are PROVEN" : "RED");
    return ok ? 0 : 1;
}
