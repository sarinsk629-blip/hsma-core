// HSMA :: aggprobe.cpp - P3-3b (DEC-275): the aggregate verify.
#include <hsma/msscvote.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/g2.hpp>
#include <chrono>
#include <cstdio>
using namespace hsma;

int main() {
    threshold::Fr c1{}, c2{}, c3{};
    threshold::fr_from_u64(c1, 0x11); threshold::fr_from_u64(c2, 0x22); threshold::fr_from_u64(c3, 0x33);
    threshold::Poly poly; poly.c = {c1, c2, c3};

    auto wr = consensus::sha256d((const std::uint8_t*)"wr",2);
    auto cf = consensus::sha256d((const std::uint8_t*)"cf",2);
    auto pr = consensus::sha256d((const std::uint8_t*)"prefA",5);
    auto pre = msscvote::vote_preimage(7, wr, cf, 3, pr);
    auto bad = pre; bad[4] ^= 0xFF;

    std::vector<threshold::g1::Pt> sigs;
    std::vector<threshold::g2::G2Pt> Ys;
    for (std::uint64_t j = 1; j <= 3; ++j) {
        threshold::Fr sj = threshold::dkg::share_for(poly, j);
        sigs.push_back(msscvote::sign_vote(sj, pre));
        threshold::mont::fe6 k{}; threshold::fr_to_fe6(sj, k);
        Ys.push_back(threshold::g2::Pmul(threshold::g2::gen(), k));
    }

    using clk = std::chrono::steady_clock;
    auto t0 = clk::now();
    bool per_ok = true;
    for (int j = 0; j < 3; ++j)
        per_ok &= msscvote::verify_vote(sigs[j], pre, Ys[j]);
    auto t1 = clk::now();
    double per_ms = std::chrono::duration<double,std::milli>(t1-t0).count();

    auto t2 = clk::now();
    msscvote::AggregateVerify av;
    for (int j = 0; j < 3; ++j) msscvote::agg_accumulate(av, sigs[j], Ys[j]);
    bool agg_ok = msscvote::agg_verify(av, pre);
    auto t3 = clk::now();
    double agg_ms = std::chrono::duration<double,std::milli>(t3-t2).count();

    std::printf("[T1] per-member (3 pairings): verdict=%s | %.0f ms\n", per_ok?"ACCEPT":"REJECT!!", per_ms);
    std::printf("[T2] aggregate (1 pairing):     verdict=%s | %.0f ms\n", agg_ok?"ACCEPT":"REJECT!!", agg_ms);
    std::printf("[T3] same verdict: %s\n", (per_ok == agg_ok) ? "YES" : "NO");
    bool agg_bad = msscvote::agg_verify(av, bad);
    std::printf("[T4] aggregate REJECTS tampered: %s\n", !agg_bad ? "YES" : "NO");
    std::printf("\n[P3-3b] %s | speedup: %.1fx\n",
        (per_ok && agg_ok && !agg_bad) ? "GREEN" : "RED",
        per_ms / (agg_ms > 0.01 ? agg_ms : 0.01));
    return (per_ok && agg_ok && !agg_bad) ? 0 : 1;
}
