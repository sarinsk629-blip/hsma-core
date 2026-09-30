// P5-B isolation: does agg_verify hang on the node's EXACT aggregate?
#include <hsma/consensus.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <cstdio>
#include <chrono>
int main() {
    using namespace hsma;
    hsma::threshold::vss::Transcript T{};
    if (!hsma::threshold::vss::deal(T, 0, 3, 2)) { std::printf("deal FAILED\n"); return 1; }
    auto wr = consensus::sha256d((const std::uint8_t*)"wr", 2);
    auto cf = consensus::sha256d((const std::uint8_t*)"cf", 2);
    auto pr = consensus::sha256d((const std::uint8_t*)"prefA", 5);
    auto pre = msscvote::vote_preimage(0, wr, cf, 0, pr);
    auto s1 = msscvote::sign_vote(threshold::dkg::share_for(T.f, 1), pre);
    auto s2 = msscvote::sign_vote(threshold::dkg::share_for(T.f, 2), pre);

    std::printf("[A] distinct sigmas: accumulate...\n"); fflush(stdout);
    msscvote::AggregateVerify av{};
    msscvote::agg_accumulate(av, s1, T.Y[1]);
    msscvote::agg_accumulate(av, s2, T.Y[2]);
    std::uint64_t ax[6], ay[6];
    bool af = threshold::g1::to_affine(av.sigma_agg, ax, ay);
    std::printf("[A] sigma_agg affine=%d x[0]=%016llx y[0]=%016llx\n", (int)af,
        af ? (unsigned long long)ax[0] : 0ULL, af ? (unsigned long long)ay[0] : 0ULL); fflush(stdout);
    std::printf("[A] agg_verify...\n"); fflush(stdout);
    const auto t0 = std::chrono::steady_clock::now();
    bool ok = msscvote::agg_verify(av, pre);
    std::printf("[A] = %d | %.1f ms\n", (int)ok,
        std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-t0).count()); fflush(stdout);

    std::printf("[B] identical sigmas (P+P doubling path)...\n"); fflush(stdout);
    msscvote::AggregateVerify av2{};
    msscvote::agg_accumulate(av2, s1, T.Y[1]);
    msscvote::agg_accumulate(av2, s1, T.Y[1]);            // Padd(P, P) — THE EDGE
    bool bf = threshold::g1::to_affine(av2.sigma_agg, ax, ay);
    std::printf("[B] sigma_agg affine=%d x[0]=%016llx y[0]=%016llx\n", (int)bf,
        bf ? (unsigned long long)ax[0] : 0ULL, bf ? (unsigned long long)ay[0] : 0ULL); fflush(stdout);
    std::printf("[B] agg_verify...\n"); fflush(stdout);
    bool ok2 = msscvote::agg_verify(av2, pre);
    std::printf("[B] = %d\n", (int)ok2); fflush(stdout);
    return 0;
}
