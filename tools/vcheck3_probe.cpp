#include <hsma/consensus.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <cstdio>
#include <vector>
int main() {
    using namespace hsma;
    hsma::threshold::vss::Transcript T{};
    if (!hsma::threshold::vss::deal(T, 0, 3, 2)) { std::printf("deal FAILED\n"); return 1; }
    auto wr = consensus::sha256d((const std::uint8_t*)"wr", 2);
    auto cf = consensus::sha256d((const std::uint8_t*)"cf", 2);
    auto pr = consensus::sha256d((const std::uint8_t*)"prefA", 5);
    auto pre = msscvote::vote_preimage(0, wr, cf, 0, pr);
    auto sig2 = msscvote::sign_vote(threshold::dkg::share_for(T.f, 2), pre);
    std::printf("[p3] vs Y1...\n");  fflush(stdout);
    std::printf("[p3] vs Y1 = %d\n", (int)msscvote::verify_vote(sig2, pre, T.Y[1])); fflush(stdout);
    std::printf("[p3] vs Y2... (silence after this = THE HANG, isolated)\n"); fflush(stdout);
    std::printf("[p3] vs Y2 = %d\n", (int)msscvote::verify_vote(sig2, pre, T.Y[2])); fflush(stdout);
    std::printf("[p3] vs Y3 = %d\n", (int)msscvote::verify_vote(sig2, pre, T.Y[3])); fflush(stdout);
    return 0;
}
