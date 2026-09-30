// throwaway conform probe - P5-A vote-verify diagnosis (delete after verdict)
#include <hsma/consensus.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <cstdio>
#include <vector>

int main() {
    using namespace hsma;
    hsma::threshold::vss::Transcript T{};
    if (!hsma::threshold::vss::deal(T, 0, 3, 2)) { std::printf("deal FAILED\n"); return 1; }

    threshold::Poly poly = T.f;
    threshold::Fr S1 = threshold::dkg::share_for(poly, 1);
    threshold::mont::fe6 k{}; threshold::fr_to_fe6(S1, k);
    auto Yp = threshold::g2::Pmul(threshold::g2::gen(), k);

    std::printf("verify_share(T,1,[f(1)]G2) = %s\n",
        hsma::threshold::vss::verify_share(T,1,Yp) ? "TRUE" : "FALSE");
    std::printf("verify_share(T,1,T.Y[1])   = %s\n",
        hsma::threshold::vss::verify_share(T,1,T.Y[1]) ? "TRUE" : "FALSE");

    std::vector<std::uint8_t> pre(64);
    for (int i = 0; i < 64; ++i) pre[i] = std::uint8_t(i);
    auto sig = msscvote::sign_vote(S1, pre);

    bool ok1 = false;
    for (std::uint64_t j = 1; j <= 3; ++j) {
        if (msscvote::verify_vote(sig, pre, T.Y[j])) {
            ok1 = true;
            std::printf("vote verifies against Y%llu\n", (unsigned long long)j);
            break;
        }
    }
    std::printf("vote cross-verify: %s\n", ok1 ? "TRUE" : "FALSE");
    return 0;
}
