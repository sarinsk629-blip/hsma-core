#include <hsma/consensus.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <hsma/m2envelope.hpp>
#include <hsma/threshold/m2.hpp>
#include <cstdio>
int main() {
    using namespace hsma;
    hsma::threshold::vss::Transcript T{};
    if (!hsma::threshold::vss::deal(T, 0, 3, 2)) return 1;
    threshold::Fr rk{}; threshold::fr_from_u64(rk, 12345);
    threshold::mont::fe6 rkk{}; threshold::fr_to_fe6(rk, rkk);
    auto R = threshold::g2::Pmul(threshold::g2::gen(), rkk);

    auto mk = [&](std::uint64_t j){
        threshold::Fr sj = threshold::dkg::share_for(T.f, j);
        threshold::mont::fe6 k6{}; threshold::fr_to_fe6(sj, k6);
        std::uint64_t sc[6];
        for (int w = 0; w < 6; ++w) sc[w] = k6[w];
        return threshold::m2::dec_share(sc, R);
    };
    auto D1 = mk(1), D2 = mk(2);

    threshold::g2::G2Pt agg{};
    std::vector<std::pair<std::uint64_t, threshold::g2::G2Pt>> sh = {{1,D1},{2,D2}};
    if (!hsma::threshold::vss::agg_dec_share(agg, sh)) { std::printf("agg FAILED\n"); return 1; }

    threshold::mont::fe6 f0{}; threshold::fr_to_fe6(T.f.c[0], f0);
    auto Key = threshold::g2::Pmul(R, f0);

    std::uint64_t ax[6], ay[6], bx[6], by[6];
    bool a1 = threshold::g2::to_affine(agg, ax, ay, bx, by);   // conform: G2 to_affine arity (xa,xb,ya,yb)
    std::uint64_t cx[6], cy[6], dx[6], dy[6];
    bool a2 = threshold::g2::to_affine(Key, cx, cy, dx, dy);
    std::printf("agg affine=%d key affine=%d\n", (int)a1, (int)a2);
    if (a1 && a2) {
        std::printf("X match: %s | Y match: %s\n",
            (std::memcmp(ax,cx,sizeof ax)==0 && std::memcmp(bx,dx,sizeof bx)==0)?"TRUE":"FALSE",
            (std::memcmp(ay,cy,sizeof ay)==0 && std::memcmp(by,dy,sizeof by)==0)?"TRUE":"FALSE");
        std::printf("agg x[0]=%016llx | key x[0]=%016llx\n",
            (unsigned long long)ax[0], (unsigned long long)cx[0]);
    }
    return 0;
}
