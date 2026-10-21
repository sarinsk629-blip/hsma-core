// throwaway round-trip probe - P5-A wire diagnosis (votecast construction -> encode -> decode -> node preimage)
#include <hsma/msscvote.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/dkg_vss.hpp>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    using namespace hsma;
    // ---- replicate votecast EXACTLY (post-conform) ----
    hsma::threshold::vss::Transcript T{};
    if (!hsma::threshold::vss::deal(T, 0, 3, 2)) { std::printf("deal FAILED\n"); return 1; }
    threshold::Poly poly = T.f;
    threshold::Fr S1 = threshold::dkg::share_for(poly, 1);

    auto wr = consensus::sha256d((const std::uint8_t*)"wr", 2);
    auto cf = consensus::sha256d((const std::uint8_t*)"cf", 2);
    auto pr = consensus::sha256d((const std::uint8_t*)"prefA", 5);
    auto pre_vc = msscvote::vote_preimage(0, wr, cf, 0, pr);
    auto sig    = msscvote::sign_vote(S1, pre_vc);
    auto msg    = msscvote::encode_vote(0, wr, cf, 0, pr, sig);
    std::printf("payload=%zu bytes\n", msg.payload.size());

    // ---- replicate the NODE exactly (decode -> reconstruct -> verify loop) ----
    auto dv = msscvote::decode_vote(msg);
    std::printf("decode ok=%d epoch=%u round=%llu\n", (int)dv.ok, dv.epoch, (unsigned long long)dv.round);
    if (!dv.ok) { std::printf("VERDICT: decode failed - encode/decode mismatch\n"); return 1; }
    auto pre_node = msscvote::vote_preimage(dv.epoch, dv.weight_root, dv.conflict, dv.round, dv.preference);

    // ---- THE VERDICTS ----
    std::printf("A. preimage match: %s", std::memcmp(pre_vc.data(), pre_node.data(), pre_vc.size()) == 0 ? "TRUE" : "FALSE");
    if (std::memcmp(pre_vc.data(), pre_node.data(), pre_vc.size()) != 0) {
        for (size_t i = 0; i < pre_vc.size() && i < pre_node.size(); ++i)
            if (pre_vc[i] != pre_node[i]) { std::printf("  (first diff at byte %zu: vc=%02x node=%02x)", i, pre_vc[i], pre_node[i]); break; }
    }
    std::printf("\n");

    // sigma integrity through the wire
    std::uint64_t ax[6], ay[6], bx[6], by[6];
    bool sa = threshold::g1::to_affine(sig, ax, ay);
    bool sb = threshold::g1::to_affine(dv.sigma, bx, by);
    std::printf("B. sigma round-trip: %s\n", (sa && sb && !std::memcmp(ax,bx,sizeof ax) && !std::memcmp(ay,by,sizeof ay)) ? "TRUE" : "FALSE");

    // full node verify loop against transcript publics
    for (std::uint64_t j = 1; j <= 3; ++j) {
        bool v = msscvote::verify_vote(dv.sigma, pre_node, T.Y[j]);
        std::printf("C. verify vs Y%llu: %s\n", (unsigned long long)j, v ? "TRUE" : "FALSE");
    }
    return 0;
}
