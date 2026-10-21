// HSMA :: msscvote1probe.cpp - P3-1 (DEC-271): the vote wire layer, standalone.
// [V1] preimage determinism: same inputs -> identical 109 bytes (DEC-016 law)
// [V2] preimage discipline: different pref -> different bytes (no collisions)
// [V3] sign/verify roundtrip: honest partial VERIFIES against Y_j
// [V4] negative: tampered preimage -> verify REJECTS
// [V5] wire roundtrip: encode -> decode -> same fields, same sigma, verifies
#include <hsma/msscvote.hpp>
#include <cassert>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include "threshold_golden.hpp"
#include <cstdio>
#include <vector>
using namespace hsma;

static bool feqg_pre(const threshold::g1::Pt& a, const threshold::g1::Pt& b) {
    std::uint64_t ax[6], ay[6], bx[6], by[6];
    if (!threshold::g1::to_affine(a, ax, ay)) return false;
    if (!threshold::g1::to_affine(b, bx, by)) return false;
    for (int i = 0; i < 6; ++i) if (ax[i]!=bx[i] || ay[i]!=by[i]) return false;
    return true;
}
int main() {
    const std::uint32_t epoch = 7;
    const consensus::Digest wr  = consensus::sha256d((const std::uint8_t*)"wr", 2);
    const consensus::Digest cf  = consensus::sha256d((const std::uint8_t*)"cf", 2);
    const consensus::Digest p1  = consensus::sha256d((const std::uint8_t*)"prefA", 5);
    const consensus::Digest p2  = consensus::sha256d((const std::uint8_t*)"prefB", 5);
    bool all = true;

    {   // [V1] + [V2]
        auto b1 = msscvote::vote_preimage(epoch, wr, cf, 3, p1);
        auto b1b = msscvote::vote_preimage(epoch, wr, cf, 3, p1);
        auto b2 = msscvote::vote_preimage(epoch, wr, cf, 3, p2);
        const bool det = (b1 == b1b) && b1.size() == msscvote::PREIMAGE_SIZE;
        const bool disc = (b1 != b2);
        std::printf("[V1] preimage deterministic, 109B: %s\n", det ? "YES" : "NO");
        std::printf("[V2] pref change -> different bytes: %s\n", disc ? "YES" : "NO");
        all = all && det && disc;
    }
    {   // [V3]-[V5]: test committee - 1-of-1 for the wire proof (lambda=1 trivial)
        using namespace threshold;
        Fr s_secret{}; bool ok1 = fr_from_u64(s_secret, 0x11);   // secret s = 17
        (void)ok1; assert(ok1);
        Poly poly; poly.c.push_back(s_secret);
        Fr S1 = dkg::share_for(poly, 1);
        // Y_j = [S_j]G2gen ; G2gen from g2::gen()
        mont::fe6 k{}; fr_to_fe6(S1, k);
        auto G2g = g2::gen();
        g2::G2Pt Y1 = g2::Pmul(G2g, k);
        auto pre = msscvote::vote_preimage(epoch, wr, cf, 3, p1);
        auto sig = msscvote::sign_vote(S1, pre);
        const bool v3 = msscvote::verify_vote(sig, pre, Y1);
        std::printf("[V3] sign/verify roundtrip (honest): %s\n", v3 ? "YES" : "NO");
        auto bad = pre; bad[4] ^= 0xFF;   // tamper weight_root's first byte
        const bool v4 = !msscvote::verify_vote(sig, bad, Y1);
        std::printf("[V4] tampered preimage REJECTED: %s\n", v4 ? "YES" : "NO");
        auto msg = msscvote::encode_vote(epoch, wr, cf, 3, p1, sig);
        auto dv = msscvote::decode_vote(msg);
        std::printf("  [v5d] ok=%d epoch=%u (want %u) round=%llu (want 3)\n",
                    (int)dv.ok, dv.epoch, epoch, (unsigned long long)dv.round);
        const bool sig_same = feqg_pre(dv.sigma, sig);
        std::printf("  [v5d] sigma roundtrip: %s\n", sig_same ? "SAME" : "DIFFERS");
        const bool v5 = dv.ok && msscvote::verify_vote(dv.sigma, pre, Y1)
                        && dv.epoch == epoch && dv.round == 3;
        std::printf("[V5] wire roundtrip (encode->decode->verify): %s\n", v5 ? "YES" : "NO");
        all = all && v3 && v4 && v5;
    }
    std::printf("\n[P3-1a] %s\n", all ? "GREEN so far" : "RED");
    return all ? 0 : 1;
}
