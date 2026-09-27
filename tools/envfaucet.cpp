// HSMA :: envfaucet.cpp - P4-3: send encrypted envelopes to a node.
#include <hsma/m2envelope.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/poly.hpp>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
using namespace hsma;

int main(int argc, char** argv) {
    const char* host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 31233;
    // X_E = [0x11]G2gen (the degree-0 secret from P4-1/P4-2)
    threshold::Fr s{}; threshold::fr_from_u64(s, 0x11);
    threshold::mont::fe6 sk{}; threshold::fr_to_fe6(s, sk);
    auto X_E = threshold::g2::Pmul(threshold::g2::gen(), sk);

    int fd = p2p::connect_peer(0x7F000001, (std::uint16_t)port);
    if (fd < 0) { std::printf("[envfaucet] connect FAILED\n"); return 1; }

    for (int i = 0; i < 3; ++i) {
        char payload[32];
        snprintf(payload, sizeof(payload), "encrypted-decree-%d", i);
        std::vector<std::uint8_t> pl(payload, payload + strlen(payload));
        // vary r per envelope
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
        env.ct = pl;
        threshold::m2::dem_encrypt(env.ct, env.tag, k, hdr, pl.data(), pl.size());
        auto r_ser = m2env::pt_to_bytes(env.R);
        threshold::m2::ct_hash(env.cth, r_ser.data(), env.ct.data(), env.ct.size());
        auto msg = m2env::encode_envelope(env);
        p2p::send_message(fd, msg);
        std::printf("[envfaucet] envelope %d sent (%zu bytes payload encrypted)\n", i, pl.size());
    }
    close(fd);
    return 0;
}
