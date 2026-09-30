// HSMA :: envfaucet.cpp - P4-3: send encrypted envelopes to a node.
#include <hsma/m2envelope.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/poly.hpp>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <hsma/threshold/dkg_vss.hpp>
using namespace hsma;

static threshold::Poly g_test_poly_local() {
    threshold::Fr c1{}, c2{}, c3{};
    threshold::fr_from_u64(c1, 0x11); threshold::fr_from_u64(c2, 0x22); threshold::fr_from_u64(c3, 0x33);
    threshold::Poly p; p.c = {c1, c2, c3};
    return p;
}

int main(int argc, char** argv) {
    const char* host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 31233;
    // X_E = [0x11]G2gen — MUST match the node's g_test_poly.c[0]
    // (the node's g_test_poly = {0x11, 0x22, 0x33} degree-2)
    // the SECRET is c[0] = 0x11; X_E = [0x11]G2gen
    // the node's dec_share uses g_own_share = share_for(g_test_poly, member)
    // for a degree-2 poly, share_for(1) = 0x11 + 0x22 + 0x33 = 0x66 ≠ 0x11
    // THE MISMATCH: the node's share ≠ the secret
    // FIX: the envfaucet encrypts under X_E = [share_for(poly, 1)]·G2gen
    // (= the node's actual share as member 1), so the node's dec_share matches
    hsma::threshold::vss::Transcript ef_T{};
    if (!hsma::threshold::vss::deal(ef_T, 0, 3, 2)) { return 2; }
    threshold::Fr s_secret = ef_T.f.c[0]; // P5-A: beacon-dealt secret = node's g_env_secret
    threshold::mont::fe6 sk{}; threshold::fr_to_fe6(s_secret, sk);
    auto X_E = threshold::g2::Pmul(threshold::g2::gen(), sk);

    // DEF-183 law: the displayed host and the dialed host are the same host.
    std::uint32_t ip = 0x7F000001; // loopback default
    if (host && std::strcmp(host, "127.0.0.1") != 0) {
        struct in_addr a{};
        if (inet_pton(AF_INET, host, &a) != 1) { std::printf("[envfaucet] bad host: %s\n", host); return 1; }
        ip = ntohl(a.s_addr);   // connect_peer contract: HOST-order (p2p.hpp DEF-183 comment) — inet_pton gives network-order, convert
    }
    int fd = p2p::connect_peer(ip, (std::uint16_t)port);
    if (fd < 0) { std::printf("[envfaucet] connect FAILED\n"); return 1; }

    for (int i = 0; i < 10; ++i) {
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
        std::printf("[dbg-sender] xe: ");
        for (int i = 0; i < 8; ++i) std::printf("%02x", xe_b[i]);
        std::printf("\n");
        std::printf("[dbg-sender] ss_full: ");
        for (int i = 0; i < 192; ++i) std::printf("%02x", ss_b[i]);
        std::printf("\n");
        std::printf("[dbg-sender] hdr_full: ");
        for (int i = 0; i < 56; ++i) std::printf("%02x", hdr[i]);
        std::printf("\n");
        std::printf("[dbg-sender] ss: ");
        for (int i = 0; i < 8; ++i) std::printf("%02x", ss_b[i]);
        std::printf(" | hdr: ");
        for (int i = 0; i < 8; ++i) std::printf("%02x", hdr[i]);
        std::printf(" | k: ");
        for (int i = 0; i < 4; ++i) std::printf("%02x", k[i]);
        std::printf("\n");
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
