// HSMA :: votecast.cpp - P3-1b (DEC-271): cast a signed MSSC vote at a node.
// Usage: votecast HOST PORT [--tamper]
// Holds member 1's share of the PUBLIC test poly (honest testnet scope).
#include <hsma/msscvote.hpp>
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
    bool tamper = argc > 3 && std::strcmp(argv[3], "--tamper") == 0;

    threshold::Fr c1{}, c2{}, c3{};
    if (!threshold::fr_from_u64(c1, 0x11) || !threshold::fr_from_u64(c2, 0x22)
        || !threshold::fr_from_u64(c3, 0x33)) return 2;
    threshold::Poly poly; poly.c = {c1, c2, c3};
    threshold::Fr S1 = threshold::dkg::share_for(poly, 1);

    auto wr = consensus::sha256d((const std::uint8_t*)"wr", 2);
    auto cf = consensus::sha256d((const std::uint8_t*)"cf", 2);
    auto pr = consensus::sha256d((const std::uint8_t*)"prefA", 5);
    auto pre = msscvote::vote_preimage(7, wr, cf, 3, pr);
    if (tamper) pre[4] ^= 0xFF;
    auto sig = msscvote::sign_vote(S1, pre);
    auto msg = msscvote::encode_vote(7, wr, cf, 3, pr, sig);
    if (msg.payload.size() != msscvote::VOTE_PAYLOAD) { std::printf("[votecast] encode FAILED\n"); return 2; }

    // DEF-183's law: host-order ip, htonl inside connect_peer
    int fd = p2p::connect_peer(0x7F000001, (std::uint16_t)port);
    if (fd < 0) { std::printf("[votecast] connect FAILED\n"); return 1; }
    if (!p2p::send_message(fd, msg)) { std::printf("[votecast] send FAILED\n"); close(fd); return 1; }
    std::printf("[votecast] vote sent (%zu bytes payload)%s\n",
                msg.payload.size(), tamper ? " [TAMPERED]" : "");
    close(fd);
    return 0;
}
