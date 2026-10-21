// P5-G conformance: ModelCommit — binding proven, and every forgery class rejected.
#include <hsma/pouw/model_commit.hpp>
#include <cstdio>
#include <cstring>
using namespace hsma;
int main(){
    int fails = 0; auto C = [&](bool ok, const char* w){ if(!ok){ std::printf("FAIL: %s\n", w); ++fails; } };

    // a "model": 96 weight bytes (testnet scale)
    std::uint8_t W[96]; for (int i = 0; i < 96; ++i) W[i] = std::uint8_t(i * 7 + 3);
    const auto D = pouw::mcommit::weight_digest(W, 96);

    // digest determinism + tamper sensitivity:
    C(pouw::mcommit::weight_digest(W, 96) == D, "digest deterministic");
    std::uint8_t W2[96]; std::memcpy(W2, W, 96); W2[50] ^= 0x01;   // ONE BIT flipped
    C(pouw::mcommit::weight_digest(W2, 96) != D, "digest tamper-sensitive (1 bit)");

    // register the honest model:
    pouw::mcommit::Registry R;
    const auto r = (std::uint64_t)424242;
    const auto Cm = pouw::mcommit::commit(D, r);
    C(R.register_model(1, Cm), "model registered");
    C(!R.register_model(1, Cm), "double registration rejected");

    // THE POSITIVE: honest workload with the correct opening — ADMITTED
    C(R.workload_admitted(1, D, r), "honest workload admitted (binding verified)");

    // FORGERY CLASS 1: wrong weights (different model) — digest mismatch
    C(!R.workload_admitted(1, pouw::mcommit::weight_digest(W2, 96), r), "forged weights REJECTED");

    // FORGERY CLASS 2: right weights, wrong randomness — commitment mismatch
    C(!R.workload_admitted(1, D, r + 1), "wrong opening REJECTED");

    // FORGERY CLASS 3: unknown model
    C(!R.workload_admitted(99, D, r), "unknown model REJECTED");

    // commitment hiding (structural): different r -> different C for same digest
    C(pouw::mcommit::commit(D, r).C != pouw::mcommit::commit(D, r+1).C, "commitment r-dependent (hiding)");

    std::printf("%s\n", fails ? "test_step39: FAILED" : "test_step39: ALL PASS (ModelCommit: binding + all forgery classes rejected)");
    return fails ? 1 : 0;
}
