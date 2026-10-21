// HSMA :: test_step56 - Phase 6.20 (DEC-s4): the REAL model registry.
// The owned defect: /register_model fabricated a commitment, printed, and
// forgot — the P5-G Registry class never held state and no workload was ever
// admitted against it. s4 made the registry REAL; this test pins the exact
// semantics the node now rides:
//   P1 registration      : register lands state; duplicate REJECTED
//   P2 admission         : (digest, r) opening recomputes C -> ADMITTED
//   P3 rejection paths   : wrong digest / wrong r / unknown model REJECTED
//   P4 digest binding    : different weight bytes -> different digest
//                          (collision-resistance at the API boundary)
//   P5 the node flow     : replica-exact submission semantics — digest over
//                          the SUBMITTED bytes (A||B canonical LE), registered
//                          model, admission true; flip ONE byte of the
//                          submission -> digest moves -> REJECTED. The
//                          binding binds the workload the node actually
//                          receives, not an abstraction of it.
#include <hsma/pouw/model_commit.hpp>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace hsma;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

int main() {
    std::printf("test_step56: the REAL model registry — registration, admission, rejection\n");

    // ---- P1: registration is state, not a print ----
    pouw::mcommit::Registry reg;
    {
        std::uint8_t w[64]; for (int i = 0; i < 64; ++i) w[i] = (std::uint8_t)(7 + i);
        const auto D = pouw::mcommit::weight_digest(w, 64);
        const auto C = pouw::mcommit::commit(D, 77);
        chk(reg.register_model(7, C), "P1 model 7 registered");
        chk(reg.size() == 1, "P1 registry HOLDS the state (size == 1)");
        chk(!reg.register_model(7, C), "P1 duplicate registration REJECTED");
        chk(!reg.entries().empty() && reg.entries().count(7) == 1,
            "P1 entries() exposes the committed view");
    }

    // ---- P2/P3: admission + the three rejection paths ----
    {
        std::uint8_t w[64]; for (int i = 0; i < 64; ++i) w[i] = (std::uint8_t)(9 + i);
        const auto D = pouw::mcommit::weight_digest(w, 64);
        const auto C = pouw::mcommit::commit(D, 91);
        reg.register_model(9, C);
        chk(reg.workload_admitted(9, D, 91), "P2 correct opening ADMITTED");
        chk(!reg.workload_admitted(9, D + 1, 91), "P3 wrong digest REJECTED");
        chk(!reg.workload_admitted(9, D, 92), "P3 wrong r REJECTED");
        chk(!reg.workload_admitted(42, D, 91), "P3 unknown model REJECTED");
    }

    // ---- P4: the digest is weight-sensitive ----
    {
        std::uint8_t w1[64], w2[64];
        for (int i = 0; i < 64; ++i) { w1[i] = (std::uint8_t)(3 + i); w2[i] = (std::uint8_t)(3 + i); }
        w2[63] ^= 0x01;   // one bit
        const auto D1 = pouw::mcommit::weight_digest(w1, 64);
        const auto D2 = pouw::mcommit::weight_digest(w2, 64);
        chk(D1 != D2, "P4 one flipped weight bit -> different digest");
        // domain separation: the digest is HSM_MDL_v1-blocked (DEF-248 sizing)
        std::uint8_t w3[33]; for (int i = 0; i < 33; ++i) w3[i] = (std::uint8_t)i;
        const auto D3a = pouw::mcommit::weight_digest(w3, 33);
        const auto D3b = pouw::mcommit::weight_digest(w3, 32);
        chk(D3a != D3b, "P4 length sensitivity (33 vs 32 bytes) — no truncation ambiguity");
    }

    // ---- P5: the node submission flow, replica-exact ----
    {
        // the node builds mcat = A_raw || B_raw (canonical LE) and digests it
        const unsigned n = 4;
        const std::size_t nb = (std::size_t)n * n * 32;
        std::vector<std::uint8_t> A(nb), B(nb);
        std::uint64_t st = 0x4D444C56ull;   // "MDLV"
        for (std::size_t k = 0; k < nb; ++k) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            A[k] = (std::uint8_t)(st >> 24);
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            B[k] = (std::uint8_t)(st >> 24);
        }
        std::vector<std::uint8_t> mcat;
        mcat.reserve(2 * nb);
        mcat.insert(mcat.end(), A.begin(), A.end());
        mcat.insert(mcat.end(), B.begin(), B.end());
        const auto Dsub = pouw::mcommit::weight_digest(mcat.data(), mcat.size());
        // the model owner registers a model whose committed weights ARE this
        // workload's input material (testnet dev-model; production: the
        // owner's real weight tensor)
        const auto C = pouw::mcommit::commit(Dsub, 1234567);
        reg.register_model(1001, C);
        chk(reg.workload_admitted(1001, Dsub, 1234567),
            "P5 submission-flow replica: digest(submitted bytes) + r ADMITTED against the registered model");
        // the adversarial submission: ONE byte of A flipped
        std::vector<std::uint8_t> mcat_bad = mcat;
        mcat_bad[5] ^= 0x01;
        const auto Dsub_bad = pouw::mcommit::weight_digest(mcat_bad.data(), mcat_bad.size());
        chk(Dsub_bad != Dsub, "P5 one flipped submission byte -> different digest");
        chk(!reg.workload_admitted(1001, Dsub_bad, 1234567),
            "P5 the doctored submission is REJECTED (binding binds the real bytes)");
    }

    std::printf("%s\n", "test_step56: DONE — the registry is real (state, admission, rejection, byte-binding)");
    return fails;
}
