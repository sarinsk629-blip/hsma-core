// HSMA :: test_step40 - Phase 6.5: the GPU must equal the CPU, limb for limb.
// CA-R273 executable form: same seed -> gemm_cpu vs gemm(GPU) -> memcmp == 0.
#include <hsma/fe.hpp>
#include <hsma/pouw/gemm_backend.hpp>
#include <hsma/pouw.hpp>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace hsma;

int main() {
    if (!pouw::gpu_available()) { std::printf("SKIP: no CUDA device\n"); return 0; }
    const unsigned n = 128;
    std::uint64_t st = 0x9E3779B97F4A7C15ull;
    auto rnd = [&st]() -> fp::fe {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        return fp::fe_from_u64(st * 0x9E3779B97F4A7C15ull);
    };
    std::vector<fp::fe> A((std::size_t)n*n), B((std::size_t)n*n), C1((std::size_t)n*n), C2((std::size_t)n*n);
    for (auto& x : A) x = rnd();
    for (auto& x : B) x = rnd();
    pouw::gemm_cpu(A.data(), B.data(), C1.data(), n);          // the reference
    if (!pouw::gemm(A.data(), B.data(), C2.data(), n)) {       // GPU path
        std::printf("FAIL: GPU path not taken despite available device\n");
        return 1;
    }
    if (std::memcmp(C1.data(), C2.data(), (std::size_t)n*n*sizeof(fp::fe)) != 0) {
        std::printf("FAIL: GPU output differs from CPU reference\n");
        return 1;
    }
    const auto PP = pouw::prove_gemm_v2(A, B, C2, n, n, n);    // the full chain
    const bool ok = pouw::verify_gemm_v2(PP, A, B, C2);
    std::printf(ok ? "PASS: GPU==CPU limb-for-limb; sumcheck ACCEPT (n=%u)\n"
                   : "FAIL: sumcheck rejected GPU output\n", n);
    return ok ? 0 : 1;
}
