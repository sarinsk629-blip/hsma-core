// HSMA :: gemm_backend.hpp - Phase 6.5 (the GEMM backend).
// CPU path IS the conformance reference: the original inline fe_mul/fe_add loop.
// The GPU path (HSMA_CUDA) must be BIT-IDENTICAL — enforced by test_step40.
// Speed is the bonus; identity is the gate. DEC-090: integer-only here.
#pragma once
#include <cstdint>
#include <cstddef>
#include <hsma/fe.hpp>

namespace hsma::pouw {

// CPU reference GEMM over the Pallas field — the original loop, verbatim.
inline void gemm_cpu(const fp::fe* A, const fp::fe* B, fp::fe* C, unsigned n) noexcept {
    for (unsigned i = 0; i < n; ++i)
        for (unsigned j = 0; j < n; ++j) {
            fp::fe acc = fp::fe_zero();
            for (unsigned k = 0; k < n; ++k)
                acc = fp::fe_add(acc, fp::fe_mul(A[(std::size_t)i*n+k], B[(std::size_t)k*n+j]));
            C[(std::size_t)i*n+j] = acc;
        }
}

#ifndef HSMA_CUDA
inline bool gpu_available() noexcept { return false; }
inline bool gemm_gpu(const fp::fe*, const fp::fe*, fp::fe*, unsigned) noexcept { return false; }
#endif

// Unified entry: GPU when available and n is large enough to pay the
// transfer cost, else the CPU reference. Returns true if GPU computed it.
inline bool gemm(const fp::fe* A, const fp::fe* B, fp::fe* C, unsigned n) noexcept {
    if (gpu_available() && n >= 128) {
        if (gemm_gpu(A, B, C, n)) return true;
    }
    gemm_cpu(A, B, C, n);
    return false;
}

} // namespace hsma::pouw
