// HSMA :: gemm_pallas.cu - Phase 6.5 (the CUDA GEMM kernel over Pallas).
// BIT-IDENTITY CONTRACT (CA-R273): replicates fe.hpp's SOS Montgomery
// multiply and canonical add limb-for-limb. test_step40 memcmp's GPU
// output against the CPU reference - one differing limb is a failure.
// Self-contained by CA-R275: no host-only headers cross this file.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstddef>

namespace {

using u64 = unsigned long long;

__device__ inline bool d_geq(const u64* a, const u64* b) {
    for (int i = 3; i >= 0; --i) { if (a[i] != b[i]) return a[i] > b[i]; }
    return true;
}
// r = a - b assuming a >= b (mirror of fe.hpp sub_assumed)
__device__ inline void d_sub_assumed(u64* r, const u64* a, const u64* b) {
    u64 borrow = 0;
    for (int i = 0; i < 4; ++i) {
        const u64 t1 = a[i] - b[i];
        const u64 b1 = (a[i] < b[i]) ? 1u : 0u;
        const u64 t2 = t1 - borrow;
        const u64 b2 = (t1 < borrow) ? 1u : 0u;
        r[i] = t2;
        borrow = b1 | b2;
    }
}
// mirror of fe.hpp fe_add: c || geq(r, MOD) -> ONE subtract (sum < 2p)
__device__ inline void d_fe_add(u64* r, const u64* a, const u64* b, const u64* mod) {
    u64 c = 0;
    for (int i = 0; i < 4; ++i) {
        const u64 lo  = a[i] + b[i];
        const u64 c1  = (lo < a[i]) ? 1u : 0u;
        const u64 lo2 = lo + c;                       // c in {0,1}
        const u64 c2  = (lo2 < c) ? 1u : 0u;          // fires iff lo==~0 && c==1
        r[i] = lo2;
        c = c1 | c2;
    }
    if (c || d_geq(r, mod)) d_sub_assumed(r, r, mod);
}
// mirror of fe.hpp fe_mul (SOS): exact u128 semantics via __umul64hi + carries
__device__ inline void d_fe_mul(u64* r, const u64* A, const u64* B,
                                const u64* mod, u64 inv) {
    u64 T[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; ++i) {                     // (1) schoolbook
        u64 carry = 0;
        for (int j = 0; j < 4; ++j) {
            const u64 plo = A[j] * B[i];
            const u64 phi = __umul64hi(A[j], B[i]);
            const u64 lo  = T[i+j] + plo;
            const u64 e1  = (lo < T[i+j]) ? 1u : 0u;
            const u64 lo2 = lo + carry;
            const u64 e2  = (lo2 < lo) ? 1u : 0u;
            T[i+j] = lo2;
            carry = phi + e1 + e2;                    // SOS bound: < 2^64
        }
        int k = i + 4;
        while (carry) {
            const u64 cur = T[k] + carry;
            const u64 cc  = (cur < T[k]) ? 1u : 0u;
            T[k] = cur; carry = cc; ++k;
        }
    }
    for (int i = 0; i < 4; ++i) {                     // (2) Montgomery folds
        const u64 m    = T[i] * inv;
        const u64 plo0 = m * mod[0];
        const u64 phi0 = __umul64hi(m, mod[0]);
        const u64 lo0  = T[i] + plo0;
        const u64 e0   = (lo0 < T[i]) ? 1u : 0u;
        u64 carry = phi0 + e0;                        // == (T[i]+m*MOD[0])>>64
        for (int j = 1; j < 4; ++j) {
            const u64 plo = m * mod[j];
            const u64 phi = __umul64hi(m, mod[j]);
            const u64 lo  = T[i+j] + plo;
            const u64 e1  = (lo < T[i+j]) ? 1u : 0u;
            const u64 lo2 = lo + carry;
            const u64 e2  = (lo2 < lo) ? 1u : 0u;
            T[i+j] = lo2;
            carry = phi + e1 + e2;
        }
        int k = i + 4;
        while (carry) {
            const u64 cur = T[k] + carry;
            const u64 cc  = (cur < T[k]) ? 1u : 0u;
            T[k] = cur; carry = cc; ++k;
        }
    }
    for (int i = 0; i < 4; ++i) r[i] = T[4+i];        // (3) one conditional sub
    if (d_geq(r, mod)) d_sub_assumed(r, r, mod);
}

__global__ void gemm_pallas_kernel(const u64* __restrict__ A,
                                   const u64* __restrict__ B,
                                   u64* __restrict__ C,
                                   unsigned n, const u64* __restrict__ mod, u64 inv) {
    const unsigned i = blockIdx.y * blockDim.y + threadIdx.y;
    const unsigned j = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n || j >= n) return;
    u64 acc[4] = {0,0,0,0};                           // fe_zero (Montgomery 0)
    for (unsigned k = 0; k < n; ++k) {
        u64 prod[4];
        d_fe_mul(prod, &A[((std::size_t)i*n + k)*4], &B[((std::size_t)k*n + j)*4], mod, inv);
        d_fe_add(acc, acc, prod, mod);
    }
    u64* out = &C[((std::size_t)i*n + j)*4];
    out[0]=acc[0]; out[1]=acc[1]; out[2]=acc[2]; out[3]=acc[3];
}

} // namespace

extern "C" int hsma_gpu_probe() noexcept {
    int ndev = 0;
    if (cudaGetDeviceCount(&ndev) != cudaSuccess) return 0;
    return ndev > 0 ? 1 : 0;
}

extern "C" int hsma_gemm_pallas(const std::uint64_t* A, const std::uint64_t* B,
                                std::uint64_t* C, unsigned n,
                                const std::uint64_t* mod_host,
                                std::uint64_t inv) noexcept {
    int ndev = 0;
    if (cudaGetDeviceCount(&ndev) != cudaSuccess || ndev == 0) return -1;
    const std::size_t bytes = (std::size_t)n * n * 4 * sizeof(std::uint64_t);
    std::uint64_t *dA=nullptr, *dB=nullptr, *dC=nullptr, *dmod=nullptr;
    int rc = -1;
    do {
        if (cudaMalloc((void**)&dA,   bytes) != cudaSuccess) break;
        if (cudaMalloc((void**)&dB,   bytes) != cudaSuccess) break;
        if (cudaMalloc((void**)&dC,   bytes) != cudaSuccess) break;
        if (cudaMalloc((void**)&dmod, 4*sizeof(std::uint64_t)) != cudaSuccess) break;
        if (cudaMemcpy(dA,   A,        bytes, cudaMemcpyHostToDevice) != cudaSuccess) break;
        if (cudaMemcpy(dB,   B,        bytes, cudaMemcpyHostToDevice) != cudaSuccess) break;
        if (cudaMemcpy(dmod, mod_host, 4*sizeof(std::uint64_t), cudaMemcpyHostToDevice) != cudaSuccess) break;
        const dim3 block(16, 16);
        const dim3 grid((n + 15) / 16, (n + 15) / 16);
        gemm_pallas_kernel<<<grid, block>>>((const u64*)dA, (const u64*)dB, (u64*)dC, n, (const u64*)dmod, (u64)inv);
        if (cudaGetLastError() != cudaSuccess) break;
        if (cudaDeviceSynchronize() != cudaSuccess) break;
        if (cudaMemcpy((void*)C, dC, bytes, cudaMemcpyDeviceToHost) != cudaSuccess) break;
        rc = 0;
    } while (false);
    if (dA)   cudaFree(dA);
    if (dB)   cudaFree(dB);
    if (dC)   cudaFree(dC);
    if (dmod) cudaFree(dmod);
    return rc;   // any failure -> caller falls back to the CPU reference
}
