// HSMA :: threshold/h2g1.hpp — hash-to-G1 (Step 9, DEC-189).
// Kernel try-and-increment pattern: SHA-256 counter preimage -> QR gate ->
// tonelli -> even-y law -> cofactor clear. Counter = advancing entropy +
// starvation guard (CA-R38 law). Deterministic; [r]H(m) = inf by construction
// (cofactor clear). Production RFC-9380 SSWU is a Phase-1+ hardening candidate;
// current grind-resistance = SHA-256 preimage resistance (honest scope).
#pragma once
#include <hsma/threshold/g1.hpp>
#include <hsma/sha256.hpp>
#include <cstdio>
#include <cstdlib>

namespace hsma::threshold {

inline g1::Pt hash_to_g1(const std::uint8_t* m, std::size_t n) {
    static constexpr char TAG[] = "HSM_H2G1_v1";   // 11 bytes
    const g1::Ctx& CX = g1::ctx();
    const mont::MCtx& QC = CX.m;
    for (std::uint32_t c = 0; c < 1024; ++c) {
        digest::Sha256 h;
        h.update(reinterpret_cast<const std::uint8_t*>(TAG), sizeof(TAG) - 1);
        const std::uint8_t ml[4] = { std::uint8_t(n), std::uint8_t(n >> 8),
                                     std::uint8_t(n >> 16), std::uint8_t(n >> 24) };
        h.update(ml, 4);
        h.update(m, n);
        const std::uint8_t cb[4] = { std::uint8_t(c), std::uint8_t(c >> 8),
                                     std::uint8_t(c >> 16), std::uint8_t(c >> 24) };
        h.update(cb, 4);
        std::uint8_t d[32];
        h.finish(d);
        mont::fe6 x{};                                // DEC-127
        for (int k = 0; k < 4; ++k)
            for (int b = 0; b < 8; ++b)
                x[k] |= std::uint64_t(d[k * 8 + b]) << (8 * b);    // LE limbs
        const mont::fe6 Mx = mont::mfrom(QC, x);
        const mont::fe6 rhsM = mont::madd(QC,
            mont::mmul(QC, mont::mmul(QC, Mx, Mx), Mx), CX.b);
        if (!(mont::mpow(QC, rhsM, CX.halfq) == QC.r1)) continue;   // QR gate
        mont::fe6 y = g1::tonelli_q(mont::mto(QC, rhsM));
        if (y[0] & 1ULL) y = g1::cneg(y);             // even-y law
        g1::Pt P; P.x = Mx; P.y = mont::mfrom(QC, y); P.z = QC.r1;
        P = g1::Pmul(P, CX.h1);                       // cofactor clear
        if (g1::PisInf(P)) continue;
        return P;
    }
    std::fprintf(stderr, "FATAL: h2g1 starved (1024)\n");
    std::abort();
}

} // namespace hsma::threshold
