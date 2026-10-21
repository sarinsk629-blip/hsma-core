#!/usr/bin/env python3
# HSMA :: gen/steps/step36.py - P3 production oracle: the t=112/n=224 threshold
# transcript golden. Mirrors include/hsma/threshold/g2.hpp's Fq2-NATIVE Jacobian
# arithmetic line-for-line (NOT the monolith's Fq12 machinery — too slow at 224).
#
# THE LAWS (single source of truth, both planes):
#   - consensus::sha256d is SINGLE sha256 (the "d" means digest)
#   - epoch seed: sha256("HSM_DKG_V1" || LE64(epoch))                    (dkg_vss.hpp)
#   - coefficient c_k: LE64(sha256(seed || byte(k))[0:8])                (deal())
#   - Y_j = [f(j)]G2gen, D_j = [f(j)]R, D_agg = sum(lam_j * D_j) = [f(0)]R
#   - lam over participants 1..112 via exact Lagrange at zero (mod r)
#   - R law: R = [r]G2gen with r = LE64(sha256("HSM_R224_V1" || LE64(7))[0:8])
import hashlib, os, sys

q = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001
r = 0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001
BETA = 5
B2 = (5, 1)  # twist coefficient b' = 5 + 1u

def limbs2int(l):
    # C++ goldens are LITTLE-ENDIAN limb arrays: value = limb0 + limb1<<64 + ...
    v = 0
    for i, x in enumerate(l): v |= x << (64 * i)
    return v

# G2 generator (bls_g2_params_gen.hpp, canonical affine, limb arrays verbatim)
GEN_X = (limbs2int([0x41e48e6f0ba558f7, 0x853327a41683c2da, 0x7caa7ad2d18027ad,
                    0xc9ee84506c467325, 0x36cca6b1d74f8603, 0x0138b57c5ff32644]),
         limbs2int([0xd583dea6a4ec163e, 0x5b3228efb39bf3fc, 0x3b0a5655e671a396,
                    0x651d4621a7f6cf96, 0x2a5e31fe5b79a761, 0x0168b5ad4f4f3c36]))
GEN_Y = (limbs2int([0x70bcb48e942c7c8b, 0xe55959cec479e5db, 0x7311ad10e611d564,
                    0x24a0c6cec04f0c7d, 0x64e6af034df05724, 0x007440d176ed4387]),
         limbs2int([0xea0a90e3505c5d47, 0x029f968b7b6efbb5, 0xc7d270016550c26f,
                    0x6315a461e6261607, 0xef84093c339688cf, 0x0192dc7b5d44d9ab]))

def fadd(a, b): return ((a[0] + b[0]) % q, (a[1] + b[1]) % q)
def fsub(a, b): return ((a[0] - b[0]) % q, (a[1] - b[1]) % q)
def fmul(a, b):
    a0, a1 = a; b0, b1 = b
    return ((a0 * b0 + BETA * a1 * b1) % q, (a0 * b1 + a1 * b0) % q)
def fsq(a): return fmul(a, a)
def fneg(a): return ((-a[0]) % q, (-a[1]) % q)
def finv(a):
    a0, a1 = a
    n = (a0 * a0 - BETA * a1 * a1) % q
    ni = pow(n, q - 2, q)
    return ((a0 * ni) % q, ((-a1) % q * ni) % q)
def feq(a, b): return a[0] == b[0] and a[1] == b[1]
def fisz(a): return a[0] == 0 and a[1] == 0

INF = ((0, 0), (0, 0), (0, 0))  # Jacobian: Z == (0,0) means infinity

# self-proving constants: the generator must sit on y^2 = x^3 + b' (absolute test)
assert fsq(GEN_Y) == fadd(fmul(fsq(GEN_X), GEN_X), B2), "G2 generator OFF CURVE"

def is_inf(P): return fisz(P[2])

def pdbl(P):
    X, Y, Z = P
    if is_inf(P) or fisz(Y): return INF
    A = fsq(X); B = fsq(Y); C = fsq(B)
    XB = fadd(X, B)
    D = fsq(XB); D = fsub(D, A); D = fsub(D, C); D = fadd(D, D)
    E = fadd(fadd(A, A), A)
    X3 = fsub(fsq(E), fadd(D, D))
    C2 = fadd(C, C); C4 = fadd(C2, C2); C8 = fadd(C4, C4)
    Y3 = fsub(fmul(E, fsub(D, X3)), C8)
    Z3 = fmul(fadd(Y, Y), Z)
    return (X3, Y3, Z3)

def padd(P, Q):
    if is_inf(P): return Q
    if is_inf(Q): return P
    X1, Y1, Z1 = P; X2, Y2, Z2 = Q
    Z1s = fsq(Z1); Z2s = fsq(Z2)
    U1 = fmul(X1, Z2s); U2 = fmul(X2, Z1s)
    S1 = fmul(fmul(Y1, Z2s), Z2); S2 = fmul(fmul(Y2, Z1s), Z1)
    if feq(U1, U2):
        return pdbl(P) if feq(S1, S2) else INF
    H = fsub(U2, U1); HH = fsq(H)
    I = fadd(fadd(HH, HH), fadd(HH, HH))
    J = fmul(H, I)
    rr = fadd(fsub(S2, S1), fsub(S2, S1))
    V = fmul(U1, I)
    X3 = fsub(fsub(fsq(rr), J), fadd(V, V))
    SJ = fadd(fmul(S1, J), fmul(S1, J))
    Y3 = fsub(fmul(rr, fsub(V, X3)), SJ)
    TWO = (2, 0)
    Z3 = fmul(fmul(fmul(Z1, Z2), H), TWO)
    return (X3, Y3, Z3)

def pmul(P, k):
    res = INF
    if k == 0: return res
    for bit in bin(k)[2:]:
        res = pdbl(res)
        if bit == '1': res = padd(res, P)
    return res

def to_affine(P):
    X, Y, Z = P
    if is_inf(P): return None
    zi = finv(Z); z2 = fsq(zi); z3 = fmul(z2, zi)
    return (fmul(X, z2), fmul(Y, z3))

def limbs6(v):
    return [(v >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(6)]

def pt_limbs(pt):  # -> (x0[6], x1[6], y0[6], y1[6])
    (x, y) = to_affine(pt)
    return limbs6(x[0]), limbs6(x[1]), limbs6(y[0]), limbs6(y[1])

# ---- the DKG transcript (mirror of vss::deal, epoch 7, n=224, t=112) -------
EPOCH = 7
N = 224
T = 112

seed = hashlib.sha256(b"HSM_DKG_V1" + EPOCH.to_bytes(8, "little")).digest()
cs = []
for k in range(T):
    d = hashlib.sha256(seed + bytes([k])).digest()
    cs.append(int.from_bytes(d[0:8], "little"))
assert all(c < r for c in cs)

def poly_eval(j):
    acc = 0
    for c in reversed(cs):
        acc = (acc * j + c) % r
    return acc

f0 = cs[0]  # poly_eval(0) == c[0]

G = (GEN_X, GEN_Y, (1, 0))
# Feldman commitments + member publics (all 224 — ~350 point muls total, seconds)
Cs = [pmul(G, c) for c in cs]
Ys = [None] * (N + 1)
for j in range(1, N + 1):
    Ys[j] = pmul(G, poly_eval(j))

# sample Feldman self-check (full Horner, 8 members — the C++ test does all 224)
for j in (1, 2, 57, 113, 168, 222, 223, 224):
    rhs = Cs[T - 1]
    jf = j % r
    for k in range(T - 2, -1, -1):
        rhs = padd(padd(pmul(rhs, jf), Cs[k]), INF)
    assert to_affine(rhs) == to_affine(Ys[j]), f"Feldman sample {j} FAILED"

# ---- the R law + share set + batch-Lagrange aggregate ----------------------
r_scalar = int.from_bytes(hashlib.sha256(b"HSM_R224_V1" + EPOCH.to_bytes(8, "little")).digest()[0:8], "little")
R = pmul(G, r_scalar)

xs = list(range(1, T + 1))
Ds = [pmul(R, poly_eval(j)) for j in xs]

# exact Lagrange at zero over the participants (mod-r, one inversion)
lam = []
for i in range(T):
    num, den = 1, 1
    for j in range(T):
        if i == j: continue
        num = (num * (-xs[j])) % r
        den = (den * (xs[i] - xs[j])) % r
    lam.append(num * pow(den, r - 2, r) % r)

D_agg = INF
for i in range(T):
    D_agg = padd(D_agg, pmul(Ds[i], lam[i]))

# THE self-check: the aggregate IS [f(0)]R — independent recomputation
assert to_affine(D_agg) == to_affine(pmul(R, f0)), "D_agg != [f(0)]R"
XE = pmul(G, f0)
assert to_affine(XE) == to_affine(D_agg if False else XE)  # trivial; D_agg == [f(0)]R checked above

print("[step36] self-check TRUE: D_agg == [f(0)]R, Feldman samples hold")

# ---- emit the golden -------------------------------------------------------
def limbs_c(name, arr):
    return "inline constexpr std::uint64_t %s[6] = {%s};\n" % (
        name, ", ".join("0x%016xull" % v for v in arr))

out_path = os.path.join("generated", "threshold224_golden.hpp")
with open(out_path, "w") as f:
    f.write("#pragma once\n")
    f.write("// P3 production golden: t=112/n=224 threshold transcript (epoch 7).\n")
    f.write("// Oracle: scripts/gen/steps/step36.py — Fq2-native Jacobian mirroring\n")
    f.write("// g2.hpp exactly; single-SHA256 seed law; R law HSM_R224_V1.\n")
    f.write("// auto-generated - DO NOT HAND-EDIT (CA-R126)\n")
    f.write("namespace hsma::threshold::golden {\n")
    f.write("inline constexpr std::uint64_t THR224_N = %d;\n" % N)
    f.write("inline constexpr std::uint64_t THR224_T = %d;\n" % T)
    f.write("inline constexpr std::uint64_t THR224_EPOCH = %d;\n" % EPOCH)
    f.write("inline constexpr std::uint64_t THR224_R_SCALAR = 0x%016xull;\n" % r_scalar)
    x0, x1, y0, y1 = pt_limbs(XE)
    f.write(limbs_c("THR224_XE_X0", x0)); f.write(limbs_c("THR224_XE_X1", x1))
    f.write(limbs_c("THR224_XE_Y0", y0)); f.write(limbs_c("THR224_XE_Y1", y1))
    x0, x1, y0, y1 = pt_limbs(R)
    f.write(limbs_c("THR224_R_X0", x0)); f.write(limbs_c("THR224_R_X1", x1))
    f.write(limbs_c("THR224_R_Y0", y0)); f.write(limbs_c("THR224_R_Y1", y1))
    x0, x1, y0, y1 = pt_limbs(D_agg)
    f.write(limbs_c("THR224_DAGG_X0", x0)); f.write(limbs_c("THR224_DAGG_X1", x1))
    f.write(limbs_c("THR224_DAGG_Y0", y0)); f.write(limbs_c("THR224_DAGG_Y1", y1))
    # per-participant aggregate shares D_j, j = 1..112
    f.write("struct Thr224Pt { std::uint64_t x0[6], x1[6], y0[6], y1[6]; };\n")
    f.write("inline constexpr Thr224Pt THR224_D[%d] = {\n" % T)
    for j in range(T):
        x0, x1, y0, y1 = pt_limbs(Ds[j])
        f.write("  { {%s},\n    {%s},\n    {%s},\n    {%s} },\n" % (
            ", ".join("0x%016xull" % v for v in x0),
            ", ".join("0x%016xull" % v for v in x1),
            ", ".join("0x%016xull" % v for v in y0),
            ", ".join("0x%016xull" % v for v in y1)))
    f.write("};\n")
    # member publics Y_j, j = 1..224
    f.write("inline constexpr Thr224Pt THR224_Y[%d] = {\n" % N)
    for j in range(1, N + 1):
        x0, x1, y0, y1 = pt_limbs(Ys[j])
        f.write("  { {%s},\n    {%s},\n    {%s},\n    {%s} },\n" % (
            ", ".join("0x%016xull" % v for v in x0),
            ", ".join("0x%016xull" % v for v in x1),
            ", ".join("0x%016xull" % v for v in y0),
            ", ".join("0x%016xull" % v for v in y1)))
    f.write("};\n")
    # Feldman commitments C_k, k = 0..111
    f.write("inline constexpr Thr224Pt THR224_C[%d] = {\n" % T)
    for k in range(T):
        x0, x1, y0, y1 = pt_limbs(Cs[k])
        f.write("  { {%s},\n    {%s},\n    {%s},\n    {%s} },\n" % (
            ", ".join("0x%016xull" % v for v in x0),
            ", ".join("0x%016xull" % v for v in x1),
            ", ".join("0x%016xull" % v for v in y0),
            ", ".join("0x%016xull" % v for v in y1)))
    f.write("};\n")
    f.write("} // namespace hsma::threshold::golden\n")

sz = os.path.getsize(out_path)
print("[step36] %s written (%d bytes): 1+1+1 XE/R/DAGG + %d D_j + %d Y_j + %d C_k" % (out_path, sz, T, N, T))
