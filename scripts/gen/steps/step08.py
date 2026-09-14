# HSMA :: gen/steps/step08.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 8 APPEND — E(F_q) promotion: constants + affine-EC goldens (DEC-185..188) ═══
import hashlib as _h8, os as _os8

_S8_M64 = (1 << 64) - 1
_S8_X = 0x8508c00000000001   # matches SEED_X; identity-anchored (CA-R32 doctrine)

def _step8_fatal(msg):
    print("[step8] FATAL: " + msg); raise SystemExit(1)

def _s8_row6(v):
    return "{0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull}" % (
        v & _S8_M64, (v >> 64) & _S8_M64, (v >> 128) & _S8_M64,
        (v >> 192) & _S8_M64, (v >> 256) & _S8_M64, (v >> 320) & _S8_M64)

def _s8_rows6(vals):
    return ",\n    ".join(_s8_row6(v) for v in vals)

def _s8_pair_rows(Ps):
    return ",\n    ".join("{ " + _s8_row6(p[0]) + ", " + _s8_row6(p[1]) + " }" for p in Ps)

def _s8_draw(n_, limit, salt):   # 256-bit draws: <q(377b) always; <r(253b) ~1/8
    out = []; i = 0
    while len(out) < n_:
        v = int.from_bytes(_h8.sha256(salt + i.to_bytes(8, "big")).digest(), "big")
        i += 1
        if 0 < v < limit: out.append(v)
    return out

def _s8_tonelli(a, q):
    if a % q == 0: return 0
    e = 0; s = q - 1
    while s % 2 == 0: s //= 2; e += 1
    z = 2
    while pow(z, (q - 1) // 2, q) != q - 1: z += 1
    M, c, t, R = e, pow(z, s, q), pow(a, s, q), pow(a, (s + 1) // 2, q)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1: t2 = t2 * t2 % q; i += 1
        b = pow(c, 1 << (M - i - 1), q)
        M, c, t = i, b * b % q, t * b * b % q
        R = R * b % q            # UNCONDITIONAL (kernel invariant R^2 = t*a)
    return R

def _s8_add(P, Q, q):           # affine E: y^2 = x^3 + 1; None = infinity
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % q == 0: return None
        lam = (3 * x1 * x1) * pow(2 * y1, -1, q) % q
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, q) % q
    x3 = (lam * lam - x1 - x2) % q
    return (x3, (lam * (x1 - x3) - y1) % q)

def _s8_mul(P, k, q):
    R, A = None, P
    while k:
        if k & 1: R = _s8_add(R, A, q)
        A = _s8_add(A, A, q)
        k >>= 1
    return R

def _s8_pt_from_x(x, q):
    rhs = (pow(x, 3, q) + 1) % q
    if pow(rhs, (q - 1) // 2, q) != 1: return None
    return (x, _s8_tonelli(rhs, q))

def _step8_params():
    x = _S8_X
    r = x**4 - x**2 + 1
    if r != _DOCUMENTED_R: _step8_fatal("r != step7 documented r")
    if (x - 1)**2 % 3 != 0: _step8_fatal("(x-1)^2 mod 3 != 0")
    h1 = (x - 1)**2 // 3
    q = h1 * r + x
    if q % (1 << 64) != x: _step8_fatal("ancestry: q low limb != x")
    if q.bit_length() != 377 or r.bit_length() != 253: _step8_fatal("widths q/r")
    if not _step7_prime(q): _step8_fatal("q failed MR")
    if not _step7_prime(r): _step8_fatal("r failed MR")
    e = 0; s = q - 1
    while s % 2 == 0: s //= 2; e += 1
    gy = _s8_tonelli(2, q)
    if gy * gy % q != 2: _step8_fatal("gy^2 != 2")
    if gy & 1: gy = q - gy                 # kernel law: even low limb
    if gy & 1: _step8_fatal("gy parity")
    GEN = _s8_mul((1, gy), h1, q)          # cofactor-cleared generator
    if GEN is None: _step8_fatal("GEN vanished")
    gx, gyy = GEN
    if (gyy * gyy - (gx * gx * gx + 1)) % q != 0: _step8_fatal("GEN off curve")
    if _s8_mul(GEN, r, q) is not None: _step8_fatal("GEN not in r-subgroup")
    return dict(x=x, r=r, h1=h1, q=q, e=e, sodd=s, gy=gy,
                gen=(gx, gyy), ne=h1 * r,
                one=pow(2, 384, q), r2=pow(2, 768, q), m2=q - 2,
                halfq=(q - 1) // 2, n0=(-pow(q, -1, 1 << 64)) % (1 << 64))

def _step8():
    P8 = _step8_params()
    print("[t8] params OK")
    q, r, e, sodd = P8["q"], P8["r"], P8["e"], P8["sodd"]
    FQ = 48
    A = _s8_draw(FQ, q, b"HSM_G8_FQ_A"); B = _s8_draw(FQ, q, b"HSM_G8_FQ_B")
    ADD = [(a + b) % q for a, b in zip(A, B)]
    SUB = [(a - b) % q for a, b in zip(A, B)]
    MUL = [a * b % q for a, b in zip(A, B)]
    pts = []
    _att = 0
    while len(pts) < 4:
        cand = _s8_draw(1, q, b"HSM_G8_PX" + _att.to_bytes(8, "big"))[0]
        _att += 1
        if _att > 1000: _step8_fatal("pts starved")
        P = _s8_pt_from_x(cand, q)
        if P is not None: pts.append(P)
    ADDT = []
    for i in range(4):
        Pp, Qq = pts[i], pts[(i + 1) % 4]
        Rr = _s8_add(Pp, Qq, q)
        if Rr is None: _step8_fatal("add triple infinity - redraw salt")
        ADDT.append((Pp, Qq, Rr))
    DBLT = []
    for Pp in pts:
        D = _s8_add(Pp, Pp, q)
        if D is None: _step8_fatal("dbl infinity")
        DBLT.append((Pp, D))
    ks = _s8_draw(4, r, b"HSM_G8_K")
    print("[t8] ks drawn (r-limit draws healthy)")
    MULt = []
    for i in range(4):
        Rr = _s8_mul(pts[i], ks[i], q)
        if Rr is None: _step8_fatal("mul triple infinity - redraw salt")
        MULt.append((ks[i], pts[i], Rr))
    TS = []
    _att = 0
    while len(TS) < 8:
        v = _s8_draw(1, q, b"HSM_G8_TS" + _att.to_bytes(8, "big"))[0]
        _att += 1
        if _att > 1000: _step8_fatal("TS starved")
        if pow(v, (q - 1) // 2, q) != 1: continue
        TS.append((v, _s8_tonelli(v, q)))
    for v, w in TS:
        if w * w % q != v: _step8_fatal("TS w^2 != v")
    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1: _step8_fatal("ambiguous generated dirs")
    outdir = cdirs.pop()
    hp = ("// GENERATED by scripts/gen_constants.py - STEP 8 (DEC-186). DO NOT EDIT.\n"
          "// Provenance: q = h1*r + x, h1 = (x-1)^2/3, r = x^4-x^2+1, x = 0x8508c00000000001\n"
          "// (identity-anchored vs SEED_X, CA-R32). Validated: q,r MR-52; widths 377/253;\n"
          "// ancestry; gy^2=2; GEN on-curve; [r]GEN = inf (Python affine oracle).\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::blsq {\n")
    hp += "inline constexpr std::uint64_t Q_MOD[6] = %s;\n" % _s8_row6(q)
    hp += "inline constexpr std::uint64_t Q_R1[6] = %s;  // 2^384 mod q\n" % _s8_row6(P8["one"])
    hp += "inline constexpr std::uint64_t Q_R2[6] = %s;  // 2^768 mod q\n" % _s8_row6(P8["r2"])
    hp += "inline constexpr std::uint64_t Q_M2[6] = %s;  // q - 2\n" % _s8_row6(P8["m2"])
    hp += "inline constexpr std::uint64_t Q_HALFQ[6] = %s;  // (q-1)/2\n" % _s8_row6(P8["halfq"])
    hp += "inline constexpr std::uint64_t Q_RMOD[6] = %s;  // r (subgroup exponent)\n" % _s8_row6(r)
    hp += "inline constexpr std::uint64_t Q_H1[6] = %s;  // cofactor\n" % _s8_row6(P8["h1"])
    hp += "inline constexpr std::uint64_t Q_SODD[6] = %s;  // odd part of q-1\n" % _s8_row6(sodd)
    hp += "inline constexpr std::uint64_t Q_NE[6] = %s;  // h1*r = #E\n" % _s8_row6(P8["ne"])
    hp += "inline constexpr std::uint64_t Q_GEN_X[6] = %s;  // generator x, affine canonical\n" % _s8_row6(P8["gen"][0])
    hp += "inline constexpr std::uint64_t Q_GEN_Y[6] = %s;  // generator y, affine canonical\n" % _s8_row6(P8["gen"][1])
    hp += "inline constexpr std::uint64_t Q_N0 = 0x%016xull;  // -q^-1 mod 2^64\n" % P8["n0"]
    hp += "inline constexpr unsigned Q_E = %uu;  // 2-adicity of q-1\n}\n" % e
    hg = ("// GENERATED by scripts/gen_constants.py - STEP 8 (DEC-187). DO NOT EDIT.\n"
          "// Oracle: Python plain-int AFFINE EC (independent of C++ Jacobian/Montgomery).\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n")
    hg += "inline constexpr unsigned G8_FQ = %uu;\n" % FQ
    for nm, vv in (("G8_A", A), ("G8_B", B), ("G8_ADD", ADD), ("G8_SUB", SUB), ("G8_MUL", MUL)):
        hg += "inline constexpr std::uint64_t %s[G8_FQ][6] = {\n    %s\n};\n" % (nm, _s8_rows6(vv))
    hg += "inline constexpr std::uint64_t G8_ADD_P[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[0] for t in ADDT])
    hg += "inline constexpr std::uint64_t G8_ADD_Q[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[1] for t in ADDT])
    hg += "inline constexpr std::uint64_t G8_ADD_R[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[2] for t in ADDT])
    hg += "inline constexpr std::uint64_t G8_DBL_P[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[0] for t in DBLT])
    hg += "inline constexpr std::uint64_t G8_DBL_R[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[1] for t in DBLT])
    hg += "inline constexpr std::uint64_t G8_MUL_K[4][6] = {\n    %s\n};\n" % _s8_rows6(ks)
    hg += "inline constexpr std::uint64_t G8_MUL_P[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[1] for t in MULt])
    hg += "inline constexpr std::uint64_t G8_MUL_R[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[2] for t in MULt])
    hg += "inline constexpr std::uint64_t G8_TS_X[8][6] = {\n    %s\n};\n" % _s8_rows6([t[0] for t in TS])
    hg += "inline constexpr std::uint64_t G8_TS_W[8][6] = {\n    %s\n};\n}\n" % _s8_rows6([t[1] for t in TS])
    open(_os8.path.join(outdir, "bls_q_params_gen.hpp"), "w").write(hp)
    print("[t8] bls_q_params_gen.hpp written")
    open(_os8.path.join(outdir, "bls_curve_golden.hpp"), "w").write(hg)
    print("[t8] bls_curve_golden.hpp written")
    print("[validate] bls-q: MR-52 prime, 377 bits, ancestry OK, 2adic(q-1)=%d" % e)
    print("[step8][emit] bls_q_params_gen.hpp (q, mont consts, GEN)")
    print("[step8][emit] bls_curve_golden.hpp (%d fq pairs, 4+4+4 triples, 8 tonelli)" % FQ)

_step8()
