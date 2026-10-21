# HSMA :: gen/steps/step26.py — P1-06 NEW-CODE step (GAP-03c, DEC-224).
# Vesta curve y² = x³ + 5 over F_q. Generator: (-1, 2).
# Emits vesta_curve_golden.hpp: add/dbl/mul triples from a Python affine oracle.
import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

B_CONST = 5
M64 = (1 << 64) - 1

def _step26():
    P = lambda *a: print(*a, flush=True)
    C = GC.load_constants()
    q = C["q_vesta"]
    # the group order = p (the Pallas modulus) — the 2-cycle property
    p_order = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

    # affine EC: y^2 = x^3 + 5 over F_q
    def ec_add(Pt, Qt):
        if Pt is None: return Qt
        if Qt is None: return Pt
        x1, y1 = Pt; x2, y2 = Qt
        if x1 == x2 and (y1 + y2) % q == 0: return None
        if Pt == Qt:
            lam = (3 * x1 * x1) * pow(2 * y1, -1, q) % q
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, q) % q
        x3 = (lam * lam - x1 - x2) % q
        y3 = (lam * (x1 - x3) - y1) % q
        return (x3, y3)
    def ec_dbl(Pt):
        return ec_add(Pt, Pt)
    def ec_mul(k, Pt):
        R = None; A = Pt
        while k:
            if k & 1: R = ec_add(R, A)
            A = ec_dbl(A); k >>= 1
        return R

    # generator: (-1, 2) mod q
    G = ((q - 1) % q, 2)
    # verify on-curve
    assert (G[1] * G[1]) % q == (pow(G[0], 3, q) + B_CONST) % q, "gen not on curve"
    P("[step26] generator (-1, 2) on curve y^2 = x^3 + 5: VERIFIED")

    # generate points
    pts = []
    for k in range(1, 17):
        pt = ec_mul(k, G)
        pts.append((k, pt))
        P("[step26] %d*G = (%s, %s)" % (k, hex(pt[0])[:20] if pt else "inf", hex(pt[1])[:20] if pt else "-"))

    # addition triples
    ADD = []
    for i in range(8):
        k1, P1 = pts[i]
        k2, P2 = pts[i + 1]
        P3 = ec_add(P1, P2)
        assert P3 == ec_mul(k1 + k2, G), "add consistency"
        ADD.append((P1, P2, P3))
    P("[step26] 8 addition triples verified")

    # doubling cases
    DBL = []
    for i in range(8):
        k, Pt = pts[i]
        D = ec_dbl(Pt)
        assert D == ec_mul(2 * k, G), "dbl consistency"
        DBL.append((Pt, D))
    P("[step26] 8 doubling cases verified")

    # scalar mul cases
    MULS = []
    for k in [1, 2, 3, 5, 100, 1000, p_order - 1, p_order - 2]:
        R = ec_mul(k, G)
        if R is None: R = (0, 0)  # point at infinity → (0, 0) representation
        MULS.append((k, G, R))
    P("[step26] 8 scalar-mul cases computed (inf → (0,0))")

    # subgroup check: [p]G = inf
    assert ec_mul(p_order, G) is None, "[p]G != inf"
    P("[step26] subgroup: [p]G = inf VERIFIED (the 2-cycle property)")

    # emission
    def _r4(v): return GC.row4(v)
    parts = [
        "// GENERATED FILE - vesta_curve_golden.hpp (P1-06, DEC-224). DO NOT EDIT.",
        "// Vesta curve: y^2 = x^3 + 5 over F_q. Generator: (-1, 2).",
        "// Group order: p (the Pallas modulus, the 2-cycle property).",
        "#pragma once", "#include <array>", "#include <cstdint>",
        "namespace hsma::golden {",
        "inline constexpr unsigned VEC_ADD_N = %du;" % len(ADD),
        "struct VestaAdd { std::uint64_t x1[4], y1[4], x2[4], y2[4], x3[4], y3[4]; };",
        "inline constexpr std::array<VestaAdd, %d> VEC_ADD {{" % len(ADD),
    ]
    for P1, P2, P3 in ADD:
        parts.append("{ " + ", ".join(GC.row4(x) for x in (P1[0], P1[1], P2[0], P2[1], P3[0], P3[1])) + " },")
    parts.append("}};")
    parts.append("inline constexpr unsigned VEC_DBL_N = %du;" % len(DBL))
    parts.append("struct VestaDbl { std::uint64_t x[4], y[4], x2[4], y2[4]; };")
    parts.append("inline constexpr std::array<VestaDbl, %d> VEC_DBL {{" % len(DBL))
    for Pt, D in DBL:
        parts.append("{ " + ", ".join(GC.row4(x) for x in (Pt[0], Pt[1], D[0], D[1])) + " },")
    parts.append("}};")
    parts.append("inline constexpr unsigned VEC_MUL_N = %du;" % len(MULS))
    parts.append("struct VestaMul { std::uint64_t k[4], xr[4], yr[4]; };")
    parts.append("inline constexpr std::array<VestaMul, %d> VEC_MUL {{" % len(MULS))
    for k, Gp, R in MULS:
        if R is None: R = (0, 0)
        kb = [(k >> (64*i)) & M64 for i in range(4)]
        Rb = [(R[0] >> (64*i)) & M64 for i in range(4)] if R != (0, 0) else [0, 0, 0, 0]
        # VestaMul struct: k[4], x[4], y[4], xr[4], yr[4] — but we only need k and xr/yr
        # the struct is: k (scalar), x (gen x), y (gen y), xr (result x), yr (result y)
        # but gen is constant — emit k and R only, the struct becomes k[4], xr[4], yr[4]
        parts.append("{ " + GC.row4(k) + ", " + GC.row4(R[0]) + ", " + GC.row4(R[1]) + " },")
    parts.append("}};")
    # the generator limbs
    parts.append("inline constexpr std::uint64_t VESTA_GEN_X[4] = " + GC.row4(G[0]) + ";")
    parts.append("inline constexpr std::uint64_t VESTA_GEN_Y[4] = " + GC.row4(G[1]) + ";")
    # the group order (p)
    pb = [(p_order >> (64*i)) & M64 for i in range(4)]
    parts.append("inline constexpr std::uint64_t VESTA_ORDER[4] = " + GC.row4(sum(l << (64*i) for i, l in enumerate(pb))) + ";")
    parts.append("} // namespace hsma::golden")
    od = GC.BUILD_GEN
    os.makedirs(od, exist_ok=True)
    path = os.path.join(od, "vesta_curve_golden.hpp")
    with open(path, "w") as f:
        f.write("\n".join(parts) + "\n")
    P("[step26][emit] vesta_curve_golden.hpp (add x8, dbl x8, mul x8, gen, order)")

_step26()
