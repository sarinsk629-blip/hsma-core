# HSMA :: gen/steps/step29.py - P1-09 NEW-CODE step (GAP-05 Layer 1, DEC-227).
# Homomorphic Pedersen golden, BOTH Pasta accumulators in one header.
# PedP: Pallas curve, scalars in F_q (order = q). PedV: Vesta, scalars in F_p.
# Bases: h_i = sha256("HSMA_PEDERSEN_<CURVE>_H<i>") LE % order; H_i = h_i*G.
# Emitter self-checks every receipt (on-curve, homomorphism, scalar hom,
# subgroup) BEFORE emitting. Boilerplate per CA-R120: namespace hsma::golden,
# '}};' closer - copied from the proven step26/27/28 pattern.
import os, sys, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

M64 = (1 << 64) - 1

def _step29():
    P = lambda *a: print(*a, flush=True)
    C = GC.load_constants()

    seed = b"hsma-pedersen-golden-v1"
    def drbg(curve, tag, n, ctr):
        out, blk = b"", 0
        while len(out) < n:
            out += hashlib.sha256(seed + b"|%s|%s|%d|%d" % (curve.encode(), tag.encode(), ctr, blk)).digest(); blk += 1
        return out[:n]

    def build(curve, FP, ORD):
        def ec_add(Pt, Qt):
            if Pt is None: return Qt
            if Qt is None: return Pt
            x1, y1 = Pt; x2, y2 = Qt
            if x1 == x2 and (y1 + y2) % FP == 0: return None
            lam = (3*x1*x1) * pow(2*y1, -1, FP) % FP if Pt == Qt \
                  else (y2 - y1) * pow(x2 - x1, -1, FP) % FP
            x3 = (lam*lam - x1 - x2) % FP
            return (x3, (lam*(x1 - x3) - y1) % FP)
        def ec_mul(k, Pt):
            acc = None
            for bit in bin(k)[2:]:
                acc = ec_add(acc, acc)
                if bit == '1': acc = ec_add(acc, Pt)
            return acc
        G = (FP - 1, 2)
        on = lambda Pt: Pt is None or Pt[1]*Pt[1] % FP == (pow(Pt[0], 3, FP) + 5) % FP
        assert on(G), curve + " generator off-curve"
        # bases
        hs, Hs = [], []
        for i in range(8):
            h = int.from_bytes(hashlib.sha256(("HSMA_PEDERSEN_%s_H%d" % (curve, i)).encode()).digest(), "little") % ORD
            H = ec_mul(h, G); assert on(H) and h < ORD
            hs.append(h); Hs.append(H)
        # commit oracle
        def commit(m, r):
            Cc = ec_mul(r, G)
            for i in range(8): Cc = ec_add(Cc, ec_mul(m[i], Hs[i]))
            return Cc
        def msg(ctr):
            raw = drbg(curve, "m", 8*32, ctr)
            return [int.from_bytes(raw[32*j:32*j+32], "little") % (ORD - 2) + 1 for j in range(8)]
        # 3 commit cases
        commits = []
        for i in range(3):
            m = msg(i)
            r = int.from_bytes(drbg(curve, "r", 32, i), "little") % ORD
            Cv = commit(m, r)
            assert on(Cv) and ec_mul(ORD, Cv) is None, curve + " commit %d violated" % i
            commits.append((m, r, Cv))
        # homomorphism case
        m1, m2 = msg(10), msg(11)
        r1 = int.from_bytes(drbg(curve, "r1", 32, 10), "little") % ORD
        r2 = int.from_bytes(drbg(curve, "r2", 32, 11), "little") % ORD
        m12 = [(a + b) % ORD for a, b in zip(m1, m2)]
        r12 = (r1 + r2) % ORD
        C1, C2, C12 = commit(m1, r1), commit(m2, r2), commit(m12, r12)
        assert ec_add(C1, C2) == C12, curve + " homomorphism violated"
        # scalar homomorphism case
        m3 = msg(20)
        r3 = int.from_bytes(drbg(curve, "r3", 32, 20), "little") % ORD
        s  = int.from_bytes(drbg(curve, "s", 32, 21), "little") % (ORD - 2) + 1
        sm = [(v * s) % ORD for v in m3]; sr = (r3 * s) % ORD
        C3, CS = commit(m3, r3), commit(sm, sr)
        assert ec_mul(s, C3) == CS, curve + " scalar hom violated"
        P("[step29] %s: 8 bases + 3 commits + hom + scalar-hom SELF-CHECKED" % curve)
        return dict(order=ORD, G=G, hs=hs, Hs=Hs, commits=commits,
                    m1=m1, r1=r1, m2=m2, r2=r2, m12=m12, r12=r12,
                    C1=C1, C2=C2, C12=C12, m3=m3, r3=r3, s=s, sm=sm, sr=sr,
                    C3=C3, CS=CS)

    PL = build("PALLAS", C["p"], C["q_vesta"])
    VE = build("VESTA", C["q_vesta"], C["p"])

    l4 = lambda v: [(v >> (64*t)) & M64 for t in range(4)]
    row = lambda v: GC.row4(v)   # GC.row4 takes the INTEGER and does its own limb split
    mrow = lambda m: "{ " + ", ".join(row(v) for v in m) + " }"   # CA-R127: a 2D member (m[8][4]) needs its OWN brace level - a braced group binds to the next MEMBER, not the next sub-array

    parts = ["// HSMA :: pedersen_golden.hpp - P1-09 golden (DEC-227).",
             "// Homomorphic Pedersen, both Pasta accumulators. CANONICAL limbs.",
             "// Bases: h_i = sha256(label) LE % order; H_i = [h_i]*G; commit C = [r]G + sum [m_i]H_i.",
             "#pragma once", "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {"]
    for tag, D in (("PALLAS", PL), ("VESTA", VE)):
        parts += [
            "inline constexpr std::uint64_t %s_PED_ORDER[4] = %s;" % (tag, row(D["order"])),
            "struct %sPedBase { std::uint64_t h[4], x[4], y[4]; };" % tag.capitalize(),
            "inline constexpr std::array<%sPedBase, 8> %s_PED_BASES {{" % (tag.capitalize(), tag)]
        for h, H in zip(D["hs"], D["Hs"]):
            parts.append("{ " + row(h) + ", " + row(H[0]) + ", " + row(H[1]) + " },")
        parts += ["}};",
            "struct %sPedCommit { std::uint64_t m[8][4], r[4], cx[4], cy[4]; };" % tag.capitalize(),
            "inline constexpr std::array<%sPedCommit, 3> %s_PED_COMMIT {{" % (tag.capitalize(), tag)]
        for m, r, Cv in D["commits"]:
            parts.append("{ " + mrow(m) + ", " + row(r) + ", " + row(Cv[0]) + ", " + row(Cv[1]) + " },")
        parts += ["}};",
            "struct %sPedHom { std::uint64_t m1[8][4], r1[4], m2[8][4], r2[4], m12[8][4], r12[4], c1x[4], c1y[4], c2x[4], c2y[4], c12x[4], c12y[4]; };" % tag.capitalize(),
            "inline constexpr std::array<%sPedHom, 1> %s_PED_HOM {{" % (tag.capitalize(), tag)]
        D2_ = D
        parts.append("{ " + mrow(D2_["m1"]) + ", " + row(D2_["r1"]) + ", " + mrow(D2_["m2"]) + ", " + row(D2_["r2"]) +
                     ", " + mrow(D2_["m12"]) + ", " + row(D2_["r12"]) +
                     ", " + row(D2_["C1"][0]) + ", " + row(D2_["C1"][1]) +
                     ", " + row(D2_["C2"][0]) + ", " + row(D2_["C2"][1]) +
                     ", " + row(D2_["C12"][0]) + ", " + row(D2_["C12"][1]) + " },")
        parts += ["}};",
            "struct %sPedScalarHom { std::uint64_t m[8][4], r[4], s[4], sm[8][4], sr[4], cx[4], cy[4], csx[4], csy[4]; };" % tag.capitalize(),
            "inline constexpr std::array<%sPedScalarHom, 1> %s_PED_SHOM {{" % (tag.capitalize(), tag)]
        parts.append("{ " + mrow(D2_["m3"]) + ", " + row(D2_["r3"]) + ", " + row(D2_["s"]) +
                     ", " + mrow(D2_["sm"]) + ", " + row(D2_["sr"]) +
                     ", " + row(D2_["C3"][0]) + ", " + row(D2_["C3"][1]) +
                     ", " + row(D2_["CS"][0]) + ", " + row(D2_["CS"][1]) + " },")
        parts.append("}};")
    parts += ["}};" if False else "", "} // namespace hsma::golden"]
    parts = [p for p in parts if p != ""]
    # NOTE: the per-section arrays each closed with '}};'; the namespace closes here.
    parts[-1] = "} // namespace hsma::golden"
    open("build/generated/pedersen_golden.hpp", "w").write("\n".join(parts) + "\n")
    P("[step29][emit] pedersen_golden.hpp (both accumulators: bases x8, commits x3, hom, scalar-hom)")

_step29()
