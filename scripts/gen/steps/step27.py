# HSMA :: gen/steps/step27.py - P1-07 (GAP-03d + GAP-04, DEC-225).
# Absorption golden: payload(8 canonical u64 limbs) -> d = Poseidon_V over the
# CYCLEFOLD domain (dom=0, the P1-04 pre-minted IV) as a 7-call binary tree
# -> P_cf = [d]*G_vesta. The Python oracle is a FAITHFUL MONTGOMERY emulation
# of the proven vp3 twin (constants raw, adds plain, muls x R^-1, sbox x^5 via
# mont-mul chain) and is AUTO-CALIBRATED against the compiled twin via
# build/p27probe.txt (schedule selected by an exact 3-vector match).
import os, sys, re, hashlib, subprocess
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC
hx = lambda w: int(re.search(r'0x([0-9a-fA-F]+)', w).group(1), 16)  # row4 emits ull suffixes

M64 = (1 << 64) - 1

def _step27():
    P = lambda *a: print(*a, flush=True)
    C = GC.load_constants()
    q = C["q_vesta"]; p_order = C["p"]
    R = pow(2, 256, q); Rinv = pow(R, -1, q)

    if not os.path.exists("build/p27probe.txt"):
        cmd = ("clang++ -std=c++20 -Iinclude -Igenerated tools/p27probe.cpp"
               " -o build/p27probe && ./build/p27probe > build/p27probe.txt")
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        assert os.path.exists("build/p27probe.txt"), "probe rebuild failed: " + r.stderr[-400:]

    txt = open("generated/vesta_poseidon_params_gen.hpp").read()
    def rows(name):
        mm = re.search(r'VP3_%s\b.*?\{\{(.*?)\}\}\s*;' % name, txt, re.S)
        assert mm, "VP3_%s block not found" % name
        return [[hx(w) for w in r_.split(",")]
                for r_ in re.findall(r'\{\s*(0x[0-9a-fA-F]{16}ull(?:\s*,\s*0x[0-9a-fA-F]{16}ull){3})\s*\}', mm.group(1))]
    cv = lambda l: l[0] | l[1] << 64 | l[2] << 128 | l[3] << 192  # hoisted above first use (Z-fix)
    MDS = rows("MDS"); RC = [cv(r) for r in rows("RC")]  # limb-rows -> limb-integers: the twin adds raw limbs, so must the emulation
    mm2 = re.search(r'VP3_IV_HSM_CYCLEFOLD_V1\[4\]\s*=\s*\{(.*?)\}', txt, re.S)
    assert mm2, "CYCLEFOLD IV not found"
    cv = lambda l: l[0] | l[1] << 64 | l[2] << 128 | l[3] << 192
    iv = cv([hx(w) for w in mm2.group(1).split(",")])
    P("[step27] VP3 constants: MDS %d elems, RC %d, CYCLEFOLD IV (dom=0)" % (len(MDS), len(RC)))

    madd = lambda a, b: (a + b) % q
    mmul = lambda a, b: a * b % q * Rinv % q
    def sbox5(v):
        v2 = mmul(v, v); v3 = mmul(v2, v); return mmul(v2, v3)
    def mix(s):
        out = []
        for r_ in range(3):
            acc = 0
            for c_ in range(3):
                acc = madd(acc, mmul(s[c_], cv(MDS[r_ * 3 + c_])))
            out.append(acc)
        return out

    def perm(s0, s1, sched):
        s = [s0, s1, iv]; i = 0          # P3StateV s{l, r, vp3_iv(dom)} - IV in lane 3
        def full():
            nonlocal i
            if sched == "C":
                r_ = RC[i]; i += 1
                s[0] = madd(s[0], r_); s[1] = madd(s[1], r_); s[2] = madd(s[2], r_)
            else:
                s[0] = madd(s[0], RC[i]); s[1] = madd(s[1], RC[i+1]); s[2] = madd(s[2], RC[i+2]); i += 3
            s[0] = sbox5(s[0]); s[1] = sbox5(s[1]); s[2] = sbox5(s[2])
            s[:] = mix(s)
        def part():
            nonlocal i
            s[0] = madd(s[0], RC[i]); i += 1
            s[0] = sbox5(s[0]); s[:] = mix(s)
        nf = 4 if sched == "B" else 12
        for _ in range(nf): full()
        for _ in range(56): part()
        for _ in range(nf): full()
        assert i <= len(RC), "RC overrun %d>%d" % (i, len(RC))
        return s[0]

    probes = [(1, 2), (0xdeadbeefcafebabe, 0x1234567890abcdef), (q - 1, 5)]
    exp = {}
    for ln in open("build/p27probe.txt"):
        t = ln.split()
        if len(t) == 5 and t[0].startswith("P"): exp[t[0]] = [int(x, 16) for x in t[1:]]
    assert len(exp) == 3, "probe file malformed"
    chosen = None; diag = []
    for sched in ("B", "C", "A"):
        try:
            ok = True
            for (l_, r_), tag in zip(probes, ("P01", "P02", "P03")):
                s0m = perm(l_ * R % q, r_ * R % q, sched)
                got = [(s0m * Rinv % q >> (64 * t)) & M64 for t in range(4)]
                if got != exp[tag]:
                    diag.append("%s/%s got %s exp %s" % (sched, tag,
                        "".join("%016x" % w for w in got), "".join("%016x" % w for w in exp[tag])))
                    ok = False; break
            if ok: chosen = sched; break
        except IndexError:
            diag.append("%s: RC overrun (needs > %d RCs)" % (sched, len(RC)))
    assert chosen, "no schedule matched the twin. diag:\n  " + "\n  ".join(diag)
    P("[step27] schedule '%s' CALIBRATED vs the compiled twin (3/3 probes)" % chosen)

    def p3v(l_, r_):
        return perm(l_ * R % q, r_ * R % q, chosen) * Rinv % q
    def digest(px, py):
        h0 = p3v(px[0], px[1]); h1 = p3v(px[2], px[3])
        h2 = p3v(py[0], py[1]); h3 = p3v(py[2], py[3])
        return p3v(p3v(h0, h1), p3v(h2, h3))

    Bc = 5
    def ec_add(Pt, Qt):
        if Pt is None: return Qt
        if Qt is None: return Pt
        x1, y1 = Pt; x2, y2 = Qt
        if x1 == x2 and (y1 + y2) % q == 0: return None
        lam = (3 * x1 * x1) * pow(2 * y1, -1, q) % q if Pt == Qt \
              else (y2 - y1) * pow(x2 - x1, -1, q) % q
        x3 = (lam * lam - x1 - x2) % q
        return (x3, (lam * (x1 - x3) - y1) % q)
    def ec_mul(k, Pt):
        acc = None
        for bit in bin(k)[2:]:
            acc = ec_add(acc, acc)
            if bit == '1': acc = ec_add(acc, Pt)
        return acc
    Gv = (q - 1, 2)
    on = lambda Pt: Pt is None or Pt[1] * Pt[1] % q == (pow(Pt[0], 3, q) + Bc) % q
    assert on(Gv), "generator off-curve"

    seed = b"hsma-cycfold-golden-v1"
    def drbg(n, ctr):
        out, blk = b"", 0
        while len(out) < n:
            out += hashlib.sha256(seed + b"|%d|%d" % (ctr, blk)).digest(); blk += 1
        return out[:n]
    N = 6; vecs = []
    for i in range(N):
        raw = drbg(64, i)
        px = [int.from_bytes(raw[8*j:8*j+8], "little") for j in range(4)]
        py = [int.from_bytes(raw[32+8*j:40+8*j], "little") for j in range(4)]
        d = digest(px, py); assert 0 <= d < q
        Pcf = ec_mul(d, Gv)
        assert on(Pcf) and ec_mul(p_order, Pcf) is None, "payload %d violated" % i
        vecs.append((px, py, d, Pcf))
        P("[step27] payload[%d] d=0x%064x  on-curve, [p]P=inf" % (i, d))

    l4 = lambda v: [(v >> (64*t)) & M64 for t in range(4)]
    parts = ["// HSMA :: vesta_absorb_golden.hpp - P1-07 golden (DEC-225).",
             "// payload(8 canonical u64 limbs) -> d = Poseidon_V(CYCLEFOLD, dom=0)",
             "// 7-call tree -> P_cf = [d]*G_vesta. CANONICAL limbs throughout.",
             "#pragma once", "#include <array>", "#include <cstdint>", "namespace hsma::golden {",
             "inline constexpr unsigned VEC_ABSORB_N = %du;" % N,
             "struct VestaAbsorb { std::uint64_t px[4], py[4], d[4], pcfx[4], pcfy[4]; };",
             "inline constexpr std::array<VestaAbsorb, %d> VEC_ABSORB {{" % N]
    for px, py, d, Pcf in vecs:
        row = ", ".join("{" + ", ".join("0x%016xull" % w for w in g) + "}"
                        for g in (px, py, l4(d), l4(Pcf[0]), l4(Pcf[1])))
        parts.append("{ " + row + " },")
    parts += ["}};", "} // namespace hsma::golden"]
    open("generated/vesta_absorb_golden.hpp", "w").write("\n".join(parts) + "\n")
    P("[step27][emit] vesta_absorb_golden.hpp (absorb x%d: payload->d->P_cf)" % N)

_step27()
