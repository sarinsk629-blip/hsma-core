# HSMA :: gen/steps/step19.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 19 APPEND — the sum-check engine (DEC-212) ═══
import hashlib as _h19

def _r6(vs): return "{ " + ", ".join("0x%016xu" % v for v in vs) + " }"
def _r66(rows): return "{\n " + ",\n ".join(_r6(x) for x in rows) + "\n}"
def _r4t(v): return _s7_row(v) if isinstance(v, int) else _r6(v)
def _r44t(rows): return "{\n " + ",\n ".join(_r4t(x) for x in rows) + "\n}"

def _step19():
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    IV_SC = iv_derive(p, "HSM_SUMCHECK_v1")
    def _P3(a, b): return poseidon3_ref(p, IV_SC, a % p, b % p, MDS, RC)
    def _kint(tag): return int.from_bytes(_h19.sha256(tag).digest(), "big") % p
    INV2 = pow(2, p - 2, p)

    def _direct(arr, rs):
        nv = len(rs); tot = 0
        for idx in range(len(arr)):
            w = 1
            for v in range(nv):
                bit = (idx >> v) & 1
                w = w * (rs[v] if bit else (1 - rs[v])) % p
            tot = (tot + arr[idx] * w) % p
        return tot

    def _verify(nv, d, C, claims, evals, r, fa, fb):
        if claims[0] != C: return False, 0
        for i in range(nv):
            p0, p1, p2 = evals[i]
            if (p0 + p1) % p != claims[i]: return False, i
            t = _P3(p0, p1)
            if d == 2: t = _P3(t, p2)
            if _P3(t, claims[i]) != r[i]: return False, i
            if d == 1:
                nc = (p0 * (1 - r[i]) + p1 * r[i]) % p
            else:
                L0 = (r[i] - 1) * (r[i] - 2) % p * INV2 % p
                L1 = r[i] * (2 - r[i]) % p
                L2 = r[i] * (r[i] - 1) % p * INV2 % p
                nc = (p0 * L0 + p1 * L1 + p2 * L2) % p
            if nc != claims[i + 1]: return False, i
        fin = fa if d == 1 else (fa * fb) % p
        if fin != claims[nv]: return False, nv
        return True, nv

    def _prove(nv, d, A, B):
        C = (sum(A) if d == 1 else sum(A[i] * B[i] for i in range(len(A)))) % p
        a = A[:]; b = B[:] if d == 2 else None
        claims = [C]; evals = []; rs = []
        for i in range(nv):
            h = len(a) // 2
            if d == 2:
                p0 = sum(a[2 * j] * b[2 * j] for j in range(h)) % p
                p1 = sum(a[2 * j + 1] * b[2 * j + 1] for j in range(h)) % p
                p2 = sum((2 * a[2 * j + 1] - a[2 * j]) * (2 * b[2 * j + 1] - b[2 * j])
                         for j in range(h)) % p
            else:
                p0 = sum(a[2 * j] for j in range(h)) % p
                p1 = sum(a[2 * j + 1] for j in range(h)) % p
                p2 = 0
            t = _P3(p0, p1)
            if d == 2: t = _P3(t, p2)
            r = _P3(t, claims[-1])
            if d == 1:
                nc = (p0 * (1 - r) + p1 * r) % p
            else:
                L0 = (r - 1) * (r - 2) % p * INV2 % p
                L1 = r * (2 - r) % p
                L2 = r * (r - 1) % p * INV2 % p
                nc = (p0 * L0 + p1 * L1 + p2 * L2) % p
            a = [(a[2 * j] * (1 - r) + a[2 * j + 1] * r) % p for j in range(h)]
            if d == 2:
                b = [(b[2 * j] * (1 - r) + b[2 * j + 1] * r) % p for j in range(h)]
            evals.append((p0, p1, p2)); rs.append(r); claims.append(nc)
        fa, fb = a[0], (b[0] if d == 2 else 0)
        ok, fr = _verify(nv, d, C, claims, evals, rs, fa, fb)
        assert ok, fr
        dv = _direct(A, rs) if d == 1 else (_direct(A, rs) * _direct(B, rs)) % p
        assert dv == claims[-1], "dual-path mismatch"
        return dict(nv=nv, d=d, C=C, claims=claims, evals=evals, rs=rs, fa=fa, fb=fb, dv=dv)

    A1 = [_kint(b"G19F_A1_" + i.to_bytes(1, "big")) for i in range(16)]
    A2 = [_kint(b"G19F_A2_" + i.to_bytes(1, "big")) for i in range(16)]
    B2 = [_kint(b"G19F_B2_" + i.to_bytes(1, "big")) for i in range(16)]
    A3 = [_kint(b"G19F_A3_" + i.to_bytes(1, "big")) for i in range(8)]
    B3 = [_kint(b"G19F_B3_" + i.to_bytes(1, "big")) for i in range(8)]
    S1 = _prove(4, 1, A1, None)
    S2 = _prove(4, 2, A2, B2)
    S3 = _prove(3, 2, A3, B3)
    c1 = list(S1["claims"]); c1[0] = (c1[0] + 1) % p
    ok, fr = _verify(4, 1, S1["C"], c1, S1["evals"], S1["rs"], S1["fa"], S1["fb"])
    assert not ok and fr == 0, fr
    e2 = list(S2["evals"]); e2[1] = (e2[1][0], (e2[1][1] + 1) % p, e2[1][2])
    ok, fr = _verify(4, 2, S2["C"], S2["claims"], e2, S2["rs"], S2["fa"], S2["fb"])
    assert not ok and fr == 1, fr
    ok, fr = _verify(4, 2, S2["C"], S2["claims"], S2["evals"], S2["rs"], (S2["fa"] + 1) % p, S2["fb"])
    assert not ok and fr == 4, fr
    print("[t19] sc1 (d=1, nv=4): 4 rounds ACCEPT; dual-path final == claim")
    print("[t19] sc2 (d=2, nv=4): 4 rounds ACCEPT; dual-path product == claim")
    print("[t19] sc3 (d=2, nv=3): 3 rounds ACCEPT; dual-path product == claim")
    print("[t19] negatives: claim-tamper REJECTED @0; eval-tamper REJECTED @1; final-tamper REJECTED @final")

    import os as _os19
    _root19 = _os19.path.dirname(_os19.path.dirname(_os19.path.abspath(__file__)))
    _tgt19 = _os19.path.join(_root19, "build", "generated", "sumcheck_golden.hpp")
    _os19.makedirs(_os19.path.dirname(_tgt19), exist_ok=True)
    def _r4(v): return _s7_row(v)

    def _r44(rows): return "{\n " + ",\n ".join(_r4(x) for x in rows) + "\n}"
    def _r444(rows): return "{\n " + ",\n ".join("{" + ", ".join(_r4(x) for x in row) + "}" for row in rows) + "\n}"
    hp = "// GENERATED FILE - sumcheck_golden.hpp (Step 19, DEC-212)\n#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n"
    hp += "inline constexpr std::uint64_t G19S_INV2[4] = " + _r4(INV2) + ";\n"
    for name, S, A, B in (("1", S1, A1, None), ("2", S2, A2, B2), ("3", S3, A3, B3)):
        nv, d = S["nv"], S["d"]
        hp += "inline constexpr unsigned G19S_NV%s = %du;\n" % (name, nv)
        hp += "inline constexpr unsigned G19S_D%s = %du;\n" % (name, d)
        hp += "inline constexpr std::uint64_t G19S_C%s[4] = " % name + _r4(S["C"]) + ";\n"
        hp += "inline constexpr std::uint64_t G19S_CL%s[%d][4] = %s;\n" % (name, nv + 1, _r44(S["claims"]))
        hp += "inline constexpr std::uint64_t G19S_EV%s[%d][3][4] = %s;\n" % (name, nv, _r444(S["evals"]))
        hp += "inline constexpr std::uint64_t G19S_R%s[%d][4] = %s;\n" % (name, nv, _r44(S["rs"]))
        hp += "inline constexpr std::uint64_t G19S_FA%s[4] = " % name + _r4(S["fa"]) + ";\n"
        hp += "inline constexpr std::uint64_t G19S_FB%s[4] = " % name + _r4(S["fb"]) + ";\n"
        hp += "inline constexpr std::uint64_t G19S_DIR%s[4] = " % name + _r4(S["dv"]) + ";\n"
        hp += "inline constexpr std::uint64_t G19S_A%s[%d][4] = %s;\n" % (name, len(A), _r44(A))
        if B is not None:
            hp += "inline constexpr std::uint64_t G19S_B%s[%d][4] = %s;\n" % (name, len(B), _r44(B))
    hp += "} // namespace hsma::golden\n"
    with open(_tgt19, "w") as f: f.write(hp)
    print("[step19][emit] sumcheck_golden.hpp (3 transcripts, arrays, INV2, dual-path pins)")

_step19()
