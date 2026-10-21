# HSMA :: gen/steps/step20.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 20 APPEND — the Phase-0 multilinear PCS (DEC-213) ═══
# Commit C = Sponge(HSM_SUMCHECK_v1, evals).squeeze(); point r_i = P3(SC, C, i).
# Open = the Step-19 fold machinery at the FIXED r (CA-R78 LSB-first folds).
# Verify = Step-19 round checks + Lagrange@{0,1,2}. NOT homomorphic/hiding —
# the production dual-layer (Pedersen + WHIR, DEC-063/071) is deferred; the
# transcript machinery and check structure are production-faithful.
import hashlib as _h20
def _step20():
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    IV_SC = iv_derive(p, "HSM_SUMCHECK_v1")
    def _P3(a, b): return poseidon3_ref(p, IV_SC, a % p, b % p, MDS, RC)
    def _sponge(elems): return sponge_ref(p, IV_SC, list(elems), MDS, RC)
    def _kint(tag): return int.from_bytes(_h20.sha256(tag).digest(), "big") % p
    INV2 = pow(2, p - 2, p)

    def _direct(arr, rs):
        nv = len(rs); tot = 0
        for idx in range(len(arr)):
            w = 1
            for v in range(nv):
                w = w * (rs[v] if (idx >> v) & 1 else (1 - rs[v])) % p
            tot = (tot + arr[idx] * w) % p
        return tot

    def _verify_open(nv, d, C, claims, evals, r, fa, fb):
        for i in range(nv):
            p0, p1, p2 = evals[i]
            if (p0 + p1) % p != claims[i]: return False, i
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

    def _open(nv, d, A, B, r):
        C = _sponge(A if d == 1 else A + B)
        a = A[:]; b = B[:] if d == 2 else None
        claims = [(sum(a) if d == 1 else sum(a[i] * b[i] for i in range(len(a)))) % p]
        evals = []
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
            ri = r[i]
            if d == 1:
                nc = (p0 * (1 - ri) + p1 * ri) % p
            else:
                L0 = (ri - 1) * (ri - 2) % p * INV2 % p
                L1 = ri * (2 - ri) % p
                L2 = ri * (ri - 1) % p * INV2 % p
                nc = (p0 * L0 + p1 * L1 + p2 * L2) % p
            a = [(a[2 * j] * (1 - ri) + a[2 * j + 1] * ri) % p for j in range(h)]
            if d == 2:
                b = [(b[2 * j] * (1 - ri) + b[2 * j + 1] * ri) % p for j in range(h)]
            evals.append((p0, p1, p2)); claims.append(nc)
        fa, fb = a[0], (b[0] if d == 2 else 0)
        ok, fr = _verify_open(nv, d, C, claims, evals, r, fa, fb)
        assert ok, fr
        dv = _direct(A, r) if d == 1 else (_direct(A, r) * _direct(B, r)) % p
        assert dv == claims[-1], "pcs dual-path mismatch"
        return dict(C=C, nv=nv, d=d, claims=claims, evals=evals, fa=fa, fb=fb, dv=dv)

    # the point-derivation helper (also emitted, mirrored in C++)
    def _rvec(C, nv):
        return [_P3(C, i) for i in range(nv)]

    A1 = [_kint(b"G20F_A1_" + i.to_bytes(1, "big")) for i in range(16)]
    A2 = [_kint(b"G20F_A2_" + i.to_bytes(1, "big")) for i in range(16)]
    B2 = [_kint(b"G20F_B2_" + i.to_bytes(1, "big")) for i in range(16)]
    A3 = [_kint(b"G20F_A3_" + i.to_bytes(1, "big")) for i in range(8)]
    B3 = [_kint(b"G20F_B3_" + i.to_bytes(1, "big")) for i in range(8)]

    C1 = _sponge(A1)
    R1 = _rvec(C1, 4)
    O1 = _open(4, 1, A1, None, R1)
    C2 = _sponge(A2 + B2)
    R2 = _rvec(C2, 4)
    O2 = _open(4, 2, A2, B2, R2)
    C3 = _sponge(A3 + B3)
    R3 = _rvec(C3, 3)
    O3 = _open(3, 2, A3, B3, R3)

    assert C2 != _sponge(A2)              # binding: {A} vs {A,B} corpora differ
    assert _sponge(A1) == C1              # determinism
    A1t = A1[:]; A1t[0] = (A1t[0] + 1) % p
    assert _sponge(A1t) != C1             # binding: single-element tamper

    ok, fr = _verify_open(4, 1, C1, list(O1["claims"]), O1["evals"], R1,
                          (O1["fa"] + 1) % p, O1["fb"])
    assert not ok and fr == 4, fr
    e2 = list(O2["evals"]); e2[1] = (e2[1][0], (e2[1][1] + 1) % p, e2[1][2])
    ok, fr = _verify_open(4, 2, C2, O2["claims"], e2, R2, O2["fa"], O2["fb"])
    assert not ok and fr == 1, fr
    ok, fr = _verify_open(4, 2, C2, [x + 1 for x in O2["claims"]], O2["evals"], R2,
                          O2["fa"], O2["fb"])
    assert not ok and fr == 0, fr

    print("[t20] commit parity: C == sponge(evals) x3; binding (A vs A+B, single-elem tamper); determinism")
    print("[t20] points: r_i = P3(SC, C, i) x11 total; derivation deterministic")
    print("[t20] open d=1 nv=4: ACCEPT; v == f(r) dual-path pinned")
    print("[t20] open d=2 nv=4 + d=2 nv=3: ACCEPT; v == f(r)*h(r) dual-path pinned")
    print("[t20] negatives: v-tamper REJECTED @final; eval-tamper REJECTED @1; claim-tamper REJECTED @0")

    import os as _os20
    _root20 = _os20.path.dirname(_os20.path.dirname(_os20.path.abspath(__file__)))
    _tgt20 = _os20.path.join(_root20, "build", "generated", "pcs_golden.hpp")
    _os20.makedirs(_os20.path.dirname(_tgt20), exist_ok=True)
    def _r4(v): return _s7_row(v)
    def _r44(rows): return "{\n " + ",\n ".join(_r4(x) for x in rows) + "\n}"
    def _r444(rows): return "{\n " + ",\n ".join("{" + ", ".join(_r4(x) for x in row) + "}" for row in rows) + "\n}"
    hp = "// GENERATED FILE - pcs_golden.hpp (Step 20, DEC-213)\n#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n"
    hp += "inline constexpr std::uint64_t G20P_INV2[4] = " + _r4(INV2) + ";\n"
    for name, O, C, R, A, B in (("1", O1, C1, R1, A1, None),
                                 ("2", O2, C2, R2, A2, B2),
                                 ("3", O3, C3, R3, A3, B3)):
        nv, d = O["nv"], O["d"]
        hp += "inline constexpr unsigned G20P_NV%s = %du;\n" % (name, nv)
        hp += "inline constexpr unsigned G20P_D%s = %du;\n" % (name, d)
        hp += "inline constexpr std::uint64_t G20P_C%s[4] = " % name + _r4(C) + ";\n"
        hp += "inline constexpr std::uint64_t G20P_R%s[%d][4] = %s;\n" % (name, nv, _r44(R))
        hp += "inline constexpr std::uint64_t G20P_CL%s[%d][4] = %s;\n" % (name, nv + 1, _r44(O["claims"]))
        hp += "inline constexpr std::uint64_t G20P_EV%s[%d][3][4] = %s;\n" % (name, nv, _r444(O["evals"]))
        hp += "inline constexpr std::uint64_t G20P_FA%s[4] = " % name + _r4(O["fa"]) + ";\n"
        hp += "inline constexpr std::uint64_t G20P_FB%s[4] = " % name + _r4(O["fb"]) + ";\n"
        hp += "inline constexpr std::uint64_t G20P_DIR%s[4] = " % name + _r4(O["dv"]) + ";\n"
        hp += "inline constexpr std::uint64_t G20P_A%s[%d][4] = %s;\n" % (name, len(A), _r44(A))
        if B is not None:
            hp += "inline constexpr std::uint64_t G20P_B%s[%d][4] = %s;\n" % (name, len(B), _r44(B))
    hp += "} // namespace hsma::golden\n"
    with open(_tgt20, "w") as f: f.write(hp)
    print("[step20][emit] pcs_golden.hpp (3 instances, commits, points, openings, INV2, dual-path pins)")

_step20()
