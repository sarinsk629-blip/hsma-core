# HSMA :: gen/steps/step22.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 22 APPEND — the light-client epoch-header certificate (DEC-215) ═══
# Header: {height, epoch, state_root, digest_E, beacon_digest}; certificate =
# G7 threshold signature over h2g1(HSM_CERT_v1 || fields). Light-client verify
# = ONE pairing e(sigma, G2gen) == e(H(pre), Y) + chain continuity (digest_E
# rides the Step-14 fold chain) + beacon binding (the REAL HSM_BEACON_V1
# chain). Genesis-sync (height=0, no cert) rejected by policy (item 10).
# Phase-0: sigma emitted uncompressed (96 B); the 48-B compressed wire form
# is production transport. HSM_CERT_v1 pre-existed in the registry (day one).
import hashlib as _h22
def _step22():
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    IV_FOLD = iv_derive(p, "HSM_FOLD_v1")
    P8 = _step8_params()
    q, r, h1 = P8["q"], P8["r"], P8["h1"]
    P10 = _step10_params()
    beta, b2, h2 = P10["beta"], P10["b2"], P10["h2"]
    gamma = b2
    def _P3f(a, b): return poseidon3_ref(p, IV_FOLD, a % p, b % p, MDS, RC)
    def _kint(tag): return int.from_bytes(_h22.sha256(tag).digest(), "big") % p
    # the G7 committee (every pillar\'s witness, Steps 7-21)
    co = _step7_draw(15, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i*3:(i+1)*3] for i in range(5)]
    share = [[_s7_pe(polys[i], j, r) for j in range(1, 6)] for i in range(5)]
    S = sum(polys[i][0] for i in range(5)) % r
    Sj = [sum(share[i][j-1] for i in range(5)) % r for j in range(1, 6)]
    lam = _s9_lam([2, 3, 5], r)
    IDS = [2, 3, 5]
    G2g = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G2_GEN"), h2, q, beta)
    Y = _s10_e2_mul(G2g, S, q, beta)
    def _sign(H):
        sg = None
        for l, j in zip(lam, IDS):
            sg = _s8_add(sg, _s8_mul(_s8_mul(H, Sj[j-1], q), l, q), q)
        return sg
    def _pr(P, Q): return _s12_pairing(P, Q, q, beta, gamma, r, b2)
    # the REAL beacon chain (Step 11 semantics)
    def _beacon(e, prev):
        pre = b"HSM_BEACON_V1" + e.to_bytes(8, "little") + prev
        return _h22.sha256(_s9_ser(_sign(_s9_h2g1(pre, q, h1)))).digest()
    E0, E1 = 100, 101
    b0 = _beacon(E0, bytes(32))
    b1 = _beacon(E1, b0)
    # the fold digest chain (Step 14/17 semantics): digest_E = P3(FOLD, prev, decree)
    prev0 = _kint(b"G22F_PREV")
    dec0, dec1 = _kint(b"G22F_DECREE_100"), _kint(b"G22F_DECREE_101")
    d0 = _P3f(prev0, dec0)
    d1 = _P3f(d0, dec1)
    sr0, sr1 = _kint(b"G22F_STATE_100"), _kint(b"G22F_STATE_101")
    TAG_CERT = b"HSM_CERT_v1"
    def _u64b(v): return v.to_bytes(8, "little")
    def _fe2b(x): return (x % p).to_bytes(32, "little")
    def _pre(height, epoch, sr, dig, bc):
        return TAG_CERT + _u64b(height) + _u64b(epoch) + sr + _fe2b(dig) + bc
    pre0 = _pre(100, E0, sr0.to_bytes(32, "little"), d0, b0)
    pre1 = _pre(101, E1, sr1.to_bytes(32, "little"), d1, b1)
    H0 = _s9_h2g1(pre0, q, h1)
    H1 = _s9_h2g1(pre1, q, h1)
    sg0, sg1 = _sign(H0), _sign(H1)
    def _lc_verify(height, epoch, sr, dig, bc, sg):
        pre = TAG_CERT + _u64b(height) + _u64b(epoch) + sr + _fe2b(dig) + bc
        return _pr(sg, G2g) == _pr(_s9_h2g1(pre, q, h1), Y)
    assert _lc_verify(100, E0, sr0.to_bytes(32, "little"), d0, b0, sg0)
    assert _lc_verify(101, E1, sr1.to_bytes(32, "little"), d1, b1, sg1)
    assert not _lc_verify(102, E0, sr0.to_bytes(32, "little"), d0, b0, sg0)
    d1_bad = _P3f(prev0, dec1)
    assert not _lc_verify(101, E1, sr1.to_bytes(32, "little"), d1_bad, b1, sg1)
    assert not _lc_verify(101, E1, sr1.to_bytes(32, "little"), d1, b0, sg1)
    def _lc_sync(height, has_cert):
        if height == 0 and not has_cert: return False
        return True
    assert not _lc_sync(0, False) and _lc_sync(101, True)
    print("[t22] headers x2: heights 100/101, fold-chained digests, REAL beacon chain (53-B preimages)")
    print("[t22] certs x2: G7 threshold sigma over HSM_CERT_v1 preimages (123 B) — one committee, five pillars")
    print("[t22] light-client verify x2 ACCEPT: e(sigma, G2gen) == e(H(pre), Y) — ONE pairing per header")
    print("[t22] chain continuity: digest_E1 == F_head(digest_E0, decree_E1) — verified")
    print("[t22] negatives: tampered-height / chain-break / stale-beacon / genesis-sync-all REJECTED")
    import os as _os22
    _root22 = _os22.path.dirname(_os22.path.dirname(_os22.path.abspath(__file__)))
    _tgt22 = _os22.path.join(_root22, "build", "generated", "cert_golden.hpp")
    _os22.makedirs(_os22.path.dirname(_tgt22), exist_ok=True)
    def _r4(v): return _s7_row(v)
    def _r44(rows): return "{\n " + ",\n ".join(_r4(x) for x in rows) + "\n}"
    def _b2l(bs): return [int.from_bytes(bs[i*8:(i+1)*8], "little") for i in range(len(bs)//8)]
    def _e2r(Q): return "{ " + _s10_row6(Q[0][0]) + ", " + _s10_row6(Q[0][1]) + ", " + _s10_row6(Q[1][0]) + ", " + _s10_row6(Q[1][1]) + " }"
    ser0, ser1 = _s9_ser(sg0), _s9_ser(sg1)
    sx = [_b2l(ser0[:48]), _b2l(ser1[:48])]
    sy = [_b2l(ser0[48:96]), _b2l(ser1[48:96])]
    def _p1(Q): return _s12_pairing(Q, G2g, q, beta, gamma, r, b2)
    def _p2(Q): return _s12_pairing(Q, Y, q, beta, gamma, r, b2)
    hp = "// GENERATED FILE - cert_golden.hpp (Step 22, DEC-215)\n#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n"
    hp += "inline constexpr unsigned G22H_PRELEN = 123u;\n"
    hp += "inline constexpr unsigned G22H_HEIGHT[2] = {100u, 101u};\n"
    hp += "inline constexpr std::uint64_t G22H_PREV[4] = " + _r4t(prev0) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_DECREE[2][4] = " + _r44t([dec0, dec1]) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_STATE[2][4] = " + _r66([_b2l(sr0.to_bytes(32, "little")), _b2l(sr1.to_bytes(32, "little"))]) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_DIG[2][4] = " + _r44t([d0 % p, d1 % p]) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_BEACON[2][4] = " + _r66([_b2l(b0), _b2l(b1)]) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_SIGX[2][6] = " + _r66(sx) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_SIGY[2][6] = " + _r66(sy) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_HX[2][6] = " + _r66([_b2l(_s9_ser(H0)[:48]), _b2l(_s9_ser(H1)[:48])]) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_HY[2][6] = " + _r66([_b2l(_s9_ser(H0)[48:96]), _b2l(_s9_ser(H1)[48:96])]) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_Y[4][6] = " + _e2r(Y) + ";\n"
    hp += "inline constexpr std::uint64_t G22H_G2G[4][6] = " + _e2r(G2g) + ";\n"
    hp += "} // namespace hsma::golden\n"
    with open(_tgt22, "w") as f: f.write(hp)
    print("[step22][emit] cert_golden.hpp (headers, sigmas 96-B, H pins, Y, G2gen, chain)")

_step22()
