# HSMA :: gen/steps/step13.py - prelude+def+call extract (FROZEN; byte-preserving).


# ═══ STEP 13 APPEND — M2 production hardening: sigma_user + per-member partials + replay negative (DEC-204..206) ═══
import hashlib as _h13

def _step13():
    P8 = _step8_params()
    q, r, h1 = P8["q"], P8["r"], P8["h1"]
    P10 = _step10_params()
    beta, b2, h2 = P10["beta"], P10["b2"], P10["h2"]
    gamma = b2

    co = _step7_draw(15, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i*3:(i+1)*3] for i in range(5)]
    share = [[_s7_pe(polys[i], j, r) for j in range(1, 6)] for i in range(5)]
    S = sum(polys[i][0] for i in range(5)) % r
    Sj = [sum(share[i][j-1] for i in range(5)) % r for j in range(1, 6)]
    G2g = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G2_GEN"), h2, q, beta)
    Y2 = _s10_e2_mul(G2g, S, q, beta)

    def _ser_g2(Q): return b"".join(c.to_bytes(48, "little")
                                    for c in (Q[0][0], Q[0][1], Q[1][0], Q[1][1]))
    def _hdr(ep, snd, non, fee):
        return ep.to_bytes(8, "little") + snd + non.to_bytes(8, "little") + fee.to_bytes(8, "little")
    def _pr(P, Q): return _s12_pairing(P, Q, q, beta, gamma, r, b2)

    # recompute the step-12 envelopes (deterministic; C++ cross-checks vs m2_golden.hpp)
    TAG_KDF, TAG_DEM, TAG_DTAG = b"HSM_KDF_V1", b"HSM_DEM_V1", b"HSM_DEM_TAG_V1"
    def _kdf(ss, xs, hd): return _h13.sha256(TAG_KDF + ss + xs + hd).digest()
    def _ks(k, i): return _h13.sha256(TAG_DEM + k + i.to_bytes(8, "little")).digest()
    def _dem_enc(k, hd, pl):
        ct = bytearray()
        for i in range(0, len(pl), 32):
            ct += bytes(a ^ b for a, b in zip(pl[i:i+32], _ks(k, i // 32)))
        return bytes(ct), _h13.sha256(TAG_DTAG + k + hd + bytes(ct)).digest()
    rds = _s8_draw(4, r, b"HSM_G12_KEM_R")
    payloads = [_h13.sha256(b"HSM_G12_PAY" + i.to_bytes(4, "little")).digest() for i in range(4)]
    senders  = [_h13.sha256(b"HSM_G12_SND" + i.to_bytes(4, "little")).digest() for i in range(4)]
    ENV = []
    for i in range(4):
        hd = _hdr(CONS_EPOCH, senders[i], i + 1, 1000 + i)
        R = _s10_e2_mul(G2g, rds[i], q, beta)
        shared = _s10_e2_mul(Y2, rds[i], q, beta)
        k = _kdf(_ser_g2(shared), _ser_g2(Y2), hd)
        ct, tag = _dem_enc(k, hd, payloads[i])
        ENV.append(dict(hd=hd, R=R, ct=ct, tag=tag, k=k))

    # 1. sigma_user: the sender's authorization (DEC-204)
    TAG_SU = b"HSM_SIG_USER_V1"
    skus = _s8_draw(4, r, b"HSM_G13_USER_SK")
    PKu = [_s10_e2_mul(G2g, sk, q, beta) for sk in skus]
    SU = []
    for i in range(4):
        pre = TAG_SU + ENV[i]["hd"] + _ser_g2(ENV[i]["R"])     # 16 + 56 + 192 = 264
        H = _s9_h2g1(pre, q, h1)
        sig_u = _s8_mul(H, skus[i], q)
        assert _pr(sig_u, G2g) == _pr(H, PKu[i])
        SU.append((H, sig_u))
    print("[t13] sigma_user x4 signed + pairing-verified (DEC-204)")
    sig_bad = _s8_mul(SU[0][0], (skus[0] + 1) % r, q)
    assert _pr(sig_bad, G2g) != _pr(SU[0][0], PKu[0])
    print("[t13] forged sigma_user REJECTED (item 5 closed)")

    # 2. per-member partials + permissionless aggregation (DEC-205)
    pre_b = b"HSM_BEACON_V1" + CONS_EPOCH.to_bytes(8, "little") + bytes(32)
    Hb = _s9_h2g1(pre_b, q, h1)
    sig_ideal = _s8_mul(Hb, S, q)
    SUBS = [[2, 3, 5], [1, 4, 5]]
    AGGS = []
    for sub in SUBS:
        parts = {j: _s8_mul(Hb, Sj[j-1], q) for j in sub}
        lam_s = _s9_lam(sub, r)
        sig = None
        for l, j in zip(lam_s, sub):
            term = _s8_mul(parts[j], l, q)
            sig = term if sig is None else _s8_add(sig, term, q)
        assert sig == sig_ideal
        AGGS.append((parts, sig))
    print("[t13] partials x2 subsets -> identical aggregate == [S]H (DEC-205)")
    lam235 = _s9_lam([2, 3, 5], r)
    sg = None
    for l, j in zip(lam235, [2, 3, 5]):
        sg = _s8_add(sg, _s8_mul(_s8_mul(Hb, Sj[j-1], q), l, q), q)
    assert _h13.sha256(_s9_ser(AGGS[0][1]).encode if False else _s9_ser(AGGS[0][1])).digest() == \
           _h13.sha256(_s9_ser(sg)).digest()
    print("[t13] beacon-from-partials == harness chain (cross-checked)")
    lam2 = _s9_lam([2, 3], r)
    two = None
    for l, j in zip(lam2, [2, 3]):
        term = _s8_mul(_s8_mul(Hb, Sj[j-1], q), l, q)
        two = term if two is None else _s8_add(two, term, q)
    assert two != sig_ideal
    print("[t13] 2-of-5 partials REJECTED (t-threshold enforced)")

    # 3. cross-epoch replay negative (DEC-206)
    hd_bad = _hdr(CONS_EPOCH + 1, senders[0], 1, 1000)
    assert _h13.sha256(TAG_DTAG + ENV[0]["k"] + hd_bad + ENV[0]["ct"]).digest() != ENV[0]["tag"]
    print("[t13] cross-epoch replay REJECTED (item 4 explicit)")

    # 4. emission: m2prod_golden.hpp
    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1:
        print("[step13] FATAL: ambiguous dirs"); raise SystemExit(1)
    outdir = cdirs.pop()

    def _g1row(P): return "{ " + _s10_row6(P[0]) + ", " + _s10_row6(P[1]) + " }"
    def _g2row(Q): return "{ " + ", ".join(_s10_row6(c) for c in
                     (Q[0][0], Q[0][1], Q[1][0], Q[1][1])) + " }"

    L = ["// GENERATED - STEP 13 (DEC-204..206). DO NOT EDIT.",
         "// Oracle: sigma_user (BLS-style, G1 sig / G2 pk) + per-member partials.",
         "#pragma once", "#include <cstdint>", "namespace hsma::golden {",
         "inline constexpr unsigned G13_UN = 4u;",
         "inline constexpr std::uint64_t G13U_SK[4][6] = {\n    " +
             ",\n    ".join(_s10_row6(v) for v in skus) + "\n};",
         "inline constexpr std::uint64_t G13U_PK[4][4][6] = {\n    " +
             ",\n    ".join(_g2row(v) for v in PKu) + "\n};",
         "inline constexpr std::uint64_t G13U_SIG[4][2][6] = {\n    " +
             ",\n    ".join(_g1row(t[1]) for t in SU) + "\n};",
         "inline constexpr std::uint64_t G13P_HB[2][6] = " + _g1row(Hb) + ";",
         "inline constexpr std::uint64_t G13P_SUBS[2][3] = {{2, 3, 5}, {1, 4, 5}};",
         "inline constexpr std::uint64_t G13P_PART[2][3][2][6] = {\n    " +
             ",\n    ".join("{ " + ", ".join(_g1row(p[1][j]) for j in p[0]) + " }"
                             for p in [({2: 0, 3: 1, 5: 2}, {j: AGGS[0][0][j] for j in [2, 3, 5]})]
                             + [({1: 0, 4: 1, 5: 2}, {j: AGGS[1][0][j] for j in [1, 4, 5]})]) + "\n};",
         "inline constexpr std::uint64_t G13P_AGG[2][2][6] = {\n    " +
             ",\n    ".join(_g1row(a[1]) for a in AGGS) + "\n};",
         "} // namespace hsma::golden"]
    txt = "\n".join(L) + "\n"
    if txt.count("{") != txt.count("}"):
        print("[step13] FATAL: brace law"); raise SystemExit(1)
    open(_os8.path.join(outdir, "m2prod_golden.hpp"), "w").write(txt)
    print("[step13][emit] m2prod_golden.hpp (user keys x4, sigma_user x4, partials x2 subsets, aggregates)")

_step13()
