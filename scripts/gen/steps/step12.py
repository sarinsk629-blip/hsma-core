# HSMA :: gen/steps/step12.py - prelude+def+call extract (FROZEN; byte-preserving).


# ═══ STEP 12 APPEND — M2 order-bound decryption shares (DEC-201..203) ═══
import hashlib as _h12

def _step12():
    P8 = _step8_params()
    q, r, h1 = P8["q"], P8["r"], P8["h1"]
    P10 = _step10_params()
    beta, b2, h2 = P10["beta"], P10["b2"], P10["h2"]
    gamma = b2
    P_gen = P8["gen"]

    co = _step7_draw(15, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i*3:(i+1)*3] for i in range(5)]
    share = [[_s7_pe(polys[i], j, r) for j in range(1, 6)] for i in range(5)]
    S = sum(polys[i][0] for i in range(5)) % r
    Sj = [sum(share[i][j-1] for i in range(5)) % r for j in range(1, 6)]
    lam = _s9_lam([2, 3, 5], r)
    IDS = [2, 3, 5]

    G2g = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G2_GEN"), h2, q, beta)
    Y1  = _s8_mul(P_gen, S, q)                 # aggregate G1 public (Feldman root)
    Y2  = _s10_e2_mul(G2g, S, q, beta)         # X_E: unified anchor (DEC-030)
    Y1j = {j: _s8_mul(P_gen, Sj[j-1], q) for j in IDS}
    Y2j = {j: _s10_e2_mul(G2g, Sj[j-1], q, beta) for j in IDS}

    def _chain12(e, prev):                     # the REAL beacon chain (Step 11)
        pre = b"HSM_BEACON_V1" + e.to_bytes(8, "little") + prev
        H = _s9_h2g1(pre, q, h1)
        sg = None
        for l, j in zip(lam, IDS):
            sg = _s8_add(sg, _s8_mul(_s8_mul(H, Sj[j-1], q), l, q), q)
        return _h12.sha256(_s9_ser(sg)).digest()
    bE = _chain12(CONS_EPOCH, bytes(32))

    TAG_KDF, TAG_DEM, TAG_DTAG = b"HSM_KDF_V1", b"HSM_DEM_V1", b"HSM_DEM_TAG_V1"
    TAG_CT, TAG_ORD, TAG_OROOT = b"HSM_CT_V1", b"HSM_ORDER_V1", b"HSM_ORDROOT_V1"
    TAG_SHR = b"HSM_DEC_SHARE_V2"

    def _ser_g1(P):  return P[0].to_bytes(48, "little") + P[1].to_bytes(48, "little")
    def _ser_g2(Q):  return b"".join(c.to_bytes(48, "little")
                                     for c in (Q[0][0], Q[0][1], Q[1][0], Q[1][1]))
    def _hdr(ep, snd, non, fee):
        return ep.to_bytes(8, "little") + snd + non.to_bytes(8, "little") + fee.to_bytes(8, "little")
    def _kdf(rs, xs, hd):  return _h12.sha256(TAG_KDF + rs + xs + hd).digest()
    def _ks(k, i):         return _h12.sha256(TAG_DEM + k + i.to_bytes(8, "little")).digest()
    def _dem_enc(k, hd, pl):
        ct = bytearray()
        for i in range(0, len(pl), 32):
            ct += bytes(a ^ b for a, b in zip(pl[i:i+32], _ks(k, i // 32)))
        return bytes(ct), _h12.sha256(TAG_DTAG + k + hd + bytes(ct)).digest()
    def _dem_dec(k, hd, ct):
        pl = bytearray()
        for i in range(0, len(ct), 32):
            pl += bytes(a ^ b for a, b in zip(ct[i:i+32], _ks(k, i // 32)))
        return bytes(pl)
    def _dem_tag(k, hd, ct): return _h12.sha256(TAG_DTAG + k + hd + ct).digest()
    def _pr(P, Q): return _s12_pairing(P, Q, q, beta, gamma, r, b2)

    ENVN = 4
    rds = _s8_draw(ENVN, r, b"HSM_G12_KEM_R")
    payloads = [_h12.sha256(b"HSM_G12_PAY" + i.to_bytes(4, "little")).digest() for i in range(ENVN)]
    senders  = [_h12.sha256(b"HSM_G12_SND" + i.to_bytes(4, "little")).digest() for i in range(ENVN)]
    ENV = []
    for i in range(ENVN):
        hd = _hdr(CONS_EPOCH, senders[i], i + 1, 1000 + i)
        R = _s10_e2_mul(G2g, rds[i], q, beta)
        shared = _s10_e2_mul(Y2, rds[i], q, beta)      # [r]X_E - the sender-side shared secret
        k = _kdf(_ser_g2(shared), _ser_g2(Y2), hd)
        ct, tag = _dem_enc(k, hd, payloads[i])
        ENV.append(dict(hd=hd, R=R, ct=ct, tag=tag, k=k))
    print("[t12] envelopes x%d encrypted (G2-plane KEM + Phase-0 DEM)" % ENVN)

    cths  = [_h12.sha256(TAG_CT + _ser_g2(e["R"]) + e["ct"]).digest() for e in ENV]
    keys  = [_h12.sha256(TAG_ORD + bE + c).digest() for c in cths]
    order = sorted(range(ENVN), key=lambda i: keys[i])
    oroot = _h12.sha256(TAG_OROOT + b"".join(cths[i] for i in order)).digest()
    print("[t12] ordering lock: beacon-shuffled order=%s (REAL beacon, Step 11 chain)" % order)

    SHR, ATT = [], []
    for i in range(ENVN):
        dj, sj = {}, {}
        for j in IDS:
            D = _s10_e2_mul(ENV[i]["R"], Sj[j-1], q, beta)
            pre = TAG_SHR + CONS_EPOCH.to_bytes(8, "little") + oroot + cths[i] + _ser_g2(D)
            sj[j] = _s8_mul(_s9_h2g1(pre, q, h1), Sj[j-1], q)
            dj[j] = D
        SHR.append(dj); ATT.append(sj)
    for i in range(ENVN):
        for j in IDS:
            assert _pr(P_gen, SHR[i][j]) == _pr(Y1j[j], ENV[i]["R"])
            pre = TAG_SHR + CONS_EPOCH.to_bytes(8, "little") + oroot + cths[i] + _ser_g2(SHR[i][j])
            assert _pr(ATT[i][j], G2g) == _pr(_s9_h2g1(pre, q, h1), Y2j[j])
    print("[t12] shares x12 pairing identities + attestations x12 verified (oracle)")

    for i in range(ENVN):
        D = None
        for l, j in zip(lam, IDS):
            term = _s10_e2_mul(SHR[i][j], l, q, beta)
            D = term if D is None else _s10_e2_add(D, term, q, beta)
        assert _pr(P_gen, D) == _pr(Y1, ENV[i]["R"])
        k2 = _kdf(_ser_g2(D), _ser_g2(Y2), ENV[i]["hd"])
        assert k2 == ENV[i]["k"] and _dem_tag(k2, ENV[i]["hd"], ENV[i]["ct"]) == ENV[i]["tag"]
        assert _dem_dec(k2, ENV[i]["hd"], ENV[i]["ct"]) == payloads[i]
    print("[t12] aggregate + decrypt roundtrip x%d OK (k matches, tag matches, payload recovered)" % ENVN)

    D_bad = _s10_e2_mul(ENV[0]["R"], (Sj[1] + 1) % r, q, beta)
    assert _pr(P_gen, D_bad) != _pr(Y1j[2], ENV[0]["R"])
    print("[t12] malformed share REJECTED by pairing identity (item 6)")
    pre_bad = TAG_SHR + CONS_EPOCH.to_bytes(8, "little") + bytes(32) + cths[0] + _ser_g2(SHR[0][2])
    assert _pr(ATT[0][2], G2g) != _pr(_s9_h2g1(pre_bad, q, h1), Y2j[2])
    print("[t12] wrong-order_root attestation REJECTED (order-bound)")
    ct_bad = bytes([ENV[0]["ct"][0] ^ 1]) + ENV[0]["ct"][1:]
    assert _dem_tag(ENV[0]["k"], ENV[0]["hd"], ct_bad) != ENV[0]["tag"]
    print("[t12] tampered ciphertext REJECTED by DEM tag")

    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1:
        print("[step12] FATAL: ambiguous dirs"); raise SystemExit(1)
    outdir = cdirs.pop()

    def _g1row(P): return "{ " + _s10_row6(P[0]) + ", " + _s10_row6(P[1]) + " }"
    def _g2row(Q): return "{ " + ", ".join(_s10_row6(c) for c in
                     (Q[0][0], Q[0][1], Q[1][0], Q[1][1])) + " }"
    def _brow(b):  return "{" + ",".join("0x%02xu" % x for x in b) + "}"

    L = ["// GENERATED - STEP 12 (DEC-201..203). DO NOT EDIT.",
         "// Oracle: pure Python G2-plane KEM + order-bound shares + pairing verification.",
         "#pragma once", "#include <cstdint>", "namespace hsma::golden {",
         "inline constexpr unsigned G12M_ENVN = %du;" % ENVN,
         "inline constexpr std::uint64_t G12M_EPOCH = %du;" % CONS_EPOCH,
         "inline constexpr std::uint8_t G12M_BEACON[32] = " + _brow(bE) + ";",
         "inline constexpr std::uint64_t G12M_R[4][6] = {\n    " +
             ",\n    ".join(_s10_row6(v) for v in rds) + "\n};",
         "inline constexpr std::uint8_t G12M_SENDER[4][32] = {\n    " +
             ",\n    ".join(_brow(s) for s in senders) + "\n};",
         "inline constexpr std::uint64_t G12M_NONCE[4] = {1, 2, 3, 4};",
         "inline constexpr std::uint64_t G12M_FEE[4] = {1000, 1001, 1002, 1003};",
         "inline constexpr std::uint8_t G12M_PAYLOAD[4][32] = {\n    " +
             ",\n    ".join(_brow(p) for p in payloads) + "\n};",
         "inline constexpr std::uint64_t G12M_RPT[4][4][6] = {\n    " +
             ",\n    ".join(_g2row(e["R"]) for e in ENV) + "\n};",
         "inline constexpr std::uint8_t G12M_CT[4][32] = {\n    " +
             ",\n    ".join(_brow(e["ct"]) for e in ENV) + "\n};",
         "inline constexpr std::uint8_t G12M_TAG[4][32] = {\n    " +
             ",\n    ".join(_brow(e["tag"]) for e in ENV) + "\n};",
         "inline constexpr std::uint8_t G12M_K[4][32] = {\n    " +
             ",\n    ".join(_brow(e["k"]) for e in ENV) + "\n};",
         "inline constexpr std::uint8_t G12M_CTH[4][32] = {\n    " +
             ",\n    ".join(_brow(c) for c in cths) + "\n};",
         "inline constexpr std::uint8_t G12M_KEY[4][32] = {\n    " +
             ",\n    ".join(_brow(c) for c in keys) + "\n};",
         "inline constexpr unsigned G12M_ORDER[4] = {" +
             ",".join(str(i) for i in order) + "};",
         "inline constexpr std::uint8_t G12M_OROOT[32] = " + _brow(oroot) + ";",
         "inline constexpr std::uint64_t G12M_D[4][3][4][6] = {\n    " +
             ",\n    ".join("{ " + ", ".join(_g2row(SHR[i][j]) for j in IDS) + " }"
                             for i in range(ENVN)) + "\n};",
         "inline constexpr std::uint64_t G12M_SIG[4][3][2][6] = {\n    " +
             ",\n    ".join("{ " + ", ".join(_g1row(ATT[i][j]) for j in IDS) + " }"
                             for i in range(ENVN)) + "\n};",
         "inline constexpr std::uint64_t G12M_Y1[2][6] = " + _g1row(Y1) + ";",
         "inline constexpr std::uint64_t G12M_Y2[4][6] = " + _g2row(Y2) + ";",
         "inline constexpr std::uint64_t G12M_Y1J[3][2][6] = {\n    " +
             ",\n    ".join(_g1row(Y1j[j]) for j in IDS) + "\n};",
         "inline constexpr std::uint64_t G12M_Y2J[3][4][6] = {\n    " +
             ",\n    ".join(_g2row(Y2j[j]) for j in IDS) + "\n};",
         "inline constexpr std::uint64_t G12M_SJ[5][6] = {\n    " +
             ",\n    ".join(_s10_row6(v) for v in Sj) + "\n};",
         "} // namespace hsma::golden"]
    txt = "\n".join(L) + "\n"
    if txt.count("{") != txt.count("}"):
        print("[step12] FATAL: brace law"); raise SystemExit(1)
    open(_os8.path.join(outdir, "m2_golden.hpp"), "w").write(txt)
    print("[step12][emit] m2_golden.hpp (envelopes x%d, order, shares x12, attestations x12, keys)" % ENVN)

_step12()
