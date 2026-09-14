# HSMA :: gen/steps/step23.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 23 APPEND — the phi0-phi7 end-to-end epoch (DEC-216) ═══
# One epoch through EVERY pillar with the golden pinning each seam:
# real beacon (11) -> envelopes + sigma_user (12/13) -> ordering lock (12)
# -> order-bound shares + attestations + aggregate + decrypt (12)
# -> decree entries -> fold over the SHUFFLED order (14) -> 41B carrier (16)
# -> f_close -> the light-client certificate (22). Header digest = the F_head
# chain link; state_root = SHA256(semantic final accounts) (Phase-0 form).
import hashlib as _h23
def _step23():
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    IV_PT = iv_derive(p, "HSM_PT_v1")
    IV_FOLD = iv_derive(p, "HSM_FOLD_v1")
    def _P3f(iv, a, b): return poseidon3_ref(p, iv, a % p, b % p, MDS, RC)
    def _kint(tag): return int.from_bytes(_h23.sha256(tag).digest(), "big") % p
    P8 = _step8_params()
    q, r, h1 = P8["q"], P8["r"], P8["h1"]
    P10 = _step10_params()
    beta, b2, h2 = P10["beta"], P10["b2"], P10["h2"]
    gamma = b2
    G1gen = P8["gen"]
    co = _step7_draw(15, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i*3:(i+1)*3] for i in range(5)]
    share = [[_s7_pe(polys[i], j, r) for j in range(1, 6)] for i in range(5)]
    S = sum(polys[i][0] for i in range(5)) % r
    Sj = [sum(share[i][j-1] for i in range(5)) % r for j in range(1, 6)]
    lam = _s9_lam([2, 3, 5], r)
    IDS = [2, 3, 5]
    G2g = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G2_GEN"), h2, q, beta)
    Y = _s10_e2_mul(G2g, S, q, beta)
    Y1g = _s8_mul(G1gen, S, q)              # the G1 aggregate public (CA-R93)
    def _sign(H):
        sg = None
        for l, j in zip(lam, IDS):
            sg = _s8_add(sg, _s8_mul(_s8_mul(H, Sj[j-1], q), l, q), q)
        return sg
    def _pr(P, Q): return _s12_pairing(P, Q, q, beta, gamma, r, b2)
    def _fe2b(x): return (x % p).to_bytes(32, "little")
    def _ser_g2(Q): return b"".join(c.to_bytes(48, "little") for c in (Q[0][0], Q[0][1], Q[1][0], Q[1][1]))
    # ── phi-0/1: the REAL beacon chain + 3 encrypted envelopes ──
    def _beacon(e, prev):
        pre = b"HSM_BEACON_V1" + e.to_bytes(8, "little") + prev
        return _h23.sha256(_s9_ser(_sign(_s9_h2g1(pre, q, h1)))).digest()
    EP0, EP1 = 30, 31
    b0 = _beacon(EP0, bytes(32))
    b1 = _beacon(EP1, b0)
    rds = _s8_draw(3, r, b"HSM_G23_KEM_R")
    skus = _s8_draw(3, r, b"HSM_G23_USER_SK")
    senders = [_h23.sha256(b"HSM_G23_SND" + i.to_bytes(4, "little")).digest() for i in range(3)]
    KA, KB, KC = _kint(b"G14F_KEY_A"), _kint(b"G14F_KEY_B"), _kint(b"G14F_KEY_C")
    TXS = [dict(s=KA, r=KB, amount=100, fee=10, nonce=1),
           dict(s=KB, r=KC, amount=50, fee=5, nonce=1),
           dict(s=KC, r=KB, amount=1000, fee=20, nonce=1)]   # insolvent -> SKIP
    ENV = []
    for i, tx in enumerate(TXS):
        hd = EP0.to_bytes(8, "little") + senders[i] + tx["nonce"].to_bytes(8, "little") + tx["fee"].to_bytes(8, "little")
        R = _s10_e2_mul(G2g, rds[i], q, beta)
        shared = _s10_e2_mul(Y, rds[i], q, beta)             # [r]X_E - the shared secret, NEVER ser(R) (CA-R61)
        k = _h23.sha256(b"HSM_KDF_V1" + _ser_g2(shared) + _ser_g2(Y) + hd).digest()
        payload = _fe2b(tx["s"]) + _fe2b(tx["r"]) + tx["amount"].to_bytes(16, "little") + tx["fee"].to_bytes(16, "little") + tx["nonce"].to_bytes(8, "little")
        ct = bytearray()
        for bi in range(0, len(payload), 32):
            ks = _h23.sha256(b"HSM_DEM_V1" + k + (bi // 32).to_bytes(8, "little")).digest()
            ct += bytes(a ^ b for a, b in zip(payload[bi:bi+32], ks))
        ct = bytes(ct)
        tag = _h23.sha256(b"HSM_DEM_TAG_V1" + k + hd + ct).digest()
        upre = b"HSM_SIG_USER_V1" + hd + _ser_g2(R)          # 15+56+192 = 263 (CA-R64)
        H_u = _s9_h2g1(upre, q, h1)
        sg_u = _s8_mul(H_u, skus[i], q)
        PKu = _s10_e2_mul(G2g, skus[i], q, beta)
        assert _pr(sg_u, G2g) == _pr(H_u, PKu), "sigma_user law"
        ENV.append(dict(R=R, k=k, ct=ct, tag=tag, hd=hd, sg_u=sg_u, PKu=PKu, payload=payload))
    # ── phi-2: the ordering lock under the REAL beacon ──
    cth = [_h23.sha256(b"HSM_CT_V1" + _ser_g2(ENV[i]["R"]) + ENV[i]["ct"]).digest() for i in range(3)]
    keys = [_h23.sha256(b"HSM_ORDER_V1" + b1 + cth[i]).digest() for i in range(3)]
    order = sorted(range(3), key=lambda i: keys[i])
    oroot = _h23.sha256(b"HSM_ORDROOT_V1" + b"".join(cth[i] for i in order)).digest()
    # ── phi-3/4: order-bound shares + attestations + aggregate + decrypt ──
    Y1j = {j: _s8_mul(G1gen, Sj[j-1], q) for j in IDS}
    Y2j = {j: _s10_e2_mul(G2g, Sj[j-1], q, beta) for j in IDS}
    Ds = []
    for i in range(3):
        parts = []
        for j in IDS:
            Dj = _s10_e2_mul(ENV[i]["R"], Sj[j-1], q, beta)
            parts.append(Dj)
            assert _pr(G1gen, Dj) == _pr(Y1j[j], ENV[i]["R"]), "share pairing identity"
            dpre = b"HSM_DEC_SHARE_V2" + EP0.to_bytes(8, "little") + oroot + cth[i] + _ser_g2(Dj)
            att = _s8_mul(_s9_h2g1(dpre, q, h1), Sj[j-1], q)
            assert _pr(att, G2g) == _pr(_s9_h2g1(dpre, q, h1), Y2j[j]), "attestation law"
        D = None
        for l, j in zip(lam, IDS):                           # lambda BEFORE the None-check (CA-R60)
            term = _s10_e2_mul(parts[IDS.index(j)], l, q, beta)
            D = term if D is None else _s10_e2_add(D, term, q, beta)
        assert _pr(G1gen, D) == _pr(Y1g, ENV[i]["R"]), "aggregate identity"
        k2 = _h23.sha256(b"HSM_KDF_V1" + _ser_g2(D) + _ser_g2(Y) + ENV[i]["hd"]).digest()
        assert k2 == ENV[i]["k"], "the derivations meet"
        pl = bytearray()
        for bi in range(0, len(ENV[i]["ct"]), 32):
            ks = _h23.sha256(b"HSM_DEM_V1" + k2 + (bi // 32).to_bytes(8, "little")).digest()
            pl += bytes(a ^ b for a, b in zip(ENV[i]["ct"][bi:bi+32], ks))
        assert bytes(pl) == ENV[i]["payload"]
        Ds.append(D)
    # ── phi-5/6: decree entries + the fold over the SHUFFLED order ──
    def mk_ent(tx, status):
        return dict(s=tx["s"], r=tx["r"], amount=tx["amount"], fee=tx["fee"], nonce=tx["nonce"],
                    status=status, pt=_P3f(IV_PT, tx["amount"], (tx["fee"] << 64) | tx["nonce"]))
    STAT = [0, 0, 1]                                         # the insolvent C->B tx SKIPs
    ents = [mk_ent(TXS[i], STAT[i]) for i in order]
    prev0 = _kint(b"G23F_PREV")
    st = {KA: dict(bal=1000, nonce=0), KB: dict(bal=500, nonce=0), KC: dict(bal=50, nonce=0)}
    dhead = _P3f(IV_FOLD, prev0, int.from_bytes(oroot, "little") % p)   # f_head (LE per CA-R74)
    d = dhead
    digs = []
    count = 0
    for ent in ents:
        if ent["status"] == 2:
            continue                                         # PAD: total neutrality
        stx = st[ent["s"]]
        assert ent["nonce"] == stx["nonce"] + 1, "nonce gate"
        cost = ent["amount"] + ent["fee"]
        if stx["bal"] >= cost:
            stx["bal"] -= cost
            stx["nonce"] += 1
            rc = st.get(ent["r"])
            if rc is not None:
                rc["bal"] += ent["amount"]
            else:
                st[ent["r"]] = dict(bal=ent["amount"], nonce=0)
        else:                                                # SKIP_USER: 25% fee burn, nonce untouched
            stx["bal"] -= ent["fee"] * 25 // 100
        count += 1
        d = _P3f(IV_FOLD, d, ent["pt"])
        digs.append(d % p)
    dclose = _P3f(IV_FOLD, d, count)                         # f_close
    accb = _fe2b(dclose) + count.to_bytes(8, "little") + b"\x02"
    assert len(accb) == 41                                   # the 41-byte carrier, FULL pipeline
    # ── phi-7: the light-client certificate ──
    sem_items = sorted(st.items(), key=lambda kv: _fe2b(kv[0]))   # LE-byte order (C++ memcmp parity)
    sem = b"".join(_fe2b(kk) + _fe2b(vv["bal"]) + vv["nonce"].to_bytes(8, "little") for kk, vv in sem_items)
    sroot = _h23.sha256(sem).digest()                        # the semantic state root (Phase-0 form)
    HT = 7
    cpre = b"HSM_CERT_v1" + HT.to_bytes(8, "little") + EP1.to_bytes(8, "little") + sroot + _fe2b(dhead) + b1
    assert len(cpre) == 123
    Hc = _s9_h2g1(cpre, q, h1)
    sg_c = _sign(Hc)
    assert _pr(sg_c, G2g) == _pr(Hc, Y), "the cert law"
    # ── seam negatives ──
    R_t = _s10_e2_mul(G2g, (rds[0] + 1) % r, q, beta)
    Dt = None
    for l, j in zip(lam, IDS):
        term = _s10_e2_mul(_s10_e2_mul(R_t, Sj[j-1], q, beta), l, q, beta)
        Dt = term if Dt is None else _s10_e2_add(Dt, term, q, beta)
    k2t = _h23.sha256(b"HSM_KDF_V1" + _ser_g2(Dt) + _ser_g2(Y) + ENV[0]["hd"]).digest()
    assert k2t != ENV[0]["k"], "tampered-R seam REJECTED"
    oroot_t = bytearray(oroot); oroot_t[0] ^= 1
    assert _P3f(IV_FOLD, prev0, int.from_bytes(bytes(oroot_t), "little") % p) != dhead, "tampered-oroot REJECTED"
    cpre_t = b"HSM_CERT_v1" + (8).to_bytes(8, "little") + EP1.to_bytes(8, "little") + sroot + _fe2b(dhead) + b1
    assert _pr(_sign(_s9_h2g1(cpre_t, q, h1)), G2g) != _pr(Hc, Y), "tampered-height cert REJECTED"
    print("[t23] phi0-1: real beacon x2; envelopes x3 (shared-secret KDF, DEM, tags); sigma_user x3 law-verified")
    print("[t23] phi2: ordering lock under the REAL beacon: order=%s" % order)
    print("[t23] phi3-4: shares x9 + identities, attestations x9, aggregates x3, k2==k x3, payloads recovered x3")
    print("[t23] phi5-6: fold over the shuffled order: %d entries (SKIP 25%%-burn live), chain x%d, close -> 41B" % (count, len(digs)))
    print("[t23] phi7: cert over (height=%d, sroot, chain link, beacon) - ONE pairing" % HT)
    print("[t23] seam negatives: tampered-R / tampered-oroot / tampered-height all REJECTED")
    # ── emission ──
    import os as _os23
    _root23 = _os23.path.dirname(_os23.path.dirname(_os23.path.abspath(__file__)))
    _tgt23 = _os23.path.join(_root23, "build", "generated", "e2e_golden.hpp")
    _os23.makedirs(_os23.path.dirname(_tgt23), exist_ok=True)
    def _b2l(bs): return [int.from_bytes(bs[i*8:(i+1)*8], "little") for i in range(len(bs)//8)]
    def _e2r(Q): return "{ " + _s10_row6(Q[0][0]) + ", " + _s10_row6(Q[0][1]) + ", " + _s10_row6(Q[1][0]) + ", " + _s10_row6(Q[1][1]) + " }"
    def _b8(bs): return "{" + ", ".join("0x%02xu" % b for b in bs) + "}"
    def _s6(v):                                              # canonical int -> 6-limb row
        limbs = [(v >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(4)]
        return _r6(limbs + [0, 0])
    hp = "// GENERATED FILE - e2e_golden.hpp (Step 23, DEC-216)\n#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n"
    hp += "inline constexpr unsigned G23E_N = 3u;\n"
    hp += "inline constexpr unsigned G23E_EP[2] = {%du, %du};\n" % (EP0, EP1)
    hp += "inline constexpr std::uint64_t G23E_B0[4] = " + _r4t(int.from_bytes(b0, "little")) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_B1[4] = " + _r4t(int.from_bytes(b1, "little")) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_SJ[5][6] = {\n " + ",\n ".join(_s6(v) for v in Sj) + "\n};\n"
    hp += "inline constexpr std::uint64_t G23E_LAM[3][6] = {\n " + ",\n ".join(_s6(l_) for l_ in lam) + "\n};\n"
    hp += "inline constexpr unsigned G23E_IDS[3] = {%du, %du, %du};\n" % tuple(IDS)
    hp += "inline constexpr std::uint64_t G23E_Y[4][6] = " + _e2r(Y) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_G2G[4][6] = " + _e2r(G2g) + ";\n"
    for i in range(3):
        ser = _s9_ser(ENV[i]["sg_u"])
        hp += "inline constexpr std::uint64_t G23E_SGUX%d[6] = " % i + _r6(_b2l(ser[:48])) + ";\n"
        hp += "inline constexpr std::uint64_t G23E_SGUY%d[6] = " % i + _r6(_b2l(ser[48:96])) + ";\n"
        hp += "inline constexpr std::uint64_t G23E_PKU%d[4][6] = " % i + _e2r(ENV[i]["PKu"]) + ";\n"
        hp += "inline constexpr std::uint64_t G23E_R%d[4][6] = " % i + _e2r(ENV[i]["R"]) + ";\n"
        hp += "inline constexpr std::uint8_t G23E_CT%d[%d] = %s;\n" % (i, len(ENV[i]["ct"]), _b8(ENV[i]["ct"]))
        hp += "inline constexpr std::uint8_t G23E_PL%d[%d] = %s;\n" % (i, len(ENV[i]["payload"]), _b8(ENV[i]["payload"]))
        hp += "inline constexpr std::uint64_t G23E_SND%d[4] = " % i + _r4t(int.from_bytes(senders[i], "little")) + ";\n"
        hp += "inline constexpr std::uint64_t G23E_D%d[4][6] = " % i + _e2r(Ds[i]) + ";\n"
        hp += "inline constexpr std::uint64_t G23E_CTH%d[4] = " % i + _r4t(int.from_bytes(cth[i], "little")) + ";\n"
    hp += "inline constexpr unsigned G23E_ORDER[3] = {%du, %du, %du};\n" % tuple(order)
    hp += "inline constexpr std::uint64_t G23E_OROOT[4] = " + _r4t(int.from_bytes(oroot, "little")) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_AMT[3][2] = {%s};\n" % ", ".join("{%du, %du}" % (TXS[i]["amount"] & 0xFFFFFFFFFFFFFFFF, TXS[i]["amount"] >> 64) for i in range(3))
    hp += "inline constexpr std::uint64_t G23E_FEE[3][2] = {%s};\n" % ", ".join("{%du, %du}" % (TXS[i]["fee"] & 0xFFFFFFFFFFFFFFFF, TXS[i]["fee"] >> 64) for i in range(3))
    hp += "inline constexpr unsigned G23E_NONCE[3] = {%du, %du, %du};\n" % tuple(TXS[i]["nonce"] for i in range(3))
    hp += "inline constexpr unsigned G23E_STAT[3] = {%du, %du, %du};\n" % tuple(STAT)
    hp += "inline constexpr std::uint64_t G23E_SK[3][4] = " + _r44t([TXS[i]["s"] for i in range(3)]) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_RK[3][4] = " + _r44t([TXS[i]["r"] for i in range(3)]) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_IBAL[3][2] = {{1000u, 0u}, {500u, 0u}, {50u, 0u}};\n"
    hp += "inline constexpr std::uint64_t G23E_PT[3][4] = " + _r44t([e["pt"] for e in ents]) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_PREV[4] = " + _r4t(prev0) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_DHEAD[4] = " + _r4t(dhead) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_DIG[3][4] = " + _r44t(digs) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_ACCD[4] = " + _r4t(dclose) + ";\n"
    hp += "inline constexpr unsigned G23E_COUNT = %du;\n" % count
    FBAL = [st[kk]["bal"] for kk in (KA, KB, KC)]
    FNONCE = [st[kk]["nonce"] for kk in (KA, KB, KC)]
    hp += "inline constexpr std::uint64_t G23E_FBAL[3][2] = {%s};\n" % ", ".join("{%du, 0u}" % fb for fb in FBAL)
    hp += "inline constexpr unsigned G23E_FNONCE[3] = {%du, %du, %du};\n" % tuple(FNONCE)
    hp += "inline constexpr std::uint64_t G23E_SROOT[4] = " + _r4t(int.from_bytes(sroot, "little")) + ";\n"
    ser_c = _s9_ser(sg_c)
    hp += "inline constexpr std::uint64_t G23E_SGCX[6] = " + _r6(_b2l(ser_c[:48])) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_SGCY[6] = " + _r6(_b2l(ser_c[48:96])) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_HCX[4] = " + _r4t(Hc[0]) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_HCY[4] = " + _r4t(Hc[1]) + ";\n"
    serY1g = _s9_ser(Y1g)
    hp += "inline constexpr std::uint64_t G23E_Y1GX[6] = " + _r6(_b2l(serY1g[:48])) + ";\n"
    hp += "inline constexpr std::uint64_t G23E_Y1GY[6] = " + _r6(_b2l(serY1g[48:96])) + ";\n"
    Y1js = [_s8_mul(G1gen, Sj[j-1], q) for j in IDS]
    hp += "inline constexpr std::uint64_t G23E_Y1JX[3][6] = {\n " + ",\n ".join(_r6(_b2l(_s9_ser(Y1js[m])[:48])) for m in range(3)) + "\n};\n"
    hp += "inline constexpr std::uint64_t G23E_Y1JY[3][6] = {\n " + ",\n ".join(_r6(_b2l(_s9_ser(Y1js[m])[48:96])) for m in range(3)) + "\n};\n"
    hp += "inline constexpr unsigned G23E_HT = %du;\n" % HT
    hp += "} // namespace hsma::golden\n"
    with open(_tgt23, "w") as f: f.write(hp)
    print("[step23][emit] e2e_golden.hpp (one epoch, phi0-phi7, every seam pinned)")

_step23()
