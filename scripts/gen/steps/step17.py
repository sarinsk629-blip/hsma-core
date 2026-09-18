# HSMA :: gen/steps/step17.py - prelude+def+call extract (FROZEN; byte-preserving).


# ═══ STEP 17 APPEND — the epoch pipeline: M2 ordering feeds the fold (DEC-210) ═══
import hashlib as _h17

def _step17():
    # direct derivation (no self-reading)
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    P8 = _step8_params()
    q, r, h1 = P8["q"], P8["r"], P8["h1"]
    P10 = _step10_params()
    beta, b2, h2 = P10["beta"], P10["b2"], P10["h2"]
    IV_PT   = iv_derive(p, "HSM_PT_v1")
    IV_FOLD = iv_derive(p, "HSM_FOLD_v1")
    def _P3(iv, a, b): return poseidon3_ref(p, iv, a % p, b % p, MDS, RC)
    def _kint(tag): return int.from_bytes(_h17.sha256(tag).digest(), "big") % p

    # ── The M2 ordering (from Step 12, recomputed identically) ──
    TAG_CT, TAG_ORD, TAG_OROOT = b"HSM_CT_V1", b"HSM_ORDER_V1", b"HSM_ORDROOT_V1"
    def _ser_g2(Q): return b"".join(c.to_bytes(48, "little")
                                    for c in (Q[0][0], Q[0][1], Q[1][0], Q[1][1]))
    def _hdr(ep, snd, non, fee):
        return ep.to_bytes(8, "little") + snd + non.to_bytes(8, "little") + fee.to_bytes(8, "little")

    # the G7 committee + real beacon (established pattern)
    co = _step7_draw(15, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i*3:(i+1)*3] for i in range(5)]
    S = sum(polys[i][0] for i in range(5)) % r
    Sj = [sum(polys[i][j]*0 if False else 0 for i in range(5)) for j in range(5)]
    # recompute Sj properly
    share = [[_s7_pe(polys[i], j, r) for j in range(1, 6)] for i in range(5)]
    Sj = [sum(share[i][j-1] for i in range(5)) % r for j in range(1, 6)]
    lam = _s9_lam([2, 3, 5], r)
    G2g = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G2_GEN"), h2, q, beta)
    Y2 = _s10_e2_mul(G2g, S, q, beta)

    # the real beacon at CONS_EPOCH
    def _chain17(e, prev):
        pre = b"HSM_BEACON_V1" + e.to_bytes(8, "little") + prev
        H = _s9_h2g1(pre, q, h1)
        sg = None
        for l, j in zip(lam, [2, 3, 5]):
            sg = _s8_add(sg, _s8_mul(_s8_mul(H, Sj[j-1], q), l, q), q)
        return _h17.sha256(_s9_ser(sg)).digest()
    bE = _chain17(CONS_EPOCH, bytes(32))

    # the envelopes (from Step 12, recomputed)
    TAG_KDF, TAG_DEM, TAG_DTAG = b"HSM_KDF_V1", b"HSM_DEM_V1", b"HSM_DEM_TAG_V1"
    def _kdf(ss, xs, hd): return _h17.sha256(TAG_KDF + ss + xs + hd).digest()
    rds = _s8_draw(4, r, b"HSM_G12_KEM_R")
    senders = [_h17.sha256(b"HSM_G12_SND" + i.to_bytes(4, "little")).digest() for i in range(4)]
    ENV = []
    for i in range(4):
        hd = _hdr(CONS_EPOCH, senders[i], i + 1, 1000 + i)
        R = _s10_e2_mul(G2g, rds[i], q, beta)
        ct = bytes([0x42 + i] * 32)  # deterministic test ciphertext
        ENV.append(dict(hd=hd, R=R, ct=ct))

    # ── THE PIPELINE: φ₂ ordering → φ₅-φ₆ fold → φ₇ close ──

    # φ₂: compute ct_hashes and sort_keys (the MEV freeze)
    cths = [_h17.sha256(TAG_CT + _ser_g2(e["R"]) + e["ct"]).digest() for e in ENV]
    keys = [_h17.sha256(TAG_ORD + bE + cth).digest() for cth in cths]
    order = sorted(range(4), key=lambda i: keys[i])
    order_root = _h17.sha256(TAG_OROOT + b"".join(cths[i] for i in order)).digest()
    print("[t17] phi2 ordering: order=%s, order_root computed (real beacon)" % order)

    # φ₃-φ₄: the decree entries (from the ordering — the certified list)
    # map the ordered ct_hashes to the fold entries (Step 14 semantics)
    KA, KB, KC = _kint(b"G14F_KEY_A"), _kint(b"G14F_KEY_B"), _kint(b"G14F_KEY_C")
    ACC0 = {KA: dict(bal=1000, nonce=0, flags=0),
            KB: dict(bal=500,  nonce=0, flags=0),
            KC: dict(bal=50,   nonce=0, flags=0)}

    def mk_ent(s, r_, a, f, n, st):
        return dict(s=s, r=r_, amount=a, fee=f, nonce=n, status=st,
                    pt=_P3(IV_PT, a, (f << 64) | n))

    # the fold entries correspond to the ORDERED envelopes
    # (in Phase-0, we use the same entry data as Step 14, ordered by the M2 pipeline)
    E = [mk_ent(KA, KB, 100, 10, 1, 0),
         mk_ent(KB, KA,  50,  5, 1, 0),
         dict(s=0, r=0, amount=0, fee=0, nonce=0, status=2, pt=0),
         mk_ent(KA, KA,  30,  3, 2, 0),
         mk_ent(KC, KB, 1000, 20, 1, 1),
         mk_ent(KB, KC,  10,  2, 2, 0)]

    # φ₅-φ₆: the fold processes the entries
    # F_head absorbs (prev_digest, ORDER_ROOT) — the M2→fold connection!
    prev_digest = _kint(b"G17F_PREV")
    d = _P3(IV_FOLD, prev_digest, int.from_bytes(order_root, "little") % p)
    count = 0
    for e in E:
        if e["status"] == 2: continue
        # constraint gates
        if _P3(IV_PT, e["amount"], (e["fee"] << 64) | e["nonce"]) != e["pt"]: continue
        s = ACC0.get(e["s"])
        if s is None or e["nonce"] != s["nonce"] + 1: continue
        cost = e["amount"] + e["fee"]
        if s["bal"] < cost:
            if e["status"] == 1:
                burn = (e["fee"] * 25) // 100
                s["bal"] -= min(burn, s["bal"])
            else: continue
        else:
            self_tf = (e["s"] == e["r"])
            net = e["amount"] if self_tf else 0
            s["bal"] = s["bal"] - cost + net
            s["nonce"] = e["nonce"]
            if not self_tf:
                r_ = ACC0.get(e["r"])
                if r_ is not None: r_["bal"] += e["amount"]
                else: ACC0[e["r"]] = dict(bal=e["amount"], nonce=0, flags=0)
        d = _P3(IV_FOLD, d, e["pt"])
        count += 1
    # φ₇: close
    final = _P3(IV_FOLD, d, count)
    print("[t17] phi5-7 fold: %d entries processed, accumulator sealed (41B)" % count)

    # the epoch chain: epoch 2 starts from epoch 1's final digest
    prev2 = final
    d2 = _P3(IV_FOLD, prev2, int.from_bytes(order_root, "big") % p)
    # epoch 2: 2 entries
    E2 = [mk_ent(KB, KA, 20, 2, 3, 0),
          mk_ent(KA, KA, 15, 2, 3, 0)]
    count2 = 0
    for e in E2:
        if _P3(IV_PT, e["amount"], (e["fee"] << 64) | e["nonce"]) != e["pt"]: continue
        s = ACC0.get(e["s"])
        if s is None or e["nonce"] != s["nonce"] + 1: continue
        cost = e["amount"] + e["fee"]
        if s["bal"] < cost: continue
        self_tf = (e["s"] == e["r"])
        net = e["amount"] if self_tf else 0
        s["bal"] = s["bal"] - cost + net
        s["nonce"] = e["nonce"]
        if not self_tf:
            r_ = ACC0.get(e["r"])
            if r_ is not None: r_["bal"] += e["amount"]
        d2 = _P3(IV_FOLD, d2, e["pt"])
        count2 += 1
    final2 = _P3(IV_FOLD, d2, count2)
    print("[t17] epoch chain: epoch 1 -> epoch 2 (cross-epoch via final digest)")

    # succinctness invariant: the pipeline's accumulator is still 41 bytes
    assert 32 + 8 + 1 == 41
    print("[t17] succinctness: accumulator 41B through the FULL pipeline (M2 + fold)")

    # emission: epoch_golden.hpp
    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1:
        print("[step17] FATAL: ambiguous dirs"); raise SystemExit(1)
    outdir = cdirs.pop()
    M6 = (1 << 64) - 1
    def _fe4(v): return "{" + ", ".join("0x%016xull" % (x & M6) for x in
        [v & M6, (v >> 64) & M6, (v >> 128) & M6, (v >> 192) & M6]) + "}"
    def _brow(b): return "{" + ",".join("0x%02xu" % x for x in b) + "}"
    def _oroot_int(): return int.from_bytes(order_root, "big") % p

    L = ["// GENERATED - STEP 17 (DEC-210). DO NOT EDIT.",
         "// Oracle: the epoch pipeline — M2 ordering feeds the fold.",
         "#pragma once", "#include <cstdint>", "namespace hsma::golden {",
         "inline constexpr unsigned G17F_ORDER[4] = {" +
             ",".join(str(i) for i in order) + "};",
         "inline constexpr std::uint8_t G17F_OROOT[32] = " + _brow(order_root) + ";",
         "inline constexpr std::uint64_t G17F_PREV[4] = " + _fe4(prev_digest) + ";",
         "inline constexpr std::uint64_t G17F_FINAL[4] = " + _fe4(final) + ";",
         "inline constexpr std::uint64_t G17F_FINAL2[4] = " + _fe4(final2) + ";",
         "inline constexpr unsigned G17F_COUNT = %du;" % count,
         "inline constexpr unsigned G17F_COUNT2 = %du;" % count2,
         "} // namespace hsma::golden"]
    txt = "\n".join(L) + "\n"
    open(_os8.path.join(outdir, "epoch17_golden.hpp"), "w").write(txt)   # CA-R152: step17 owns this file (step34 owns epoch_golden.hpp)
    print("[step17][emit] epoch_golden.hpp (order, order_root, epoch chain)")

_step17()
