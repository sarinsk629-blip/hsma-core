# HSMA :: gen/steps/step14.py - prelude+def+call extract (FROZEN; byte-preserving).


# ═══ STEP 14 APPEND — the fold step family (DEC-207) ═══
import hashlib as _h14

def _step14():
    # derivation auto-extracted from emit_smt_scenario (bit-exact tables)
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    # derivation (same as step14 fix — bit-exact tables)
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    IV_PT   = iv_derive(p, "HSM_PT_v1")
    IV_FOLD = iv_derive(p, "HSM_FOLD_v1")
    def _P3(iv, a, b): return poseidon3_ref(p, iv, a % p, b % p, MDS, RC)
    def _kint(tag): return int.from_bytes(_h14.sha256(tag).digest(), "big") % p

    KA, KB, KC = _kint(b"G14F_KEY_A"), _kint(b"G14F_KEY_B"), _kint(b"G14F_KEY_C")
    ACC0 = {KA: dict(bal=1000, nonce=0, flags=0),
            KB: dict(bal=500,  nonce=0, flags=0),
            KC: dict(bal=50,   nonce=0, flags=0)}
    DECREE_ROOT = _kint(b"G14F_DECREE_ROOT")
    PREV = _kint(b"G14F_PREV_EPOCH")

    V_OK_EXEC, V_OK_SKIP, V_PAD, V_REJ_BIND, V_REJ_NONCE, V_REJ_INSOL = 0, 1, 2, 3, 4, 5

    def mk_ent(s, r, a, f, n, st):
        return dict(s=s, r=r, amount=a, fee=f, nonce=n, status=st,
                    pt=_P3(IV_PT, a, (f << 64) | n))
    E = [mk_ent(KA, KB, 100, 10, 1, 0),      # EXEC A->B
         mk_ent(KB, KA,  50,  5, 1, 0),      # EXEC B->A
         dict(s=0, r=0, amount=0, fee=0, nonce=0, status=2, pt=0),   # PAD
         mk_ent(KA, KA,  30,  3, 2, 0),      # EXEC self-send
         mk_ent(KC, KB, 1000, 20, 1, 1),     # SKIP_USER (insolvent)
         mk_ent(KB, KC,  10,  2, 2, 0)]      # EXEC B->C

    def fold_run(entries, state0, prev, droot):
        st = {k: dict(v) for k, v in state0.items()}
        d = _P3(IV_FOLD, prev, droot)            # F_head
        res, chain, count = [], [], 0
        for e in entries:
            if e["status"] == 2:                  # PAD: total neutrality
                res.append(V_PAD); chain.append(d); continue
            if _P3(IV_PT, e["amount"], (e["fee"] << 64) | e["nonce"]) != e["pt"]:
                res.append(V_REJ_BIND); chain.append(d); continue
            s = st.get(e["s"])
            if s is None or e["nonce"] != s["nonce"] + 1:
                res.append(V_REJ_NONCE); chain.append(d); continue
            cost = e["amount"] + e["fee"]
            if s["bal"] < cost:
                if e["status"] == 1:              # SKIP_USER: 25% burn, no nonce
                    burn = (e["fee"] * 25) // 100
                    s["bal"] -= min(burn, s["bal"])
                    d = _P3(IV_FOLD, d, e["pt"]); count += 1
                    res.append(V_OK_SKIP); chain.append(d); continue
                res.append(V_REJ_INSOL); chain.append(d); continue
            # EXEC: the apply_rules twin (tx.hpp G5 verbatim)
            self_tf = (e["s"] == e["r"])
            net = e["amount"] if self_tf else 0
            s["bal"] = s["bal"] - cost + net
            s["nonce"] = e["nonce"]
            if not self_tf:
                r = st.get(e["r"])
                if r is not None: r["bal"] += e["amount"]
                else: st[e["r"]] = dict(bal=e["amount"], nonce=0, flags=0)
            d = _P3(IV_FOLD, d, e["pt"]); count += 1
            res.append(V_OK_EXEC); chain.append(d)
        final = _P3(IV_FOLD, d, count)            # F_close (absorbs the count)
        return st, res, chain, final, count

    st_f, res, chain, final, count = fold_run(E, ACC0, PREV, DECREE_ROOT)
    assert res == [V_OK_EXEC, V_OK_EXEC, V_PAD, V_OK_EXEC, V_OK_SKIP, V_OK_EXEC]
    assert count == 5
    assert st_f[KA]["bal"] == 937 and st_f[KA]["nonce"] == 2
    assert st_f[KB]["bal"] == 533 and st_f[KB]["nonce"] == 2
    assert st_f[KC]["bal"] == 55  and st_f[KC]["nonce"] == 0
    print("[t14] honest epoch folded: 5 entries (4 EXEC + 1 SKIP) + 1 PAD; final states verified")

    E_nopad = [e for e in E if e["status"] != 2]
    _, _, _, final_np, count_np = fold_run(E_nopad, ACC0, PREV, DECREE_ROOT)
    assert final_np == final and count_np == count
    print("[t14] padding-neutrality: sans-PAD final digest IDENTICAL")

    _, _, _, final_alt, _ = fold_run(E, ACC0, _kint(b"G14F_PREV_ALT"), DECREE_ROOT)
    assert final_alt != final
    print("[t14] chain dependency: different prev_digest -> different final")

    e1 = mk_ent(KA, KB, 100, 10, 1, 0); e1["pt"] = (e1["pt"] + 1) % p
    _, r1, _, _, _ = fold_run([e1], ACC0, PREV, DECREE_ROOT)
    assert r1 == [V_REJ_BIND]
    _, r2, _, _, _ = fold_run([mk_ent(KA, KB, 100, 10, 3, 0)], ACC0, PREV, DECREE_ROOT)
    assert r2 == [V_REJ_NONCE]
    _, r3, _, _, _ = fold_run([mk_ent(KC, KB, 1000, 20, 1, 0)], ACC0, PREV, DECREE_ROOT)
    assert r3 == [V_REJ_INSOL]
    print("[t14] negatives: binding / nonce / insolvent-EXEC all REJECTED")

    # emission: fold_golden.hpp
    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1:
        print("[step14] FATAL: ambiguous dirs"); raise SystemExit(1)
    outdir = cdirs.pop()
    M6 = (1 << 64) - 1
    def _u(v): return "0x%016xull" % (v & M6)
    def _acc(k, a): return "{" + ", ".join(_u(x) for x in
        _s7_row(k) and [k & M6, (k >> 64) & M6, (k >> 128) & M6, (k >> 192) & M6,
        a["bal"] & M6, (a["bal"] >> 64) & M6, a["nonce"], a["flags"]]) + "}"
    def _ent(e): return "{" + ", ".join(_u(x) for x in [
        e["s"] & M6, (e["s"] >> 64) & M6, (e["s"] >> 128) & M6, (e["s"] >> 192) & M6,
        e["r"] & M6, (e["r"] >> 64) & M6, (e["r"] >> 128) & M6, (e["r"] >> 192) & M6,
        e["amount"] & M6, (e["amount"] >> 64) & M6,
        e["fee"] & M6, (e["fee"] >> 64) & M6,
        e["nonce"], e["status"],
        e["pt"] & M6, (e["pt"] >> 64) & M6, (e["pt"] >> 128) & M6, (e["pt"] >> 192) & M6]) + "}"
    def _fe4(v): return "{" + ", ".join(_u(x) for x in
        [v & M6, (v >> 64) & M6, (v >> 128) & M6, (v >> 192) & M6]) + "}"

    L = ["// GENERATED - STEP 14 (DEC-207). DO NOT EDIT.",
         "// Oracle: the fold step family semantics over the generator Poseidon twin.",
         "#pragma once", "#include <cstdint>", "namespace hsma::golden {",
         "inline constexpr unsigned G14F_NACC = 3u;",
         "inline constexpr unsigned G14F_NENT = 6u;",
         "inline constexpr unsigned G14F_COUNT = %du;" % count,
         "inline constexpr std::uint64_t G14F_ACC[3][8] = {",
         "    " + ", ".join(_acc(k, a) for k, a in ACC0.items()) + "};",
         "inline constexpr std::uint64_t G14F_ENT[6][18] = {",
         "    " + ", ".join(_ent(e) for e in E) + "};",
         "inline constexpr std::uint64_t G14F_RES[6] = {" +
             ", ".join(str(x) + "u" for x in res) + "};",
         "inline constexpr std::uint64_t G14F_PREV[4] = " + _fe4(PREV) + ";",
         "inline constexpr std::uint64_t G14F_DECREE[4] = " + _fe4(DECREE_ROOT) + ";",
         "inline constexpr std::uint64_t G14F_HEAD[4] = " + _fe4(_P3(IV_FOLD, PREV, DECREE_ROOT)) + ";",
         "inline constexpr std::uint64_t G14F_STEP[6][4] = {",
         "    " + ", ".join(_fe4(c) for c in chain) + "};",
         "inline constexpr std::uint64_t G14F_FINAL[4] = " + _fe4(final) + ";",
         "inline constexpr std::uint64_t G14F_FIN[3][8] = {",
         "    " + ", ".join(_acc(k, st_f[k]) for k in ACC0.keys()) + "};",
         "} // namespace hsma::golden"]
    txt = "\n".join(L) + "\n"
    if txt.count("{") != txt.count("}"):
        print("[step14] FATAL: brace law"); raise SystemExit(1)
    open(_os8.path.join(outdir, "fold_golden.hpp"), "w").write(txt)
    print("[step14][emit] fold_golden.hpp (accounts, 6 entries, verdicts, digest chain, finals)")

_step14()
