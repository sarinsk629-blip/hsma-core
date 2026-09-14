# HSMA :: gen/steps/step18.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 18 APPEND — the G1 transport skeleton (DEC-211) ═══
# Sampler: Poseidon chain over registry domain HSM_PEERSEED_v1 (no new domains,
# no second hash - the C++ reuses poseidon3(dom, l, r) bit-exactly).
# Taxonomy P0..P3 (DEC-022); AccountID = Poseidon(IV_IDENT, pk) (DEC-024);
# EMA fixed-point lambda = 971532/1e6 = 2^(-1/24): 24h half-life (DEC-079).
import hashlib as _h18

def _step18():
    # derivation - direct insertion (CA-R72..75: no exec, no search, no indent games)
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    IV_PS = iv_derive(p, "HSM_PEERSEED_v1")
    IV_AC = iv_derive(p, "IV_IDENT")
    def _P3(iv, a, b): return poseidon3_ref(p, iv, a % p, b % p, MDS, RC)
    def _kint(tag): return int.from_bytes(_h18.sha256(tag).digest(), "big") % p
    def _u64(v): return int.from_bytes(v.to_bytes(32, "little")[:8], "little")

    # 1. the beacon-seeded sampler (whitepaper section 8.1)
    # d1 = P3(IV_PS, weight_root, beacon); d2 = P3(IV_PS, d1, C_id)
    # d3 = P3(IV_PS, d2, AccountID); seed = P3(IV_PS, d3, round)
    W = [300, 300, 200, 100, 100]
    T = sum(W)
    wr = _kint(b"G18F_WEIGHT_ROOT")
    bc = _kint(b"G18F_BEACON")
    cid = _kint(b"G18F_CID")
    obs = _kint(b"G18F_PEER_OBSERVER")
    def sampler_seed(round_r):
        d1 = _P3(IV_PS, wr, bc)
        d2 = _P3(IV_PS, d1, cid)
        d3 = _P3(IV_PS, d2, obs)
        return _P3(IV_PS, d3, round_r % p)
    def draw_k(seed, k):
        sel = _u64(_P3(IV_PS, seed, k % p)) % T
        c = 0
        for i, w in enumerate(W):
            c += w
            if sel < c:
                return i
        return len(W) - 1

    seed1 = sampler_seed(7)
    draws_a = [draw_k(seed1, k) for k in range(2000)]
    draws_b = [draw_k(sampler_seed(7), k) for k in range(2000)]
    assert draws_a == draws_b, "sampler not deterministic"
    hist = [0] * 5
    for d in draws_a:
        hist[d] += 1
    for i in range(5):
        exp = 2000 * W[i] // T
        assert abs(hist[i] - exp) <= max(10, exp * 20 // 100), (i, hist[i], exp)
    hsum = hist[0] + hist[1] + hist[2]
    lsum = hist[3] + hist[4]
    assert 3.0 <= hsum / float(lsum) <= 5.0, (hsum, lsum)
    print("[t18] sampler deterministic: 2000 draws x2 runs IDENTICAL")
    print("[t18] weight-proportional: heavy=%d light=%d (ratio %.2f, expected 4.00)" % (hsum, lsum, hsum / float(lsum)))

    # 2. the 4-tier message taxonomy (DEC-022); auth: 0=canonical-preimage, 1=content-addressed
    TAX = [(4 * 1024, 0, 0), (2 * 1024, 1, 0), (64 * 1024, 2, 1), (128 * 1024, 3, 1)]
    assert TAX[3][0] == 131072  # == MAX_PROOF_BYTES (params.hpp, 128 KB)
    def tx_ok(cls, size, pull):
        cap, tmode, auth = TAX[cls]
        if size > cap: return False
        if tmode == 3 and not pull: return False  # P3 is pull-only
        return True
    assert tx_ok(0, 4096, True) and not tx_ok(0, 4097, True)
    assert tx_ok(1, 2048, True) and not tx_ok(1, 2049, True)
    assert tx_ok(2, 65536, True) and not tx_ok(2, 65537, True)
    assert tx_ok(3, 131072, True) and not tx_ok(3, 131072, False)
    print("[t18] taxonomy: caps enforced P0=4KB P1=2KB P2=64KB P3=128KB; P3 pull-only; P3 cap == MAX_PROOF_BYTES")

    # 3. the contact root (DEC-024): AccountID = Poseidon(IV_IDENT, consensus_pk)
    pks = [_kint(b"G18F_PK_" + str(i).encode()) for i in range(4)]
    accts = [_P3(IV_AC, pk, 0) for pk in pks]
    assert len(set(accts)) == 4
    last_rebind = {0: 7}
    def rebind(u, epoch):
        if u in last_rebind and epoch - last_rebind[u] < 1: return False
        last_rebind[u] = epoch; return True
    assert not rebind(0, 7)   # same-epoch rebind: cooldown blocks
    assert rebind(0, 8)       # next epoch: allowed
    assert _P3(IV_AC, pks[0], 0) == accts[0]  # transport-ID rotation keeps AccountID
    print("[t18] contact: AccountID=pk-bound; rebind blocked same-epoch, allowed E+1; transport-ID rotation keeps AccountID")

    # 4. peer scoring EMA (DEC-079) - fixed-point integers (DEC-090 discipline)
    SC = 1000000
    LAM_N, LAM_D = 971532, 1000000   # lambda = 2^(-1/24): 24h half-life
    IMP = 25000                      # bounded negative impulse: max 2.5 percent/hour
    TH_CORE, TH_GRAY = 800000, 600000
    def ema_tick(s, x):
        if x: return min(SC, s + (SC - s) * 28468 // 1000000)
        return (s * LAM_N) // LAM_D
    s24 = SC
    for _ in range(24): s24 = ema_tick(s24, 0)
    assert abs(s24 - 500000) <= 500, s24
    s_rec = s24
    for _ in range(48): s_rec = ema_tick(s_rec, 1)
    assert s_rec >= TH_CORE, s_rec
    s_bounded = SC - IMP   # 100 faults in one window = ONE impulse (the bound)
    def classify(s): return 2 if s >= TH_CORE else (1 if s >= TH_GRAY else 0)
    assert classify(SC) == 2 and classify(700000) == 1 and classify(100000) == 0
    print("[t18] EMA: 24h half-life = %d/1e6 (want 500000); 48h recovery to core (%d); impulse bound %d/h; thresholds classified" % (s24, s_rec, IMP))

    # 5. emission
    seeds = [sampler_seed(rr) for rr in (7, 8, 9, 10)]
    g = []
    g.append("inline constexpr std::uint64_t G18T_T = %du;" % T)
    g.append("inline constexpr std::uint64_t G18T_W[5] = {%s};" % ", ".join(str(w) + "u" for w in W))
    g.append("inline constexpr std::uint64_t G18T_IN[3][4] = {\n " + ",\n ".join(_s7_row(x) for x in (wr, bc, cid)) + "\n};")
    g.append("inline constexpr std::uint64_t G18T_OBS[4] = " + _s7_row(obs) + ";")
    g.append("inline constexpr std::uint64_t G18T_PK[4][4] = {\n " + ",\n ".join(_s7_row(x) for x in pks) + "\n};")
    g.append("inline constexpr std::uint64_t G18T_RND[4] = {7u, 8u, 9u, 10u};")
    g.append("inline constexpr std::uint64_t G18T_SEED[4][4] = {\n " + ",\n ".join(_s7_row(sv) for sv in seeds) + "\n};")
    g.append("inline constexpr std::uint64_t G18T_FIRST[10] = {%s};" % ", ".join(str(v) + "u" for v in draws_a[:10]))
    g.append("inline constexpr std::uint64_t G18T_HIST[5] = {%s};" % ", ".join(str(hv) + "u" for hv in hist))
    g.append("inline constexpr std::uint64_t G18T_TAX[4][3] = {\n " + ",\n ".join("{%du, %du, %du}" % t for t in TAX) + "\n};")
    g.append("inline constexpr std::uint64_t G18T_ACCT[4][4] = {\n " + ",\n ".join(_s7_row(a) for a in accts) + "\n};")
    g.append("inline constexpr std::uint64_t G18T_EMA_24 = %du;" % s24)
    g.append("inline constexpr std::uint64_t G18T_EMA_REC = %du;" % s_rec)
    g.append("inline constexpr std::uint64_t G18T_LAM[2] = {%du, %du};" % (LAM_N, LAM_D))
    g.append("inline constexpr std::uint64_t G18T_REC[2] = {28468u, 1000000u};")
    g.append("inline constexpr std::uint64_t G18T_IMP = %du;" % IMP)
    g.append("inline constexpr std::uint64_t G18T_TH[2] = {%du, %du};" % (TH_CORE, TH_GRAY))
    hp = "// GENERATED FILE - g1_golden.hpp (Step 18, DEC-211)\n#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n"
    for ln in g: hp += ln + "\n"
    hp += "} // namespace hsma::golden\n"
    import os as _os18
    _root18 = _os18.path.dirname(_os18.path.dirname(_os18.path.abspath(__file__)))
    _tgt18 = _os18.path.join(_root18, "build", "generated", "g1_golden.hpp")
    _os18.makedirs(_os18.path.dirname(_tgt18), exist_ok=True)
    with open(_tgt18, "w") as f: f.write(hp)
    print("[step18][emit] g1_golden.hpp (sampler inputs, seeds x4, first-10 draws, 2000-draw histogram, taxonomy, account IDs x4, EMA trace)")

_step18()
