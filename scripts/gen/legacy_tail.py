import os
# HSMA :: gen/legacy_tail.py - the Steps 1-6 CLI glue (FROZEN).
if __name__ == "__main__":
    main()



# ============ STEP 7 APPEND - BLS12-377 scalar field F_r + threshold goldens (DEC-181..184) ============
import hashlib as _h7, re as _re7, os as os

def _step7_fatal(msg):
    print("[step7] FATAL: " + msg); raise SystemExit(1)

_DOCUMENTED_R = 8444461749428370424248824938781546531375899335154063827935233455917409239041  # CA-6/DEC-045 record

def _step7_prime(n):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    d = n - 1; s = 0
    while d % 2 == 0: d //= 2; s += 1
    bases = [2,3,5,7,11,13,17,19,23,29,31,37] + \
        [int.from_bytes(_h7.sha256(b"HSM_MR_v1" + bytes([i])).digest()[:16], "big") % (n - 3) + 2 for i in range(40)]
    for a in set(bases):
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        ok = False
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: ok = True; break
        if not ok: return False
    return True

def _step7_draw(n_, limit, salt):
    out = []; i = 0
    while len(out) < n_:
        v = int.from_bytes(_h7.sha256(salt + i.to_bytes(8, "big")).digest(), "big")
        i += 1
        if 0 < v < limit: out.append(v)
    return out

_S7_M64 = (1 << 64) - 1
def _s7_row(v):
    return "{0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull}" % \
        (v & _S7_M64, (v >> 64) & _S7_M64, (v >> 128) & _S7_M64, (v >> 192) & _S7_M64)
def _s7_rows(vals):
    return ",\n    ".join(_s7_row(v) for v in vals)

def _s7_pe(c, j, r):
    acc = 0
    for k in reversed(range(len(c))): acc = (acc * j + c[k]) % r
    return acc
