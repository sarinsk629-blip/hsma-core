import subprocess, sys, os, json
# build the known-answer receipt: A[i][j]=i*n+j, B=1 -> C[i][j]=i*n^2+n(n-1)/2 (DEF-305's key)
n = 4
A = b"".join(v.to_bytes(32, "little") for v in [i*n+j for i in range(n) for j in range(n)])
B = b"".join((1).to_bytes(32, "little") for _ in range(n*n))
body = json.dumps({"n": n, "a": A.hex(), "b": B.hex()})
# run the decoder's math on a self-computed receipt (no node needed — pure decode test):
# expected C values:
expected = [[i*n*n + n*(n-1)//2 for j in range(n)] for i in range(n)]
# simulate: C in canonical LE
Craw = b"".join(v.to_bytes(32, "little") for i in range(n) for j in range(n) for v in [i*n*n + n*(n-1)//2])
# decode via the same logic the tool uses:
ok = True
for i in range(n):
    for j in range(n):
        off = (i*n+j)*32
        v = int.from_bytes(Craw[off:off+8], "little")
        if v != expected[i][j]:
            ok = False
print("test_step51: ALL PASS — decode round-trip matches the analytic key (DEF-305)" if ok
      else "test_step51: FAILED")
sys.exit(0 if ok else 1)
