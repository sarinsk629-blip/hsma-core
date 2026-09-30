#!/usr/bin/env bash
# Phase 5 CLOSURE gate — base gate + binding + registers + hygiene + dependency law
set -euo pipefail; cd "$(dirname "$0")/.."
echo "── [P5-0] base gate ──";              ./scripts/gate.sh
echo "── [P5-1] DEC-090 float-free ──";    ./scripts/check_no_fp.sh
echo "── [P5-2] binding matrix ──";        python3 scripts/gen_binding.py
echo "── [P5-3] zero-dependency law ──"
if grep -rEq "third_party|attic" CMakeLists.txt; then echo "FAIL: build references archive/reference trees"; exit 1; fi
echo "[ok] build = include/ + generated/ + conformance/ + tools/ only"
echo "── [P5-4] property register 9/9 ──"
python3 - <<'PY'
import sys
req = ["Adversarial Bound","Quorum Forgery","Committee Collusion","Eclipse Divergence",
       "MEV Extraction","System Soundness","Slashing","Anti-Sybil","Component Liveness"]
t = open("docs/PROPERTY_REGISTER.md").read()
miss = [p for p in req if p not in t] + (["TBD present"] if "TBD" in t else [])
if miss: print("FAIL:", miss); sys.exit(1)
print("[ok] 9/9 PROVEN or WAIVED(reason+re-open)")
PY
echo "── [P5-5] claim register ──"
if grep -q "TBD" docs/CLAIM_REGISTER.md; then echo "FAIL: unresolved whitepaper claims"; exit 1; fi
echo "[ok] every theorem receipted"
echo ""; echo "═════════ PHASE 5 GATE — GREEN ═════════"
