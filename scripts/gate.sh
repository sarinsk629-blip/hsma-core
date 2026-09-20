#!/usr/bin/env bash
# HSMA VERIFICATION GATE v6 (DEC-131/132/140/154):
#   configure → CLEAN-FIRST build → generated-header presence assert →
#   diagnostic sentinels (all layers) → conformance.
# CA-R91: the presence assert enumerates ALL generated headers (was 9 of 29)
# + a count cross-check both directions (missing AND unregistered emissions).
# clean-first kills the two historical masquerades: partial-output deletion
# (ninja multi-output trap) and stale binaries surviving failed compiles.
set -euo pipefail
cd "$(dirname "$0")/.."
cfg=$(mktemp); dg5=$(mktemp); dg6=$(mktemp)
trap 'rm -f "$cfg" "$dg5" "$dg6"' EXIT

echo "── [0/4] generate golden vectors (prerequisite for compilation) ──"
python3 scripts/gen_run_new.py --out build/generated 2>&1 | tail -3
GEN_EXIT=$?
if [ "$GEN_EXIT" -ne 0 ]; then
  echo "✗ GENERATION FAILED (exit $GEN_EXIT)"
  exit 1
fi
echo "  generated: $(ls build/generated/*.hpp | wc -l) headers"

echo "── [1/4] configure ──────────────────────────────"
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=MinSizeRel >"$cfg" 2>&1 \
  || { cat "$cfg"; echo "✗ CONFIGURE FAILED"; exit 1; }
grep -q "CMake Error" "$cfg" && { cat "$cfg"; echo "✗ CONFIG ERRORS"; exit 1; }
echo "   clean"

echo "── [2/4] build (CLEAN-FIRST — no ghosts survive) ──"
cmake --build build 2>&1 | tee /dev/stderr | grep -q "ninja: build stopped" && { echo "✗ BUILD FAILED (CA-R151)"; exit 1; }
for t in test_step17 test_step33 test_step34; do
  [ -x "build/$t" ] || { echo "✗ BUILD INCOMPLETE: $t missing (CA-R151)"; exit 1; }
done
echo "── [3/4] diagnostics ────────────────────────────"
./build/diag_step5 | tee "$dg5"
grep -q "VERDICT:"          "$dg5" || { echo "✗ STALE DIAG5";    exit 1; }
grep -q "canonical-at-rest" "$dg5" || { echo "✗ DEC-123 VIOLATED"; exit 1; }
./build/diag_step6 | tee "$dg6"
grep -q "DIAG6:VERDICT ALL-OK" "$dg6" || { echo "✗ DIAG6 FAULT";  exit 1; }
echo "   authentic + healthy"

echo "── [4/4] conformance suite ──────────────────────"
ctest --test-dir build --output-on-failure
echo "═══════════ GATE GREEN ═══════════"
