#!/usr/bin/env bash
# HSMA VERIFICATION GATE v5 (DEC-131/132/140/154):
#   configure → CLEAN-FIRST build → generated-header presence assert →
#   diagnostic sentinels (all layers) → conformance.
# clean-first kills the two historical masquerades: partial-output deletion
# (ninja multi-output trap) and stale binaries surviving failed compiles.
set -euo pipefail
cd "$(dirname "$0")/.."
cfg=$(mktemp); dg5=$(mktemp); dg6=$(mktemp)
trap 'rm -f "$cfg" "$dg5" "$dg6"' EXIT

echo "── [1/4] configure ──────────────────────────────"
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=MinSizeRel >"$cfg" 2>&1 \
  || { cat "$cfg"; echo "✗ CONFIGURE FAILED"; exit 1; }
grep -q "CMake Error" "$cfg" && { cat "$cfg"; echo "✗ CONFIG ERRORS"; exit 1; }
echo "   clean"

echo "── [2/4] build (CLEAN-FIRST — no ghosts survive) ──"
cmake --build build --clean-first 2>&1 | tee /dev/stderr \
  | grep -q "ninja: build stopped" && { echo "✗ BUILD FAILED"; exit 1; } || true

for h in pallas_params_gen.hpp vesta_params_gen.hpp field_golden.hpp \
         rnte_golden.hpp poseidon_params_gen.hpp domain_registry_gen.hpp \
         poseidon_golden.hpp smt_golden.hpp consensus_golden.hpp; do
  test -f "build/generated/$h" || { echo "✗ MISSING GENERATED: $h"; exit 1; }
done
echo "   all 9 generated headers present"

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
