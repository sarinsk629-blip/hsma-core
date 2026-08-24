#!/usr/bin/env bash
# HSMA VERIFICATION GATE v2 (DEC-131, amended DEC-132)
# Order is law: configure → build → diagnostic authenticity → conformance.
# Portability: ALL temp logs via mktemp (honors Termux TMPDIR; /tmp-free).
set -euo pipefail
cd "$(dirname "$0")/.."

cfg_log=$(mktemp); build_log=$(mktemp); diag_out=$(mktemp)
trap 'rm -f "$cfg_log" "$build_log" "$diag_out"' EXIT

echo "── [1/4] configure ──────────────────────────────"
if ! cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=MinSizeRel >"$cfg_log" 2>&1; then
    cat "$cfg_log"; echo "✗ CONFIGURE FAILED"; exit 1
fi
if grep -q "CMake Error" "$cfg_log"; then
    cat "$cfg_log"; echo "✗ CONFIGURE ERRORS"; exit 1
fi
echo "   clean"

echo "── [2/4] build ──────────────────────────────────"
cmake --build build 2>&1 | tee "$build_log"
# ninja nonzero ⇒ set -e aborts here. Nothing downstream ever runs unbuilt.

echo "── [3/4] diagnostic authenticity ────────────────"
./build/diag_step5 | tee "$diag_out"
grep -q "VERDICT:"             "$diag_out" || { echo "✗ STALE DIAGNOSTIC";   exit 1; }
grep -q "REC   tag=3 (want 3)" "$diag_out" || { echo "✗ TAG SEVERED";         exit 1; }
grep -q "canonical-at-rest"    "$diag_out" || { echo "✗ DEC-123 VIOLATED";    exit 1; }
echo "   authentic + healthy"

echo "── [4/4] conformance suite ──────────────────────"
ctest --test-dir build --output-on-failure

echo "═══════════ GATE GREEN ═══════════"
