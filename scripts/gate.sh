#!/usr/bin/env bash
# HSMA VERIFICATION GATE (DEC-131)
# Order is law: configure → build → diagnostic authenticity → conformance.
# Any stage failing hard-aborts the pipeline. No binary runs unbuilt.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "── [1/4] configure ──────────────────────────────"
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=MinSizeRel > /tmp/hsma_cfg.log 2>&1 \
  || { cat /tmp/hsma_cfg.log; echo "✗ CONFIGURE FAILED"; exit 1; }
if grep -q "CMake Error" /tmp/hsma_cfg.log; then
    cat /tmp/hsma_cfg.log; echo "✗ CONFIGURE ERRORS"; exit 1
fi
echo "   clean"

echo "── [2/4] build ──────────────────────────────────"
cmake --build build 2>&1 | tee /tmp/hsma_build.log
# ninja nonzero ⇒ set -e aborts here. No test ever sees a stale object.

echo "── [3/4] diagnostic authenticity ────────────────"
./build/diag_step5 | tee /tmp/hsma_diag.out
if ! grep -q "VERDICT:" /tmp/hsma_diag.out; then
    echo "✗ STALE/INCOMPLETE DIAGNOSTIC (sentinel missing)"; exit 1
fi
if ! grep -q "REC   tag=3 (want 3)" /tmp/hsma_diag.out; then
    echo "✗ TAG SEVERED — storage layer diseased"; exit 1
fi
if ! grep -q "canonical-at-rest" /tmp/hsma_diag.out; then
    echo "✗ DEC-123 VIOLATED"; exit 1
fi
echo "   authentic + healthy"

echo "── [4/4] conformance suite ──────────────────────"
ctest --test-dir build --output-on-failure

echo "═══════════ GATE GREEN ═══════════"
