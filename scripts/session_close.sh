#!/bin/bash
# HSMA :: session_close.sh - THE PERMANENT SESSION-CLOSE SCRIPT
# This script guarantees that EVERY file modified or created during a
# session reaches GitHub. No targeted git add. No missed files. No gaps.
# CA-R163: the session-close sweep is MANDATORY before every session end.

set -e
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════"
echo "  SESSION CLOSE — the mandatory sweep"
echo "═══════════════════════════════════════"

# Step 1: stage EVERYTHING (no targeting, no exceptions)
echo ""
echo "[1/5] staging ALL changes..."
git add -A

# Step 2: show what's staged (the verification)
echo ""
echo "[2/5] staged changes:"
git diff --cached --stat

# Step 3: check if there's anything to commit
if git diff --cached --quiet; then
    echo ""
    echo "[3/5] nothing to commit — the repo is clean"
else
    echo ""
    echo "[3/5] committing..."
    read -p "commit message: " MSG
    git commit -m "${MSG:-session-close: all changes committed}"
fi

# Step 4: push
echo ""
echo "[4/5] pushing to GitHub..."
git push origin main 2>&1 | tail -3

# Step 5: verify
echo ""
echo "[5/5] verification:"
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git ls-remote origin main 2>/dev/null | cut -f1)
if [ "$LOCAL" = "$REMOTE" ]; then
    echo "  ✓ local == remote — everything is on GitHub"
else
    echo "  ✗ MISMATCH: local=$LOCAL remote=$REMOTE"
    echo "  run: git push origin main"
fi
UNTRACKED=$(git status --short | wc -l)
echo "  untracked remaining: $UNTRACKED"
if [ "$UNTRACKED" -gt 0 ]; then
    echo "  ⚠ UNTRACKED FILES REMAIN — run git add -A again"
fi

echo ""
echo "═══════════════════════════════════════"
echo "  SESSION CLOSE COMPLETE"
echo "═══════════════════════════════════════"
