#!/bin/bash
# scripts/verify.sh — Pre-commit verification for bugstr Rust crate
#
# Run this before every commit. The pre-commit hook calls it automatically.
# Exit code 0 = pass, non-zero = fail.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(dirname "$SCRIPT_DIR")"

cd "$RUST_DIR"

ERRORS=0

# 1. Tests must pass
echo "==> Running tests..."
if ! cargo test --lib --quiet 2>&1; then
    echo "FAIL: cargo test failed"
    ERRORS=$((ERRORS + 1))
fi

# 2. Release build must compile
echo "==> Checking release build..."
if ! cargo build --release --quiet 2>&1; then
    echo "FAIL: cargo build --release failed"
    ERRORS=$((ERRORS + 1))
fi

# 3. Check CHANGELOG updated when code changed
# Only applies when called from git hook context (staged files available)
if git rev-parse --git-dir >/dev/null 2>&1; then
    STAGED_CODE=$(git diff --cached --name-only -- 'rust/src/' 2>/dev/null || true)
    STAGED_CHANGELOG=$(git diff --cached --name-only -- 'rust/CHANGELOG.md' 2>/dev/null || true)

    if [ -n "$STAGED_CODE" ] && [ -z "$STAGED_CHANGELOG" ]; then
        echo "WARN: Rust source files changed but rust/CHANGELOG.md not staged."
        echo "      If this is a user-facing change, update CHANGELOG.md."
        # Warning only, not a hard failure — some changes (refactors, internal) don't need changelog
    fi
fi

# 4. Check for common PII patterns in test files
echo "==> Checking for PII in test fixtures..."
PII_PATTERNS='([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|(\bnsec1[a-z0-9]{58}\b)|(\bnpub1[a-z0-9]{58}\b)'
if grep -rEn "$PII_PATTERNS" src/ --include='*.rs' 2>/dev/null | grep -v '// PII-OK' | grep -v 'example\.com' | head -5; then
    echo "WARN: Possible PII found in source. Add '// PII-OK' comment if intentional."
fi

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "FAILED: $ERRORS error(s) found"
    exit 1
fi

echo ""
echo "OK: All checks passed"
exit 0
