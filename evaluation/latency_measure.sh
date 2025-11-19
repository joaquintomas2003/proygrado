#!/usr/bin/env bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging helpers
step() {
    echo -e "${BLUE}[$1]========================================${NC}"
}

info() {
    echo -e "${YELLOW}$1${NC}"
}

ok() {
    echo -e "${GREEN}✔ $1${NC}"
}

fail() {
    echo -e "${RED}✖ $1${NC}"
}

# Check required tools
command -v python3 >/dev/null 2>&1 || { fail "python3 not found"; exit 1; }

echo
step "1/2"
info "Running script.py..."
if python3 script.py; then
    ok "script.py completed"
else
    fail "script.py failed"
    exit 1
fi
echo

step "2/2"
info "Running analyze.py..."
if python3 analyze.py; then
    ok "analyze.py completed"
else
    fail "analyze.py failed"
    exit 1
fi
echo

ok "✅ Latency analysis completed"