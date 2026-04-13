#!/usr/bin/env bash
#
# ci.sh: Full test cycle for ncapd
#
# Order: go build → go vet → gofmt → unit tests → integration tests
#
# Usage:
#   ./ci.sh                    # full cycle (unit + integration)
#   ./ci.sh --unit-only        # skip integration tests
#   ./ci.sh --integration-only # skip unit tests
#   ./ci.sh --no-build         # skip go build
#
# Exit codes:
#   0: all checks passed
#   1: one or more checks failed
#
# Requirements for integration tests:
#   - Docker & Docker Compose
#   - OpenSSL
#   - curl

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL=0

pass() {
    TOTAL_PASS=$((TOTAL_PASS + 1))
    printf "  ${GREEN}PASS${NC}  %s\n" "$1"
}

fail() {
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
    printf "  ${RED}FAIL${NC}  %s: %s\n" "$1" "${2:-}"
}

section() {
    echo ""
    printf "${CYAN}${BOLD}─── %s ───${NC}\n" "$1"
}

# Flags
UNIT_ONLY=false
SKIP_BUILD=false
INTEGRATION_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --unit-only)       UNIT_ONLY=true ;;
        --integration-only) INTEGRATION_ONLY=true ;;
        --no-build)        SKIP_BUILD=true ;;
        --help|-h)
            echo "Usage: ./ci.sh [--unit-only] [--integration-only] [--no-build]"
            echo ""
            echo "  --unit-only         Run only go build/vet/fmt + unit tests"
            echo "  --integration-only  Skip unit tests, run build + integration tests"
            echo "  --no-build          Skip go build step"
            echo "  --help              Show this help"
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

# Go build
if [ "$SKIP_BUILD" = false ]; then
    section "go build"
    if go build ./...; then
        pass "go build ./..."
    else
        fail "go build ./..." "compilation failed"
        echo ""
        printf "${RED}${BOLD}Build failed: aborting.${NC}\n"
        exit 1
    fi
fi

# Go vet
section "go vet"
if go vet ./...; then
    pass "go vet ./..."
else
    fail "go vet ./..." "static analysis issues found"
    echo ""
    printf "${YELLOW}Continuing despite vet warnings...${NC}\n"
fi

# Gofmt
section "gofmt"
UNFORMATTED=$(gofmt -l .)
if [ -z "$UNFORMATTED" ]; then
    pass "gofmt: all files formatted"
else
    fail "gofmt" "unformatted files: $(echo "$UNFORMATTED" | tr '\n' ' ')"
    # Auto-fix
    gofmt -w .
    printf "  ${YELLOW}Auto-fixed formatting${NC}\n"
fi

# Unit tests
if [ "$INTEGRATION_ONLY" = true ]; then
    section "Unit tests (skipped)"
    pass "Unit tests skipped (--integration-only)"
else
    section "Unit tests"

    if go test -count=1 -v -race -coverprofile=coverage.out -covermode=atomic ./...; then
        pass "go test -count=1 -race -cover ./..."

        grep -v "proto/" coverage.out | grep -v "tests/" > coverage.filtered

        COVERAGE=$(go tool cover -func=coverage.filtered | grep total | awk '{print $3}' | sed 's/%//')
        printf "  ${CYAN}INFO${NC}  coverage: %s%% (filtered: excludes proto/, tests/)\n" "$COVERAGE"
    else
        fail "go test -count=1 -race -cover ./..." "unit test failures or race detected"
        exit 1
    fi
fi

# Integration tests
if [ "$UNIT_ONLY" = true ]; then
    section "Summary (unit only)"
else
    section "Integration tests"

    INTEGRATION_DIR="$(cd "$(dirname "$0")" && pwd)/tests/integration"

    PREREQS_OK=true

    if ! command -v docker &>/dev/null; then
        fail "prerequisite" "docker not found in PATH"
        PREREQS_OK=false
    fi

    if ! docker compose version &>/dev/null 2>&1; then
        fail "prerequisite" "docker compose not available"
        PREREQS_OK=false
    fi

    if ! command -v openssl &>/dev/null; then
        fail "prerequisite" "openssl not found in PATH"
        PREREQS_OK=false
    fi

    if ! command -v curl &>/dev/null; then
        fail "prerequisite" "curl not found in PATH"
        PREREQS_OK=false
    fi

    if [ "$PREREQS_OK" = false ]; then
        echo ""
        printf "${YELLOW}Skipping integration tests: missing prerequisites${NC}\n"
    else
        echo "  Setting up integration environment..."

        if bash "${INTEGRATION_DIR}/setup.sh" \
            && docker compose -f "${INTEGRATION_DIR}/docker-compose.yml" up -d \
            && bash "${INTEGRATION_DIR}/test.sh"; then
            pass "integration tests (T1–T46)"
        else
            INT_EXIT=$?
            fail "integration tests" "exit code ${INT_EXIT}"
        fi

        echo ""
        echo "  Tearing down..."
        bash "${INTEGRATION_DIR}/teardown.sh" 2>/dev/null || true
    fi
fi

# Summary
section "Summary"
echo "  ${BOLD}Passed: ${TOTAL_PASS}${NC}"
echo "  ${BOLD}Failed: ${TOTAL_FAIL}${NC}"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
    printf "${RED}${BOLD}OVERALL: FAILED${NC}\n"
    exit 1
else
    printf "${GREEN}${BOLD}OVERALL: ALL CHECKS PASSED${NC}\n"
    exit 0
fi
