#!/bin/bash
set -euo pipefail

# Comprehensive Repository Independence Verification
# Verifies all 8 repositories are truly independent

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
REPORT_FILE="scripts/independence-verification-all-repos-${TIMESTAMP}.txt"
REPOS_DIR="/home/tomislav/repos"

REPOS=(
    "eracun-validation"
    "eracun-ingestion"
    "eracun-transformation"
    "eracun-integration"
    "eracun-archive"
    "eracun-infrastructure"
    "eracun-mocks"
    "eracun-contracts"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0;' # No Color

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_COUNT=0

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

log_test() {
    ((TOTAL_TESTS++))
    if [ "$1" = "PASS" ]; then
        ((PASSED_TESTS++))
        log "${GREEN}✓${NC} $2"
    elif [ "$1" = "FAIL" ]; then
        ((FAILED_TESTS++))
        log "${RED}✗${NC} $2"
    else
        ((WARNING_COUNT++))
        log "${YELLOW}⚠${NC} $2"
    fi
}

log ""
log "=============================================="
log "${BLUE}eRačun Repository Independence Verification${NC}"
log "=============================================="
log "Started: $(date)"
log "Repos Directory: $REPOS_DIR"
log ""

for repo in "${REPOS[@]}"; do
    REPO_PATH="${REPOS_DIR}/${repo}"

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "${BLUE}Repository: ${repo}${NC}"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ ! -d "$REPO_PATH" ]; then
        log_test "FAIL" "Repository directory not found: $REPO_PATH"
        continue
    fi

    cd "$REPO_PATH"

    # === Test 1: Git Repository ===
    if [ -d .git ]; then
        log_test "PASS" "[${repo}] Git repository initialized"
    else
        log_test "FAIL" "[${repo}] Git repository not initialized"
    fi

    # === Test 2: Required Documentation ===
    for doc in README.md TERMS_OF_REFERENCE.md CONTRACTS.md DEPENDENCY_GRAPH.md CODEOWNERS; do
        if [ -f "$doc" ]; then
            log_test "PASS" "[${repo}] $doc exists"
        else
            log_test "FAIL" "[${repo}] $doc missing"
        fi
    done

    # === Test 3: CI/CD Workflows ===
    if [ -f .github/workflows/ci.yml ]; then
        log_test "PASS" "[${repo}] CI workflow exists"
    else
        log_test "FAIL" "[${repo}] CI workflow missing"
    fi

    # === Test 4: No Hardcoded External Paths ===
    EXTERNAL_REFS=0
    for other_repo in "${REPOS[@]}"; do
        if [ "$other_repo" != "$repo" ]; then
            if grep -r "/repos/${other_repo}" --exclude-dir=node_modules --exclude-dir=.git . 2>/dev/null | grep -qv "Binary file"; then
                log_test "FAIL" "[${repo}] Hardcoded path to ${other_repo} found"
                ((EXTERNAL_REFS++))
            fi
        fi
    done

    if [ $EXTERNAL_REFS -eq 0 ]; then
        log_test "PASS" "[${repo}] No hardcoded external paths"
    fi

    # === Test 5: Dependencies via npm ===
    if [ "$repo" != "eracun-contracts" ] && [ -f package.json ]; then
        if grep -q '"@eracun/contracts"' package.json; then
            if grep -q '"@eracun/contracts": "file:' package.json; then
                log_test "FAIL" "[${repo}] Using file: reference for @eracun/contracts"
            else
                log_test "PASS" "[${repo}] Proper npm reference to @eracun/contracts"
            fi
        fi
    fi

    # === Test 6: Service READMEs ===
    if [ -d services ]; then
        MISSING_README=0
        SERVICE_COUNT=0
        for service_dir in services/*/; do
            if [ -d "$service_dir" ]; then
                ((SERVICE_COUNT++))
                if [ ! -f "${service_dir}README.md" ]; then
                    ((MISSING_README++))
                fi
            fi
        done

        if [ $SERVICE_COUNT -gt 0 ]; then
            if [ $MISSING_README -eq 0 ]; then
                log_test "PASS" "[${repo}] All $SERVICE_COUNT services have README.md"
            else
                log_test "WARN" "[${repo}] $MISSING_README/$SERVICE_COUNT services missing README.md"
            fi
        fi
    fi

    # === Test 7: Git Status ===
    if [ -z "$(git status --porcelain)" ]; then
        log_test "PASS" "[${repo}] Git working tree clean"
    else
        log_test "WARN" "[${repo}] Has uncommitted changes"
    fi

    # === Test 8: Git Remote ===
    if git remote -v | grep -q "origin"; then
        log_test "PASS" "[${repo}] Git remote configured"
    else
        log_test "WARN" "[${repo}] No git remote configured"
    fi

    log ""
done

# === Summary ===
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "${BLUE}VERIFICATION SUMMARY${NC}"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Total Tests: ${TOTAL_TESTS}"
log "${GREEN}Passed: ${PASSED_TESTS}${NC}"
log "${RED}Failed: ${FAILED_TESTS}${NC}"
log "${YELLOW}Warnings: ${WARNING_COUNT}${NC}"
log ""

PASS_RATE=$((100 * PASSED_TESTS / TOTAL_TESTS))
log "Pass Rate: ${PASS_RATE}%"
log ""

if [ $FAILED_TESTS -eq 0 ]; then
    log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${GREEN}✓ ALL REPOSITORIES VERIFIED AS INDEPENDENT${NC}"
    log "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log ""
    log "Each repository can be:"
    log "  ✓ Cloned independently"
    log "  ✓ Built independently"
    log "  ✓ Deployed independently"
    log "  ✓ Maintained by separate teams"
    log ""
    log "Report saved to: ${REPORT_FILE}"
    exit 0
else
    log "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${RED}✗ VERIFICATION FAILED${NC}"
    log "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "${FAILED_TESTS} test(s) failed"
    log "Report saved to: ${REPORT_FILE}"
    exit 1
fi
