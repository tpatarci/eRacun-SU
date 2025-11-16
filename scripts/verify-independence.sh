#!/bin/bash
# Repository Independence Verification Script
# Purpose: Automated verification of service independence
# Created: 2025-11-16

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PILOT_DIR="${1:-/tmp/eracun-infrastructure-pilot}"
REPORT_FILE="independence-verification-$(date +%Y%m%d-%H%M%S).txt"

echo "========================================="
echo "Repository Independence Verification"
echo "========================================="
echo "Target: $PILOT_DIR"
echo "Report: $REPORT_FILE"
echo ""

# Check if pilot directory exists
if [ ! -d "$PILOT_DIR" ]; then
    echo -e "${RED}Error: Directory $PILOT_DIR does not exist${NC}"
    exit 1
fi

# Initialize counters
TOTAL_SERVICES=0
SERVICES_WITH_PARENT_REFS=0
SERVICES_WITH_ERACUN_IMPORTS=0
SERVICES_BUILD_SUCCESS=0
SERVICES_TEST_SUCCESS=0

# Create report header
{
    echo "Repository Independence Verification Report"
    echo "==========================================="
    echo "Date: $(date)"
    echo "Directory: $PILOT_DIR"
    echo ""
} > "$REPORT_FILE"

# Function to check a service
check_service() {
    local service=$1
    local service_dir="$PILOT_DIR/services/$service"

    if [ ! -d "$service_dir" ]; then
        return 1
    fi

    echo "Checking: $service"
    TOTAL_SERVICES=$((TOTAL_SERVICES + 1))

    # Check for parent references
    local parent_refs=$(grep -r "\.\\./" --include="*.json" --include="*.ts" --exclude-dir=node_modules "$service_dir" 2>/dev/null | wc -l || true)
    if [ "$parent_refs" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠ Found $parent_refs parent references${NC}"
        SERVICES_WITH_PARENT_REFS=$((SERVICES_WITH_PARENT_REFS + 1))
        echo "  $service: $parent_refs parent references" >> "$REPORT_FILE"
    else
        echo -e "  ${GREEN}✓ No parent references${NC}"
    fi

    # Check for @eracun imports
    local eracun_imports=$(grep -r "@eracun/" --include="*.ts" --exclude-dir=node_modules "$service_dir" 2>/dev/null | wc -l || true)
    if [ "$eracun_imports" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠ Found $eracun_imports @eracun imports${NC}"
        SERVICES_WITH_ERACUN_IMPORTS=$((SERVICES_WITH_ERACUN_IMPORTS + 1))
        echo "  $service: $eracun_imports @eracun imports" >> "$REPORT_FILE"
    else
        echo -e "  ${GREEN}✓ No @eracun imports${NC}"
    fi

    # Check if it builds
    if [ -f "$service_dir/package.json" ]; then
        cd "$service_dir"
        if npm run build > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Build successful${NC}"
            SERVICES_BUILD_SUCCESS=$((SERVICES_BUILD_SUCCESS + 1))
        else
            echo -e "  ${RED}✗ Build failed${NC}"
            echo "  $service: Build failed" >> "$REPORT_FILE"
        fi

        # Check if tests run
        if npm test -- --passWithNoTests > /dev/null 2>&1; then
            echo -e "  ${GREEN}✓ Tests pass${NC}"
            SERVICES_TEST_SUCCESS=$((SERVICES_TEST_SUCCESS + 1))
        else
            echo -e "  ${YELLOW}⚠ Tests fail or missing${NC}"
        fi
        cd - > /dev/null
    fi

    echo ""
}

# Main verification loop
echo "Starting verification..."
echo ""

# Get list of services
if [ -d "$PILOT_DIR/services" ]; then
    for service_dir in "$PILOT_DIR"/services/*/; do
        if [ -d "$service_dir" ]; then
            service=$(basename "$service_dir")
            check_service "$service"
        fi
    done
fi

# Calculate percentages
INDEPENDENCE_SCORE=0
if [ $TOTAL_SERVICES -gt 0 ]; then
    NO_PARENT_REFS=$((TOTAL_SERVICES - SERVICES_WITH_PARENT_REFS))
    NO_ERACUN_IMPORTS=$((TOTAL_SERVICES - SERVICES_WITH_ERACUN_IMPORTS))

    PARENT_SCORE=$((NO_PARENT_REFS * 100 / TOTAL_SERVICES))
    IMPORT_SCORE=$((NO_ERACUN_IMPORTS * 100 / TOTAL_SERVICES))
    BUILD_SCORE=$((SERVICES_BUILD_SUCCESS * 100 / TOTAL_SERVICES))
    TEST_SCORE=$((SERVICES_TEST_SUCCESS * 100 / TOTAL_SERVICES))

    INDEPENDENCE_SCORE=$(( (PARENT_SCORE + IMPORT_SCORE + BUILD_SCORE + TEST_SCORE) / 4 ))
fi

# Summary
echo "========================================="
echo "SUMMARY"
echo "========================================="
echo "Total Services Checked: $TOTAL_SERVICES"
echo ""
echo "Static Analysis:"
echo "  Services with parent refs: $SERVICES_WITH_PARENT_REFS"
echo "  Services with @eracun imports: $SERVICES_WITH_ERACUN_IMPORTS"
echo ""
echo "Build & Test:"
echo "  Services that build: $SERVICES_BUILD_SUCCESS"
echo "  Services with passing tests: $SERVICES_TEST_SUCCESS"
echo ""

# Append summary to report
{
    echo ""
    echo "Summary"
    echo "-------"
    echo "Total Services: $TOTAL_SERVICES"
    echo "Parent References: $SERVICES_WITH_PARENT_REFS services affected"
    echo "@eracun Imports: $SERVICES_WITH_ERACUN_IMPORTS services affected"
    echo "Build Success: $SERVICES_BUILD_SUCCESS/$TOTAL_SERVICES"
    echo "Test Success: $SERVICES_TEST_SUCCESS/$TOTAL_SERVICES"
    echo ""
    echo "Independence Score: ${INDEPENDENCE_SCORE}%"
} >> "$REPORT_FILE"

# Display score with color
if [ $INDEPENDENCE_SCORE -ge 80 ]; then
    echo -e "${GREEN}Independence Score: ${INDEPENDENCE_SCORE}%${NC}"
    echo -e "${GREEN}Status: GOOD - Services are mostly independent${NC}"
elif [ $INDEPENDENCE_SCORE -ge 50 ]; then
    echo -e "${YELLOW}Independence Score: ${INDEPENDENCE_SCORE}%${NC}"
    echo -e "${YELLOW}Status: MODERATE - Some dependency issues remain${NC}"
else
    echo -e "${RED}Independence Score: ${INDEPENDENCE_SCORE}%${NC}"
    echo -e "${RED}Status: POOR - Significant dependency issues${NC}"
fi

echo ""
echo "Detailed report saved to: $REPORT_FILE"
echo ""

# Exit with appropriate code
if [ $INDEPENDENCE_SCORE -ge 80 ]; then
    exit 0
else
    exit 1
fi