#!/bin/bash
# k6 Load Test Runner
# Automated execution of all Team 3 load tests

set -e

echo "========================================="
echo "eRačun Load Testing Suite"
echo "Team 3: External Integration & Compliance"
echo "========================================="
echo ""

# Configuration
K6_VERSION="0.47.0"
BASE_URL="${BASE_URL:-http://localhost:8090}"
RESULTS_DIR="tests/load/results"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if k6 is installed
if ! command -v k6 &> /dev/null; then
    echo -e "${RED}❌ k6 is not installed${NC}"
    echo ""
    echo "Install k6:"
    echo "  macOS:   brew install k6"
    echo "  Ubuntu:  sudo gpg -k && sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69 && echo 'deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main' | sudo tee /etc/apt/sources.list.d/k6.list && sudo apt-get update && sudo apt-get install k6"
    echo "  Manual:  https://k6.io/docs/getting-started/installation/"
    exit 1
fi

echo -e "${GREEN}✓ k6 found (version $(k6 version))${NC}"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"
echo -e "${GREEN}✓ Results directory: $RESULTS_DIR${NC}"
echo ""

# Function to run a load test
run_test() {
    local test_name=$1
    local test_file=$2
    local duration=$3
    
    echo "========================================="
    echo "Running: $test_name"
    echo "File: $test_file"
    echo "Duration: $duration"
    echo "========================================="
    echo ""
    
    # Run k6 test
    if BASE_URL="$BASE_URL" k6 run \
        --out json="$RESULTS_DIR/${test_name}-${TIMESTAMP}.json" \
        "$test_file"; then
        echo -e "${GREEN}✅ $test_name completed successfully${NC}"
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        return 1
    fi
    
    echo ""
}

# Main execution
main() {
    echo "Configuration:"
    echo "  BASE_URL: $BASE_URL"
    echo "  RESULTS_DIR: $RESULTS_DIR"
    echo "  TIMESTAMP: $TIMESTAMP"
    echo ""
    
    # Check if services are running
    echo "Checking if services are available..."
    if ! curl -s -f "$BASE_URL/health" > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Warning: Services may not be running at $BASE_URL${NC}"
        echo "Start services with: docker-compose -f docker-compose.team3.yml up -d"
        echo ""
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}✓ Services are running${NC}"
    fi
    echo ""
    
    # Run tests
    local failed=0
    
    # Option to run specific test or all tests
    if [ $# -eq 0 ]; then
        echo "Running all load tests..."
        echo ""
        
        run_test "fina-submission" "tests/load/fina-submission.js" "16m" || ((failed++))
        run_test "archive-throughput" "tests/load/archive-throughput.js" "100m" || ((failed++))
        run_test "batch-signature" "tests/load/batch-signature.js" "63m" || ((failed++))
    else
        # Run specific test
        case "$1" in
            fina|fina-submission)
                run_test "fina-submission" "tests/load/fina-submission.js" "16m"
                ;;
            archive|archive-throughput)
                run_test "archive-throughput" "tests/load/archive-throughput.js" "100m"
                ;;
            batch|batch-signature)
                run_test "batch-signature" "tests/load/batch-signature.js" "63m"
                ;;
            *)
                echo -e "${RED}Unknown test: $1${NC}"
                echo ""
                echo "Available tests:"
                echo "  fina          - FINA submission load test (16 minutes)"
                echo "  archive       - Archive service throughput test (100 minutes)"
                echo "  batch         - Batch signature processing test (63 minutes)"
                echo ""
                echo "Run all tests: ./run-load-tests.sh"
                exit 1
                ;;
        esac
    fi
    
    # Summary
    echo "========================================="
    echo "Load Testing Complete"
    echo "========================================="
    echo "Results saved to: $RESULTS_DIR"
    echo "Failed tests: $failed"
    echo ""
    
    if [ $failed -eq 0 ]; then
        echo -e "${GREEN}✅ All tests passed${NC}"
        return 0
    else
        echo -e "${RED}❌ $failed test(s) failed${NC}"
        return 1
    fi
}

# Execute main function with all arguments
main "$@"
