#!/bin/bash
# Full Chaos Test Suite Runner
# Runs all 7 chaos scenarios with extended durations (30 minutes)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

log_success "==================================="
log_success "   FULL CHAOS TEST SUITE"
log_success "==================================="
log_info "Duration: ~30 minutes"
log_info "Scenarios: 7"
log_info ""

# Track results
declare -A test_results
total_tests=0
passed_tests=0
failed_tests=0
start_time=$(date +%s)

# Function to run a test and track results
run_test() {
  local test_name=$1
  local test_script=$2

  ((total_tests++))

  log_success "-----------------------------------"
  log_success "Test $total_tests/7: $test_name"
  log_success "-----------------------------------"
  log_info "Started at: $(date '+%Y-%m-%d %H:%M:%S')"
  echo ""

  if bash "$SCRIPT_DIR/$test_script"; then
    test_results[$test_name]="PASS"
    ((passed_tests++))
    log_success "✅ $test_name PASSED"
  else
    test_results[$test_name]="FAIL"
    ((failed_tests++))
    log_error "❌ $test_name FAILED"
  fi

  echo ""
  log_info "Waiting 30s before next test..."
  sleep 30
  echo ""
}

# Safety check
log_warning "⚠️  SAFETY CHECK"
log_warning "This test suite will:"
log_warning "  - Stop and restart Docker containers"
log_warning "  - Inject network failures and latency"
log_warning "  - Throttle CPU and memory"
log_warning "  - Modify iptables rules (requires sudo)"
log_warning ""
log_warning "NEVER run this in production!"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
  log_info "Test suite cancelled"
  exit 0
fi

echo ""
log_info "Starting full chaos test suite..."
echo ""

# Run all tests in sequence
run_test "Database Connection Failure" "database-failure.sh"
run_test "RabbitMQ Message Broker Failure" "rabbitmq-failure.sh"
run_test "Network Latency and Packet Loss" "network-failure.sh"
run_test "CPU Throttling" "cpu-throttling.sh"
run_test "Memory Pressure" "memory-pressure.sh"
run_test "Cascading Service Failures" "cascade-failure.sh"
run_test "Network Partition (Split Brain)" "partition-failure.sh"

# Calculate duration
end_time=$(date +%s)
duration=$((end_time - start_time))
duration_min=$((duration / 60))
duration_sec=$((duration % 60))

# Print summary
echo ""
log_success "==================================="
log_success "   CHAOS TEST SUITE COMPLETE"
log_success "==================================="
echo ""
log_info "Total Tests: $total_tests"
log_success "Passed: $passed_tests"
if [[ $failed_tests -gt 0 ]]; then
  log_error "Failed: $failed_tests"
fi
log_info "Duration: ${duration_min}m ${duration_sec}s"
echo ""

# Print detailed results
log_info "Detailed Results:"
log_info "-----------------------------------"
for test_name in "${!test_results[@]}"; do
  result=${test_results[$test_name]}
  if [[ "$result" == "PASS" ]]; then
    log_success "✅ $test_name"
  else
    log_error "❌ $test_name"
  fi
done
echo ""

# Overall result
if [[ $failed_tests -eq 0 ]]; then
  log_success "==================================="
  log_success "   ALL TESTS PASSED ✅"
  log_success "==================================="
  echo ""
  log_info "System demonstrated resilience across all chaos scenarios:"
  log_info "  - Database failures: Circuit breaker working"
  log_info "  - Message broker failures: Retry mechanisms working"
  log_info "  - Network degradation: Graceful degradation"
  log_info "  - CPU throttling: Maintained availability"
  log_info "  - Memory pressure: OOM handling working"
  log_info "  - Cascade failures: Circuit breaker prevented cascade"
  log_info "  - Network partitions: Idempotency maintained consistency"
  echo ""
  log_success "System is production-ready for chaos scenarios"
  exit 0
else
  log_error "==================================="
  log_error "   SOME TESTS FAILED ❌"
  log_error "==================================="
  echo ""
  log_warning "Review failed tests and address issues before production deployment"
  exit 1
fi
