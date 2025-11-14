#!/bin/bash
# Chaos Smoke Test Runner
# Runs abbreviated versions of all chaos scenarios

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

log_info "======================================="
log_info "Starting Chaos Engineering Smoke Tests"
log_info "======================================="
log_info ""

# Track results
tests_passed=0
tests_failed=0
failed_tests=()

run_test() {
  local test_name=$1
  local test_script=$2

  log_info "Running: ${test_name}..."
  log_info "-----------------------------------"

  if bash "${SCRIPT_DIR}/${test_script}" > /tmp/chaos-test-$$.log 2>&1; then
    log_success "✅ ${test_name} PASSED"
    ((tests_passed++))
  else
    log_error "❌ ${test_name} FAILED"
    ((tests_failed++))
    failed_tests+=("${test_name}")
    log_warning "See /tmp/chaos-test-$$.log for details"
  fi

  log_info ""
  sleep 5  # Cool-down between tests
}

# Run tests
log_info "Test 1/2: Database Connection Failure"
run_test "Database Failure" "database-failure.sh"

log_info "Test 2/2: RabbitMQ Message Broker Failure"
run_test "RabbitMQ Failure" "rabbitmq-failure.sh"

# Summary
log_info "======================================="
log_info "Chaos Test Suite Summary"
log_info "======================================="
log_success "Tests Passed: ${tests_passed}"
if [ ${tests_failed} -gt 0 ]; then
  log_error "Tests Failed: ${tests_failed}"
  log_error "Failed tests:"
  for test in "${failed_tests[@]}"; do
    log_error "  - ${test}"
  done
  exit 1
else
  log_success "All chaos tests passed! 🎉"
  exit 0
fi
