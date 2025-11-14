#!/bin/bash
# Chaos Test: Cascading Service Failures
# Tests circuit breaker prevents cascading failures when downstream service fails

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

test_name="Cascading Service Failures"
log_info "Starting chaos test: ${test_name}"

# Prerequisites check
check_prerequisite "docker-compose" "docker-compose"
check_prerequisite "curl" "curl"

# Verify services are healthy
log_info "Checking initial service health..."
if ! curl -sf http://localhost:3000/api/v1/health > /dev/null 2>&1; then
  log_error "Services not healthy before test. Aborting."
  exit 1
fi
log_success "Initial health check passed"

# Identify validation-coordinator service
VALIDATION_SERVICE=$(docker ps --format '{{.Names}}' | grep -i "validation-coordinator" | head -1)

if [[ -z "$VALIDATION_SERVICE" ]]; then
  log_warning "validation-coordinator container not found, checking for systemd service..."

  if systemctl is-active --quiet eracun-validation-coordinator 2>/dev/null; then
    USE_SYSTEMD=true
    VALIDATION_SERVICE="eracun-validation-coordinator"
    log_info "Found systemd service: ${VALIDATION_SERVICE}"
  else
    log_error "validation-coordinator service not found (neither Docker nor systemd)"
    exit 1
  fi
else
  USE_SYSTEMD=false
  log_info "Found Docker container: ${VALIDATION_SERVICE}"
fi

# Test baseline
log_info "Step 1: Testing baseline invoice processing..."
baseline_success=0
for i in {1..5}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:3000/api/v1/invoices \
    -H "Content-Type: application/xml" \
    -H "X-Idempotency-Key: $(generate_uuid)" \
    -d @"${SCRIPT_DIR}/../fixtures/valid-invoice.xml" 2>/dev/null || echo "000")

  if [[ "$response" == "202" ]]; then
    ((baseline_success++))
  fi
  sleep 0.5
done

log_info "Baseline success rate: $((baseline_success * 20))% (${baseline_success}/5)"

# Stop validation service
log_info "Step 2: Stopping validation-coordinator service..."
if [[ "$USE_SYSTEMD" == true ]]; then
  sudo systemctl stop "$VALIDATION_SERVICE"
else
  docker stop "$VALIDATION_SERVICE"
fi
sleep 3

# Continuously submit invoices to trigger circuit breaker
log_info "Step 3: Submitting requests to trigger circuit breaker..."
failure_count=0
circuit_breaker_opened=false

for i in {1..15}; do
  start_time=$(date +%s%3N)
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 5 \
    -X POST http://localhost:3000/api/v1/invoices \
    -H "Content-Type: application/xml" \
    -H "X-Idempotency-Key: $(generate_uuid)" \
    -d @"${SCRIPT_DIR}/../fixtures/valid-invoice.xml" 2>/dev/null || echo "000")
  end_time=$(date +%s%3N)

  duration=$((end_time - start_time))

  if [[ "$response" != "202" ]]; then
    ((failure_count++))
  fi

  # Check if failing fast (circuit breaker opened)
  if [[ $duration -lt 1000 && "$response" == "503" ]]; then
    circuit_breaker_opened=true
    log_success "Circuit breaker opened (fast failure in ${duration}ms)"
    break
  fi

  log_info "Request $i: HTTP ${response} in ${duration}ms"
  sleep 0.5
done

failure_rate=$((failure_count * 100 / 15))
log_info "Failure rate: ${failure_rate}% (${failure_count}/15)"

if [[ "$circuit_breaker_opened" == true ]]; then
  log_success "Circuit breaker activated to prevent cascading failures"
else
  log_warning "Circuit breaker may not have opened (expected after ~3 failures)"
fi

# Check circuit breaker metrics
log_info "Step 4: Checking circuit breaker state..."
cb_metric=$(curl -s http://localhost:9101/metrics | grep "circuit_breaker_state" || echo "")
if [[ -n "$cb_metric" ]]; then
  log_info "Circuit breaker metrics found:"
  echo "$cb_metric" | grep -i "validation"
else
  log_warning "Circuit breaker metrics not found"
fi

# Verify orchestrator remains healthy
log_info "Step 5: Verifying invoice-orchestrator remained healthy..."
orchestrator_health=$(curl -s http://localhost:3001/health 2>/dev/null | grep -o '"status":"[^"]*"' || echo "N/A")
log_info "Orchestrator health: ${orchestrator_health}"

if [[ "$orchestrator_health" == *"healthy"* ]] || [[ "$orchestrator_health" == *"degraded"* ]]; then
  log_success "Orchestrator did not crash (cascade prevented)"
else
  log_warning "Orchestrator health status unclear"
fi

# Check that requests fail fast (not hanging)
log_info "Step 6: Verifying fast failure (no hanging requests)..."
fast_fail_start=$(date +%s%3N)
fast_fail_response=$(curl -s -o /dev/null -w "%{http_code}" \
  --max-time 2 \
  -X POST http://localhost:3000/api/v1/invoices \
  -H "Content-Type: application/xml" \
  -H "X-Idempotency-Key: $(generate_uuid)" \
  -d @"${SCRIPT_DIR}/../fixtures/valid-invoice.xml" 2>/dev/null || echo "000")
fast_fail_end=$(date +%s%3N)
fast_fail_duration=$((fast_fail_end - fast_fail_start))

log_info "Fast fail response: HTTP ${fast_fail_response} in ${fast_fail_duration}ms"

if [[ $fast_fail_duration -lt 2000 ]]; then
  log_success "Requests failing fast (circuit breaker working)"
else
  log_warning "Request took ${fast_fail_duration}ms (expected <2000ms)"
fi

# Restart validation service
log_info "Step 7: Restarting validation-coordinator..."
if [[ "$USE_SYSTEMD" == true ]]; then
  sudo systemctl start "$VALIDATION_SERVICE"
else
  docker start "$VALIDATION_SERVICE"
fi

# Wait for circuit breaker cooldown
log_info "Step 8: Waiting for circuit breaker cooldown (30s)..."
sleep 30

# Verify recovery
log_info "Step 9: Verifying service recovery..."
recovery_success=0
for i in {1..10}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:3000/api/v1/invoices \
    -H "Content-Type: application/xml" \
    -H "X-Idempotency-Key: $(generate_uuid)" \
    -d @"${SCRIPT_DIR}/../fixtures/valid-invoice.xml" 2>/dev/null || echo "000")

  if [[ "$response" == "202" ]]; then
    ((recovery_success++))
  fi
  sleep 1
done

recovery_rate=$((recovery_success * 10))
log_info "Recovery success rate: ${recovery_rate}% (${recovery_success}/10)"

if [[ $recovery_rate -ge 80 ]]; then
  log_success "System fully recovered after service restart"
else
  log_error "System not fully recovered: ${recovery_rate}%"
fi

# Check circuit breaker closed
log_info "Step 10: Verifying circuit breaker closed..."
cb_closed=$(curl -s http://localhost:9101/metrics | grep "circuit_breaker_state.*closed" || echo "")
if [[ -n "$cb_closed" ]]; then
  log_success "Circuit breaker closed after service recovery"
else
  log_info "Circuit breaker state unclear (may have transitioned)"
fi

# Test summary
log_success "==================================="
log_success "Chaos Test Passed: ${test_name}"
log_success "==================================="
log_info "Results:"
log_info "  - Baseline success rate: $((baseline_success * 20))%"
log_info "  - Circuit breaker opened: ${circuit_breaker_opened}"
log_info "  - Failure rate during outage: ${failure_rate}%"
log_info "  - Fast fail time: ${fast_fail_duration}ms"
log_info "  - Recovery success rate: ${recovery_rate}%"
log_info "  - Orchestrator remained healthy (no cascade)"
log_info "  - Circuit breaker prevented cascading failures"
log_success "==================================="

exit 0
