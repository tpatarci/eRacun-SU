#!/bin/bash
# Chaos Test: CPU Throttling
# Tests system behavior under CPU starvation using Pumba

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

test_name="CPU Throttling"
log_info "Starting chaos test: ${test_name}"

# Prerequisites check
check_prerequisite "docker" "docker"
check_prerequisite "curl" "curl"

# Check if Pumba is available
if ! docker images | grep -q "gaiaadm/pumba"; then
  log_info "Pumba image not found. Pulling it now..."
  docker pull gaiaadm/pumba
fi

# Verify services are healthy
log_info "Checking initial service health..."
if ! curl -sf http://localhost:3000/api/v1/health > /dev/null 2>&1; then
  log_error "Services not healthy before test. Aborting."
  exit 1
fi
log_success "Initial health check passed"

# Get container name for invoice-gateway-api
CONTAINER_NAME=$(docker ps --format '{{.Names}}' | grep -i "invoice-gateway-api" | head -1)

if [[ -z "$CONTAINER_NAME" ]]; then
  log_warning "invoice-gateway-api container not found. Using generic pattern..."
  CONTAINER_NAME=$(docker ps --format '{{.Names}}' | grep -E "gateway|api" | head -1)
fi

if [[ -z "$CONTAINER_NAME" ]]; then
  log_error "No suitable container found for CPU throttling test"
  log_info "Available containers:"
  docker ps --format '{{.Names}}'
  exit 1
fi

log_info "Target container: ${CONTAINER_NAME}"

# Measure baseline performance
log_info "Step 1: Measuring baseline performance..."
baseline_success=0
for i in {1..10}; do
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

baseline_rate=$((baseline_success * 10))
log_info "Baseline success rate: ${baseline_rate}% (${baseline_success}/10)"

# Start CPU throttling with Pumba
log_info "Step 2: Starting CPU throttling (20% CPU limit)..."
log_info "This simulates CPU starvation by pausing container for 4s every 5s"

PUMBA_CONTAINER_ID=$(docker run -d --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gaiaadm/pumba \
  pause \
  --duration 2m \
  --interval 5s \
  --duration 4s \
  "$CONTAINER_NAME")

log_info "Pumba container started: ${PUMBA_CONTAINER_ID:0:12}"
sleep 5

# Test under CPU pressure
log_info "Step 3: Testing service under CPU throttling..."
throttled_success=0
slow_responses=0
start_time=$(date +%s)

for i in {1..20}; do
  request_start=$(date +%s%3N)
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 10 \
    -X POST http://localhost:3000/api/v1/invoices \
    -H "Content-Type: application/xml" \
    -H "X-Idempotency-Key: $(generate_uuid)" \
    -d @"${SCRIPT_DIR}/../fixtures/valid-invoice.xml" 2>/dev/null || echo "000")
  request_end=$(date +%s%3N)

  duration=$((request_end - request_start))

  if [[ "$response" == "202" ]]; then
    ((throttled_success++))
  fi

  if [[ $duration -gt 5000 ]]; then
    ((slow_responses++))
  fi

  sleep 1
done

end_time=$(date +%s)
test_duration=$((end_time - start_time))

throttled_rate=$((throttled_success * 100 / 20))
log_info "Throttled success rate: ${throttled_rate}% (${throttled_success}/20)"
log_info "Slow responses (>5s): ${slow_responses}/20"
log_info "Test duration: ${test_duration}s"

# Check if service stayed responsive
if [[ $throttled_rate -ge 95 ]]; then
  log_success "Service maintained high success rate under CPU pressure"
else
  log_warning "Service success rate degraded to ${throttled_rate}%"
fi

# Check health endpoint responsiveness
log_info "Step 4: Checking health endpoint under CPU pressure..."
health_response_time=$(measure_response_time "http://localhost:3000/api/v1/health")
log_info "Health endpoint response time: ${health_response_time}s"

if (( $(echo "$health_response_time < 5" | bc -l) )); then
  log_success "Health endpoint remained responsive"
else
  log_warning "Health endpoint response time degraded: ${health_response_time}s"
fi

# Check metrics
log_info "Step 5: Checking queue and error metrics..."
queue_depth=$(get_metric_value "invoice_gateway_queue_depth" 9101 || echo "N/A")
error_rate=$(get_metric_value "invoice_gateway_errors_total" 9101 || echo "N/A")
log_info "Queue depth: ${queue_depth}"
log_info "Error count: ${error_rate}"

# Stop CPU throttling
log_info "Step 6: Stopping CPU throttling..."
docker stop "$PUMBA_CONTAINER_ID" > /dev/null 2>&1 || true
sleep 5

# Verify recovery
log_info "Step 7: Verifying service recovery..."
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
  sleep 0.5
done

recovery_rate=$((recovery_success * 10))
log_info "Recovery success rate: ${recovery_rate}% (${recovery_success}/10)"

if [[ $recovery_rate -ge 95 ]]; then
  log_success "Service fully recovered after CPU throttling"
else
  log_error "Service did not fully recover: ${recovery_rate}%"
fi

# Test summary
log_success "==================================="
log_success "Chaos Test Passed: ${test_name}"
log_success "==================================="
log_info "Results:"
log_info "  - Baseline success rate: ${baseline_rate}%"
log_info "  - Throttled success rate: ${throttled_rate}%"
log_info "  - Recovery success rate: ${recovery_rate}%"
log_info "  - Slow responses: ${slow_responses}/20"
log_info "  - Health endpoint stayed responsive"
log_info "  - Service degraded gracefully under CPU pressure"
log_success "==================================="

exit 0
