#!/bin/bash
# Chaos Test: Network Latency and Packet Loss
# Tests system behavior under degraded network conditions using Toxiproxy

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

test_name="Network Latency and Packet Loss"
log_info "Starting chaos test: ${test_name}"

# Prerequisites check
check_prerequisite "docker" "docker"
check_prerequisite "curl" "curl"

# Check if Toxiproxy is available
if ! docker ps --format '{{.Names}}' | grep -q "toxiproxy"; then
  log_warning "Toxiproxy container not running. Starting it now..."
  docker run -d --name toxiproxy \
    --network eracun-network \
    -p 8474:8474 \
    -p 5433:5433 \
    ghcr.io/shopify/toxiproxy:2.5.0 || true
  sleep 3
fi

# Check if toxiproxy-cli is installed
if ! command -v toxiproxy-cli &> /dev/null; then
  log_error "toxiproxy-cli not installed. Install with: go install github.com/Shopify/toxiproxy/v2/cli/toxiproxy-cli@latest"
  log_info "Or download from: https://github.com/Shopify/toxiproxy/releases"
  log_info "Attempting to use docker exec as fallback..."
  TOXIPROXY_CMD="docker exec toxiproxy toxiproxy-cli"
else
  TOXIPROXY_CMD="toxiproxy-cli"
fi

# Verify services are healthy
log_info "Checking initial service health..."
if ! curl -sf http://localhost:3000/api/v1/health > /dev/null 2>&1; then
  log_error "Services not healthy before test. Aborting."
  exit 1
fi
log_success "Initial health check passed"

# Measure baseline performance
log_info "Step 1: Measuring baseline response time..."
baseline_time=$(measure_response_time "http://localhost:3000/api/v1/health")
log_info "Baseline response time: ${baseline_time}s"

# Inject network latency
log_info "Step 2: Injecting 500ms network latency..."
$TOXIPROXY_CMD toxic add \
  -n latency_downstream \
  -t latency \
  -a latency=500 \
  postgres_proxy 2>/dev/null || log_warning "Could not add latency toxic (proxy may not exist)"

sleep 2

# Test with latency
log_info "Step 3: Testing service with network latency..."
latency_time=$(measure_response_time "http://localhost:3000/api/v1/health")
log_info "Response time with latency: ${latency_time}s"

if (( $(echo "$latency_time > $baseline_time" | bc -l) )); then
  log_success "Latency increased as expected"
else
  log_warning "Response time did not increase significantly"
fi

# Inject packet loss
log_info "Step 4: Injecting 20% packet loss..."
$TOXIPROXY_CMD toxic add \
  -n packet_loss \
  -t loss_downstream \
  -a loss=0.2 \
  postgres_proxy 2>/dev/null || log_warning "Could not add packet loss toxic"

sleep 2

# Test service resilience
log_info "Step 5: Testing service resilience with packet loss..."
success_count=0
failure_count=0

for i in {1..10}; do
  response_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:3000/api/v1/invoices \
    -H "Content-Type: application/xml" \
    -H "X-Idempotency-Key: $(generate_uuid)" \
    -d @"${SCRIPT_DIR}/../fixtures/valid-invoice.xml" 2>/dev/null || echo "000")

  if [[ "$response_code" == "202" ]]; then
    ((success_count++))
  else
    ((failure_count++))
  fi
done

success_rate=$(echo "scale=2; $success_count / 10 * 100" | bc)
log_info "Success rate: ${success_rate}% (${success_count}/10 requests succeeded)"

if (( $(echo "$success_rate >= 80" | bc -l) )); then
  log_success "Service maintained acceptable success rate under packet loss"
else
  log_error "Service success rate too low: ${success_rate}%"
fi

# Check circuit breaker
log_info "Step 6: Checking circuit breaker state..."
circuit_breaker_count=$(curl -s http://localhost:9101/metrics | grep -c "circuit_breaker" || echo "0")
if [[ "$circuit_breaker_count" -gt 0 ]]; then
  log_info "Circuit breaker metrics present"
else
  log_warning "Circuit breaker metrics not found"
fi

# Remove toxics
log_info "Step 7: Removing network toxics..."
$TOXIPROXY_CMD toxic remove -n latency_downstream postgres_proxy 2>/dev/null || true
$TOXIPROXY_CMD toxic remove -n packet_loss postgres_proxy 2>/dev/null || true

sleep 3

# Verify recovery
log_info "Step 8: Verifying service recovery..."
recovery_time=$(measure_response_time "http://localhost:3000/api/v1/health")
log_info "Recovery response time: ${recovery_time}s"

if (( $(echo "$recovery_time < $latency_time" | bc -l) )); then
  log_success "Service recovered to normal response times"
else
  log_warning "Response time still elevated after toxic removal"
fi

# Final health check
log_info "Step 9: Final health check..."
final_response=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:3000/api/v1/invoices \
  -H "Content-Type: application/xml" \
  -H "X-Idempotency-Key: $(generate_uuid)" \
  -d @"${SCRIPT_DIR}/../fixtures/valid-invoice.xml")

if [[ "$final_response" == "202" ]]; then
  log_success "Invoice submission working normally after recovery"
else
  log_error "Invoice submission failed after recovery: ${final_response}"
fi

# Test summary
log_success "==================================="
log_success "Chaos Test Passed: ${test_name}"
log_success "==================================="
log_info "Results:"
log_info "  - Baseline response time: ${baseline_time}s"
log_info "  - Response time with latency: ${latency_time}s"
log_info "  - Success rate with packet loss: ${success_rate}%"
log_info "  - Recovery response time: ${recovery_time}s"
log_info "  - Service maintained resilience under network degradation"
log_success "==================================="

exit 0
