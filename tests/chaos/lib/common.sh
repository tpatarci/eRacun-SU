#!/bin/bash
# Common functions for chaos testing

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Check if a command exists
check_prerequisite() {
  local cmd=$1
  local name=$2

  if ! command -v "$cmd" &> /dev/null; then
    log_error "${name} is not installed. Please install it first."
    exit 1
  fi
}

# Wait for service to be healthy
wait_for_health() {
  local url=$1
  local max_attempts=${2:-12}
  local delay=${3:-5}

  log_info "Waiting for service to be healthy: ${url}"

  for i in $(seq 1 $max_attempts); do
    if curl -s -f "$url" > /dev/null 2>&1; then
      log_success "Service is healthy after $((i * delay)) seconds"
      return 0
    fi

    if [ $i -lt $max_attempts ]; then
      log_info "Attempt $i/$max_attempts: Service not healthy yet, waiting ${delay}s..."
      sleep $delay
    fi
  done

  log_error "Service did not become healthy after $((max_attempts * delay)) seconds"
  return 1
}

# Measure response time
measure_response_time() {
  local url=$1
  local response_time=$(curl -o /dev/null -s -w '%{time_total}' "$url")
  echo "$response_time"
}

# Check if Docker container is running
check_container_running() {
  local container_name=$1

  if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
    return 0
  else
    return 1
  fi
}

# Get metric value from Prometheus
get_metric_value() {
  local metric_name=$1
  local port=${2:-9101}

  curl -s "http://localhost:${port}/metrics" | grep "^${metric_name}" | awk '{print $2}' | head -1
}

# Generate UUID (compatible with both Linux and macOS)
generate_uuid() {
  if command -v uuidgen &> /dev/null; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  else
    cat /proc/sys/kernel/random/uuid
  fi
}

# Cleanup function to be called on exit
cleanup() {
  local exit_code=$?

  if [ $exit_code -ne 0 ]; then
    log_warning "Test failed, performing cleanup..."
  fi

  # Reset any iptables rules
  if command -v iptables &> /dev/null; then
    sudo iptables -F OUTPUT 2>/dev/null || true
  fi

  # Stop any running Pumba containers
  docker ps -q --filter "ancestor=gaiaadm/pumba" | xargs -r docker stop 2>/dev/null || true

  return $exit_code
}

# Set trap for cleanup
trap cleanup EXIT

# Export functions
export -f log_info
export -f log_success
export -f log_warning
export -f log_error
export -f check_prerequisite
export -f wait_for_health
export -f measure_response_time
export -f check_container_running
export -f get_metric_value
export -f generate_uuid
