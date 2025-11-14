#!/bin/bash
#
# Service Deployment Script
# Deploys a single eRačun microservice to production
#
# Usage: deploy-service.sh <service-name> <environment>
# Example: deploy-service.sh invoice-gateway-api production
#

set -euo pipefail

SERVICE_NAME="${1:-}"
ENVIRONMENT="${2:-staging}"

# Validation
if [[ -z "$SERVICE_NAME" ]]; then
  echo "Error: Service name required" >&2
  echo "Usage: $0 <service-name> <environment>" >&2
  echo "" >&2
  echo "Available services:" >&2
  echo "  - invoice-gateway-api" >&2
  echo "  - invoice-orchestrator" >&2
  echo "  - ubl-transformer" >&2
  echo "  - validation-coordinator" >&2
  exit 1
fi

# Paths
LOCAL_DIST_DIR="services/${SERVICE_NAME}/dist"
REMOTE_SERVICE_DIR="/opt/eracun/services/${SERVICE_NAME}"
SYSTEMD_UNIT="/etc/systemd/system/eracun-${SERVICE_NAME}.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Pre-deployment checks
log_info "Pre-deployment checks for ${SERVICE_NAME}..."

if [[ ! -d "$LOCAL_DIST_DIR" ]]; then
  log_error "Build directory not found: $LOCAL_DIST_DIR"
  log_error "Please run 'npm run build' first"
  exit 1
fi

log_info "✓ Build directory found"

# Build and test
log_info "Running tests..."
cd "services/${SERVICE_NAME}"
npm test || {
  log_error "Tests failed! Aborting deployment."
  exit 1
}
log_info "✓ All tests passed"

# TypeScript compilation check
log_info "Checking TypeScript compilation..."
npm run typecheck || {
  log_error "TypeScript compilation errors! Aborting deployment."
  exit 1
}
log_info "✓ TypeScript check passed"

# Build
log_info "Building service..."
npm run build || {
  log_error "Build failed! Aborting deployment."
  exit 1
}
log_info "✓ Build successful"

cd ../..

# Deployment (rsync to remote)
log_info "Deploying to ${ENVIRONMENT}..."

case "$ENVIRONMENT" in
  staging)
    REMOTE_HOST="staging.eracun.internal"
    ;;
  production)
    REMOTE_HOST="production.eracun.hr"
    ;;
  *)
    log_error "Unknown environment: $ENVIRONMENT"
    exit 1
    ;;
esac

# Backup current version
log_info "Creating backup of current version..."
ssh eracun@${REMOTE_HOST} "
  sudo mkdir -p /opt/eracun/backups
  sudo cp -r ${REMOTE_SERVICE_DIR} /opt/eracun/backups/${SERVICE_NAME}-\$(date +%Y%m%d-%H%M%S) || true
"

# Stop service
log_info "Stopping service..."
ssh eracun@${REMOTE_HOST} "sudo systemctl stop eracun-${SERVICE_NAME} || true"

# Deploy artifacts
log_info "Syncing files..."
rsync -avz --delete \
  --exclude='node_modules' \
  --exclude='tests' \
  --exclude='*.test.ts' \
  --exclude='coverage' \
  "services/${SERVICE_NAME}/" \
  "eracun@${REMOTE_HOST}:${REMOTE_SERVICE_DIR}/"

# Install production dependencies
log_info "Installing production dependencies..."
ssh eracun@${REMOTE_HOST} "
  cd ${REMOTE_SERVICE_DIR}
  npm ci --production --ignore-scripts
"

# Reload systemd
log_info "Reloading systemd daemon..."
ssh eracun@${REMOTE_HOST} "sudo systemctl daemon-reload"

# Start service
log_info "Starting service..."
ssh eracun@${REMOTE_HOST} "sudo systemctl start eracun-${SERVICE_NAME}"

# Wait for startup
log_info "Waiting for service to start..."
sleep 5

# Verify service is running
log_info "Verifying service status..."
ssh eracun@${REMOTE_HOST} "sudo systemctl is-active eracun-${SERVICE_NAME}" || {
  log_error "Service failed to start!"
  log_error "Checking logs..."
  ssh eracun@${REMOTE_HOST} "sudo journalctl -u eracun-${SERVICE_NAME} -n 50 --no-pager"
  exit 1
}

log_info "✓ Service is running"

# Health check (if available)
log_info "Running health check..."
HEALTH_URL="http://${REMOTE_HOST}:3000/health"
HEALTH_STATUS=$(ssh eracun@${REMOTE_HOST} "curl -s -o /dev/null -w '%{http_code}' ${HEALTH_URL}" || echo "000")

if [[ "$HEALTH_STATUS" == "200" ]]; then
  log_info "✓ Health check passed"
else
  log_warn "Health check returned: $HEALTH_STATUS"
fi

# Show logs
log_info "Recent logs:"
ssh eracun@${REMOTE_HOST} "sudo journalctl -u eracun-${SERVICE_NAME} -n 20 --no-pager"

log_info "🎉 Deployment completed successfully!"
log_info ""
log_info "Post-deployment checklist:"
log_info "  1. Verify metrics in Grafana"
log_info "  2. Check error rates in logs"
log_info "  3. Monitor queue depths (if applicable)"
log_info "  4. Run smoke tests"
