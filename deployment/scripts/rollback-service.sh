#!/bin/bash
#
# Service Rollback Script
# Rolls back a service to a previous backup
#
# Usage: rollback-service.sh <service-name> <environment> [backup-timestamp]
# Example: rollback-service.sh invoice-gateway-api production 20251114-143022
#

set -euo pipefail

SERVICE_NAME="${1:-}"
ENVIRONMENT="${2:-staging}"
BACKUP_TIMESTAMP="${3:-latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Validation
if [[ -z "$SERVICE_NAME" ]]; then
  log_error "Service name required"
  echo "Usage: $0 <service-name> <environment> [backup-timestamp]" >&2
  exit 1
fi

case "$ENVIRONMENT" in
  staging)
    REMOTE_HOST="staging.eracun.internal"
    ;;
  production)
    REMOTE_HOST="production.eracun.hr"
    log_warn "ROLLING BACK PRODUCTION SERVICE!"
    read -p "Are you sure? Type 'yes' to continue: " confirm
    if [[ "$confirm" != "yes" ]]; then
      log_info "Rollback cancelled"
      exit 0
    fi
    ;;
  *)
    log_error "Unknown environment: $ENVIRONMENT"
    exit 1
    ;;
esac

REMOTE_SERVICE_DIR="/opt/eracun/services/${SERVICE_NAME}"
BACKUP_DIR="/opt/eracun/backups"

# Find backup
log_info "Finding backup..."

if [[ "$BACKUP_TIMESTAMP" == "latest" ]]; then
  # Get most recent backup
  BACKUP_PATH=$(ssh eracun@${REMOTE_HOST} "ls -t ${BACKUP_DIR}/${SERVICE_NAME}-* 2>/dev/null | head -1" || echo "")
else
  BACKUP_PATH="${BACKUP_DIR}/${SERVICE_NAME}-${BACKUP_TIMESTAMP}"
fi

if [[ -z "$BACKUP_PATH" ]]; then
  log_error "No backup found for ${SERVICE_NAME}"
  exit 1
fi

log_info "Using backup: $BACKUP_PATH"

# Stop service
log_info "Stopping service..."
ssh eracun@${REMOTE_HOST} "sudo systemctl stop eracun-${SERVICE_NAME}"

# Create backup of current (failed) version
log_info "Backing up current version..."
ssh eracun@${REMOTE_HOST} "
  sudo cp -r ${REMOTE_SERVICE_DIR} ${BACKUP_DIR}/${SERVICE_NAME}-failed-\$(date +%Y%m%d-%H%M%S)
"

# Restore from backup
log_info "Restoring from backup..."
ssh eracun@${REMOTE_HOST} "
  sudo rm -rf ${REMOTE_SERVICE_DIR}
  sudo cp -r ${BACKUP_PATH} ${REMOTE_SERVICE_DIR}
  sudo chown -R eracun:eracun ${REMOTE_SERVICE_DIR}
"

# Start service
log_info "Starting service..."
ssh eracun@${REMOTE_HOST} "sudo systemctl start eracun-${SERVICE_NAME}"

# Wait and verify
log_info "Waiting for service to start..."
sleep 5

ssh eracun@${REMOTE_HOST} "sudo systemctl is-active eracun-${SERVICE_NAME}" || {
  log_error "Service failed to start after rollback!"
  ssh eracun@${REMOTE_HOST} "sudo journalctl -u eracun-${SERVICE_NAME} -n 50 --no-pager"
  exit 1
}

log_info "✓ Rollback completed successfully"
log_info ""
log_info "Post-rollback actions:"
log_info "  1. Verify service functionality"
log_info "  2. Check logs for errors"
log_info "  3. Investigate root cause of failure"
log_info "  4. Failed version backed up to: ${BACKUP_DIR}/${SERVICE_NAME}-failed-*"
