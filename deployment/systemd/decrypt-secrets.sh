#!/bin/bash
# decrypt-secrets.sh - Decrypt SOPS-encrypted secrets for systemd services
#
# Usage: decrypt-secrets.sh <service-name>
# Example: decrypt-secrets.sh email-worker
#
# This script is called by systemd ExecStartPre to decrypt secrets
# before the service starts. Decrypted secrets are written to tmpfs
# (/run/eracun/) which is cleared on every reboot.
#
# SECURITY:
# - Runs as root (needed to create /run/eracun/ and chown to eracun user)
# - age private key at /etc/eracun/.age-key (mode 600, root:root)
# - Decrypted secrets at /run/eracun/secrets.env (mode 600, eracun:eracun)
# - tmpfs ensures secrets never written to disk
#
# INSTALLATION:
# sudo cp deployment/systemd/decrypt-secrets.sh /usr/local/bin/
# sudo chmod 755 /usr/local/bin/decrypt-secrets.sh

set -euo pipefail

# Configuration
SERVICE_NAME="${1:-}"
AGE_KEY_FILE="/etc/eracun/.age-key"
SECRETS_DIR="/etc/eracun/secrets"
RUNTIME_DIR="/run/eracun"
DECRYPTED_OUTPUT="${RUNTIME_DIR}/secrets.env"
LOG_TAG="eracun-decrypt[$$]"

# Logging function
log() {
  local level="$1"
  shift
  logger -t "${LOG_TAG}" -p "user.${level}" "$@"
  echo "[${level^^}] $@" >&2
}

# Validate arguments
if [ -z "${SERVICE_NAME}" ]; then
  log err "Usage: $0 <service-name>"
  log err "Example: $0 email-worker"
  exit 1
fi

log info "Decrypting secrets for service: ${SERVICE_NAME}"

# Check for required tools
if ! command -v sops &> /dev/null; then
  log err "SOPS not found. Install: apt-get install sops"
  exit 1
fi

if ! command -v age &> /dev/null; then
  log err "age not found. Install: apt-get install age"
  exit 1
fi

# Check for age private key
if [ ! -f "${AGE_KEY_FILE}" ]; then
  log err "age private key not found: ${AGE_KEY_FILE}"
  log err "Generate with: age-keygen -o ${AGE_KEY_FILE}"
  exit 1
fi

# Verify age key permissions (must be 600)
AGE_KEY_PERMS=$(stat -c '%a' "${AGE_KEY_FILE}")
if [ "${AGE_KEY_PERMS}" != "600" ]; then
  log warn "age key has insecure permissions: ${AGE_KEY_PERMS}"
  log info "Fixing permissions to 600"
  chmod 600 "${AGE_KEY_FILE}"
fi

# Create runtime directory (tmpfs)
if [ ! -d "${RUNTIME_DIR}" ]; then
  log info "Creating runtime directory: ${RUNTIME_DIR}"
  mkdir -p "${RUNTIME_DIR}"
fi
chmod 700 "${RUNTIME_DIR}"

# Determine encrypted secrets file path
# Try environment-specific files first, fall back to generic
ENCRYPTED_FILES=(
  "${SECRETS_DIR}/${SERVICE_NAME}-production.env.enc"
  "${SECRETS_DIR}/${SERVICE_NAME}-staging.env.enc"
  "${SECRETS_DIR}/${SERVICE_NAME}-dev.env.enc"
  "${SECRETS_DIR}/${SERVICE_NAME}.env.enc"
)

ENCRYPTED_SECRETS=""
for file in "${ENCRYPTED_FILES[@]}"; do
  if [ -f "${file}" ]; then
    ENCRYPTED_SECRETS="${file}"
    log info "Found encrypted secrets: ${file}"
    break
  fi
done

if [ -z "${ENCRYPTED_SECRETS}" ]; then
  log warn "No encrypted secrets found for ${SERVICE_NAME}"
  log warn "Searched: ${ENCRYPTED_FILES[*]}"
  log warn "Service will start without secrets from SOPS"

  # Create empty secrets file to prevent service startup failure
  touch "${DECRYPTED_OUTPUT}"
  chmod 600 "${DECRYPTED_OUTPUT}"
  chown eracun:eracun "${DECRYPTED_OUTPUT}"

  exit 0
fi

# Decrypt secrets using age key
log info "Decrypting: ${ENCRYPTED_SECRETS} -> ${DECRYPTED_OUTPUT}"

if sops --decrypt --age "$(cat ${AGE_KEY_FILE})" "${ENCRYPTED_SECRETS}" > "${DECRYPTED_OUTPUT}" 2>&1; then
  log info "Successfully decrypted secrets"
else
  log err "Failed to decrypt secrets"
  log err "Check that .sops.yaml includes this droplet's age public key"
  rm -f "${DECRYPTED_OUTPUT}"
  exit 1
fi

# Set secure permissions
chmod 600 "${DECRYPTED_OUTPUT}"

# Change ownership to eracun service user
if id "eracun" &>/dev/null; then
  chown eracun:eracun "${DECRYPTED_OUTPUT}"
else
  log warn "eracun user does not exist, skipping chown"
fi

# Log decryption success with file size (but not contents)
FILE_SIZE=$(stat -c%s "${DECRYPTED_OUTPUT}")
log info "Decrypted secrets ready: ${DECRYPTED_OUTPUT} (${FILE_SIZE} bytes)"

# Security audit: log decryption event
log notice "Secrets decrypted for ${SERVICE_NAME} by $(whoami) at $(date -Iseconds)"

exit 0
