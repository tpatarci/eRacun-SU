#!/bin/bash
#
# SOPS Secret Decryption Script
# Decrypts service-specific secrets from /etc/eracun/secrets/ to /run/eracun/
#
# Usage: sops-decrypt.sh <service-name>
# Example: sops-decrypt.sh invoice-gateway-api
#
# Requirements:
#   - SOPS installed (/usr/local/bin/sops)
#   - age key at /etc/eracun/.age-key (restricted to eracun user)
#   - Encrypted secrets at /etc/eracun/secrets/<service>.enc.yaml
#
# Output:
#   - Decrypted secrets written to /run/eracun/<service>.env (tmpfs, cleared on reboot)
#

set -euo pipefail

SERVICE_NAME="${1:-}"

if [[ -z "$SERVICE_NAME" ]]; then
  echo "Error: Service name required" >&2
  echo "Usage: $0 <service-name>" >&2
  exit 1
fi

# Paths
AGE_KEY="/etc/eracun/.age-key"
ENCRYPTED_FILE="/etc/eracun/secrets/${SERVICE_NAME}.enc.yaml"
DECRYPTED_FILE="/run/eracun/${SERVICE_NAME}.env"
SOPS_BIN="/usr/local/bin/sops"

# Validate prerequisites
if [[ ! -f "$SOPS_BIN" ]]; then
  echo "Error: SOPS not installed at $SOPS_BIN" >&2
  exit 1
fi

if [[ ! -f "$AGE_KEY" ]]; then
  echo "Error: age key not found at $AGE_KEY" >&2
  exit 1
fi

if [[ ! -f "$ENCRYPTED_FILE" ]]; then
  echo "Warning: No encrypted secrets found at $ENCRYPTED_FILE" >&2
  echo "Service will start without decrypted secrets" >&2
  exit 0
fi

# Ensure /run/eracun/ exists (tmpfs)
mkdir -p /run/eracun
chmod 700 /run/eracun
chown eracun:eracun /run/eracun

# Decrypt secrets
echo "Decrypting secrets for $SERVICE_NAME..."
export SOPS_AGE_KEY_FILE="$AGE_KEY"

"$SOPS_BIN" -d "$ENCRYPTED_FILE" > "$DECRYPTED_FILE"

# Secure permissions (only eracun user can read)
chmod 600 "$DECRYPTED_FILE"
chown eracun:eracun "$DECRYPTED_FILE"

echo "Secrets decrypted successfully to $DECRYPTED_FILE"
