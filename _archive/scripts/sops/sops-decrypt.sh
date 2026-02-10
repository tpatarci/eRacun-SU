#!/bin/bash
# SOPS Decryption Script for systemd Services
# Decrypts service-specific secrets before service starts

set -e

SERVICE_NAME=$1

if [ -z "$SERVICE_NAME" ]; then
    echo "Usage: sops-decrypt.sh <service-name>"
    exit 1
fi

# Configuration
AGE_KEY_FILE="/etc/eracun/.age-key"
SECRETS_DIR="/etc/eracun/secrets"
RUNTIME_DIR="/run/eracun"

# Ensure runtime directory exists
mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"

# Export age key location
export SOPS_AGE_KEY_FILE="$AGE_KEY_FILE"

# Decrypt environment file if it exists
ENV_FILE="$SECRETS_DIR/envs/${SERVICE_NAME}.enc.env"
if [ -f "$ENV_FILE" ]; then
    echo "Decrypting environment file for $SERVICE_NAME..."
    sops --decrypt "$ENV_FILE" > "$RUNTIME_DIR/${SERVICE_NAME}.env"
    chmod 600 "$RUNTIME_DIR/${SERVICE_NAME}.env"
    echo "✓ Environment file decrypted to $RUNTIME_DIR/${SERVICE_NAME}.env"
fi

# Decrypt certificate password if it exists
CERT_PASSWORD_FILE="$SECRETS_DIR/certs/${SERVICE_NAME}.password.enc.txt"
if [ -f "$CERT_PASSWORD_FILE" ]; then
    echo "Decrypting certificate password for $SERVICE_NAME..."
    sops --decrypt "$CERT_PASSWORD_FILE" > "$RUNTIME_DIR/${SERVICE_NAME}.cert.password"
    chmod 600 "$RUNTIME_DIR/${SERVICE_NAME}.cert.password"
    echo "✓ Certificate password decrypted to $RUNTIME_DIR/${SERVICE_NAME}.cert.password"
fi

# Decrypt service-specific secrets (YAML) if they exist
YAML_FILE="$SECRETS_DIR/${SERVICE_NAME}.enc.yaml"
if [ -f "$YAML_FILE" ]; then
    echo "Decrypting secrets for $SERVICE_NAME..."
    sops --decrypt "$YAML_FILE" > "$RUNTIME_DIR/${SERVICE_NAME}.yaml"
    chmod 600 "$RUNTIME_DIR/${SERVICE_NAME}.yaml"
    echo "✓ Secrets decrypted to $RUNTIME_DIR/${SERVICE_NAME}.yaml"
fi

echo "✓ Decryption complete for $SERVICE_NAME"
