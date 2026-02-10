#!/bin/bash
# SOPS + age Setup Script
# Initialize secrets management for eRacun project

set -e

echo "=============================="
echo "SOPS + age Setup"
echo "=============================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if age is installed
if ! command -v age &> /dev/null; then
    echo -e "${RED}❌ age is not installed${NC}"
    echo ""
    echo "Install age:"
    echo "  macOS:   brew install age"
    echo "  Ubuntu:  sudo apt install age"
    echo "  Manual:  https://github.com/FiloSottile/age/releases"
    exit 1
fi

echo -e "${GREEN}✓ age found${NC}"

# Check if sops is installed
if ! command -v sops &> /dev/null; then
    echo -e "${RED}❌ SOPS is not installed${NC}"
    echo ""
    echo "Install SOPS:"
    echo "  macOS:   brew install sops"
    echo "  Ubuntu:  Download from https://github.com/mozilla/sops/releases"
    echo "  Manual:  https://github.com/mozilla/sops/releases"
    exit 1
fi

echo -e "${GREEN}✓ SOPS found${NC}"

# Check if age key already exists
AGE_KEY_FILE="/etc/eracun/.age-key"
AGE_PUBLIC_KEY=""

if [ -f "$AGE_KEY_FILE" ]; then
    echo ""
    echo -e "${YELLOW}⚠️  Age key already exists at $AGE_KEY_FILE${NC}"
    read -p "Regenerate key? This will require re-encrypting all secrets! (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing key..."
        AGE_PUBLIC_KEY=$(grep "# public key:" "$AGE_KEY_FILE" | awk '{print $4}')
    else
        echo "Backing up existing key..."
        sudo cp "$AGE_KEY_FILE" "$AGE_KEY_FILE.backup.$(date +%Y%m%d%H%M%S)"
        sudo rm "$AGE_KEY_FILE"
    fi
fi

# Generate new age key if needed
if [ ! -f "$AGE_KEY_FILE" ]; then
    echo ""
    echo "Generating new age key..."
    
    # Create directory
    sudo mkdir -p /etc/eracun
    
    # Generate key
    age-keygen | sudo tee "$AGE_KEY_FILE" > /dev/null
    
    # Set restrictive permissions
    sudo chmod 400 "$AGE_KEY_FILE"
    sudo chown root:root "$AGE_KEY_FILE"
    
    # Extract public key
    AGE_PUBLIC_KEY=$(sudo grep "# public key:" "$AGE_KEY_FILE" | awk '{print $4}')
    
    echo -e "${GREEN}✓ Age key generated${NC}"
fi

# Display public key
if [ -z "$AGE_PUBLIC_KEY" ]; then
    AGE_PUBLIC_KEY=$(sudo grep "# public key:" "$AGE_KEY_FILE" | awk '{print $4}')
fi

echo ""
echo "=============================="
echo "Age Public Key:"
echo -e "${GREEN}$AGE_PUBLIC_KEY${NC}"
echo "=============================="

# Update .sopsrc with public key
echo ""
echo "Updating .sopsrc configuration..."

cat > .sopsrc <<SOPSRC_EOF
# SOPS Configuration for eRacun Project
# Uses age encryption for secrets management

creation_rules:
  # Environment files for all services
  - path_regex: secrets/.*\.env$
    age: >-
      $AGE_PUBLIC_KEY

  # YAML secrets
  - path_regex: secrets/.*\.ya?ml$
    age: >-
      $AGE_PUBLIC_KEY

  # Certificate passwords
  - path_regex: secrets/certs/.*\.txt$
    age: >-
      $AGE_PUBLIC_KEY

  # Default rule (fallback)
  - age: >-
      $AGE_PUBLIC_KEY
SOPSRC_EOF

echo -e "${GREEN}✓ .sopsrc updated${NC}"

# Create secrets directories
echo ""
echo "Creating secrets directories..."
mkdir -p secrets/envs
mkdir -p secrets/certs
mkdir -p secrets/.sops

# Create .gitignore
cat > secrets/.gitignore <<'GITIGNORE_EOF'
# Encrypted secrets are safe to commit
# Decrypted secrets must never be committed

# Allow encrypted files
!*.enc.env
!*.enc.yaml
!*.enc.yml

# Block decrypted files
*.dec.env
*.dec.yaml
*.dec.yml
*.env
*.txt
*.p12
*.key
*.pem

# Allow .gitignore and README
!.gitignore
!README.md
GITIGNORE_EOF

echo -e "${GREEN}✓ Secrets directories created${NC}"

# Create example secrets file
echo ""
echo "Creating example encrypted secret..."

cat > /tmp/example.env <<'EXAMPLE_EOF'
# Example secrets file
DATABASE_PASSWORD=super-secret-password
API_KEY=api-key-12345
CERT_PASSWORD=cert-password-xyz
EXAMPLE_EOF

sops --encrypt /tmp/example.env > secrets/envs/example.enc.env
rm /tmp/example.env

echo -e "${GREEN}✓ Example secret created: secrets/envs/example.enc.env${NC}"

# Create README
cat > secrets/README.md <<'README_EOF'
# Secrets Management with SOPS + age

This directory contains encrypted secrets for the eRacun platform.

## Directory Structure

```
secrets/
├── envs/              # Encrypted environment files (.enc.env)
├── certs/             # Encrypted certificate files
├── .sops/             # SOPS metadata (auto-generated)
└── README.md          # This file
```

## Usage

### Encrypt a New Secret

```bash
# Encrypt file
sops --encrypt secrets/envs/production.env > secrets/envs/production.enc.env

# Delete unencrypted file
rm secrets/envs/production.env
```

### Edit Encrypted Secret

```bash
# Edit in place (decrypts to editor, re-encrypts on save)
sops secrets/envs/production.enc.env
```

### Decrypt Secret

```bash
# Decrypt to stdout
sops --decrypt secrets/envs/production.enc.env

# Decrypt to file
sops --decrypt secrets/envs/production.enc.env > /tmp/production.env
```

### Use in systemd Service

```bash
# Decrypt before service starts (ExecStartPre)
/usr/local/bin/sops-decrypt.sh production
```

## Security

- **Encrypted files (.enc.*):** Safe to commit to git
- **Decrypted files (*.env, *.p12, etc.):** NEVER commit to git
- **Age private key:** Stored in `/etc/eracun/.age-key` with 400 permissions
- **Age public key:** Embedded in `.sopsrc` configuration

## Troubleshooting

**Permission denied when decrypting:**
```bash
# Check age key permissions
ls -l /etc/eracun/.age-key

# Should be 400 (read-only for root)
sudo chmod 400 /etc/eracun/.age-key
```

**SOPS can't find age key:**
```bash
# Set environment variable
export SOPS_AGE_KEY_FILE=/etc/eracun/.age-key

# Or add to shell profile
echo 'export SOPS_AGE_KEY_FILE=/etc/eracun/.age-key' >> ~/.bashrc
```

## Related Documentation

- **Security Standards:** @docs/SECURITY.md
- **Deployment Guide:** @docs/DEPLOYMENT_GUIDE.md
- **ADR-002:** @docs/adr/ADR-002-secrets-management.md
README_EOF

echo -e "${GREEN}✓ README created${NC}"

echo ""
echo "=============================="
echo -e "${GREEN}✅ SOPS Setup Complete!${NC}"
echo "=============================="
echo ""
echo "Next steps:"
echo "1. Encrypt your secrets:"
echo "   sops --encrypt myfile.env > secrets/envs/myfile.enc.env"
echo ""
echo "2. Edit encrypted secrets:"
echo "   sops secrets/envs/myfile.enc.env"
echo ""
echo "3. Decrypt for deployment:"
echo "   sops --decrypt secrets/envs/myfile.enc.env > /run/eracun/myfile.env"
echo ""
echo "4. IMPORTANT: Add decrypted files to .gitignore"
echo ""
echo "Age public key (share with team):"
echo -e "${GREEN}$AGE_PUBLIC_KEY${NC}"
echo ""
