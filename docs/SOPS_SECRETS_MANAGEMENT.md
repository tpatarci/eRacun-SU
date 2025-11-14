# SOPS Secrets Management

Secure secrets management using SOPS (Secrets OPerationS) with age encryption.

## Overview

**SOPS** encrypts secrets at rest using **age** (modern encryption tool). Encrypted files are safe to commit to git, while the encryption key is stored securely on production servers.

### Benefits
- ✅ Secrets encrypted at rest
- ✅ Safe to commit encrypted files to git
- ✅ Simple age encryption (no GPG complexity)
- ✅ €0 cost (open source)
- ✅ systemd integration for automatic decryption

### Architecture
```
┌─────────────────┐
│ Developer       │
│ Encrypts secret │
└────────┬────────┘
         │ age public key
         ▼
┌─────────────────┐
│ Git Repository  │
│ .enc.env files  │  ← Safe to commit
└────────┬────────┘
         │ Pull
         ▼
┌─────────────────┐
│ Production      │
│ Decrypt on boot │  ← age private key
└─────────────────┘
```

## Installation

### Quick Setup
```bash
./scripts/sops/setup-sops.sh
```

### Manual Setup
```bash
# 1. Install age
brew install age  # macOS
sudo apt install age  # Ubuntu

# 2. Install SOPS
brew install sops  # macOS
# Ubuntu: https://github.com/mozilla/sops/releases

# 3. Generate age key
age-keygen | sudo tee /etc/eracun/.age-key > /dev/null
sudo chmod 400 /etc/eracun/.age-key

# 4. Extract public key
sudo grep "# public key:" /etc/eracun/.age-key

# 5. Update .sopsrc with public key
# (done automatically by setup script)
```

## Usage

### Encrypt a New Secret

```bash
# 1. Create unencrypted file
cat > secrets/envs/production.env <<EOF
DATABASE_PASSWORD=super-secret-password
API_KEY=api-key-12345
FINA_CERT_PASSWORD=cert-password-xyz
