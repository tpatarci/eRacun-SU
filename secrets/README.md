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

## Quick Start

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

- **Full Documentation:** @docs/SOPS_SECRETS_MANAGEMENT.md
- **Security Standards:** @docs/SECURITY.md
- **Deployment Guide:** @docs/DEPLOYMENT_GUIDE.md
- **ADR-002:** @docs/adr/ADR-002-secrets-management.md
