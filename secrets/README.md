# Secrets Management

This directory contains **SOPS-encrypted secrets** that are safe to commit to git.

**Tools Used:**
- **SOPS:** https://github.com/mozilla/sops (Mozilla secrets encryption tool)
- **age:** https://age-encryption.org/ (Modern file encryption)

---

## Developer Setup (One-Time)

### 1. Install Tools

**macOS:**
```bash
brew install sops age
```

**Linux:**
```bash
# age
sudo apt-get install age  # Debian/Ubuntu
# or
sudo dnf install age      # Fedora/RHEL

# SOPS
wget https://github.com/mozilla/sops/releases/download/v3.8.1/sops_3.8.1_amd64.deb
sudo dpkg -i sops_3.8.1_amd64.deb
```

### 2. Generate Personal age Key

```bash
# Generate key (save to ~/.age-key)
age-keygen -o ~/.age-key

# Get your public key
age-keygen -y ~/.age-key
```

**Output:**
```
Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

### 3. Share Public Key with Team Lead

**Send your public key** (age1...) to team lead via secure channel (Signal, encrypted email).

Team lead will add your public key to `.sops.yaml` and you'll be able to decrypt secrets.

---

## Working with Secrets

### Decrypt Secrets (for Local Development)

```bash
# Decrypt single file
sops --decrypt secrets/database-dev.env.enc > .env

# Decrypt all dev secrets
sops --decrypt secrets/database-dev.env.enc > .env.database
sops --decrypt secrets/api-keys-dev.env.enc > .env.api-keys

# IMPORTANT: Never commit .env files (they're in .gitignore)
```

### Encrypt Secrets (Adding New Secrets)

```bash
# Create plaintext secret file (DO NOT COMMIT THIS)
cat > /tmp/new-secret.env <<EOF
API_KEY=secret_value_here
API_SECRET=another_secret
EOF

# Encrypt with SOPS
sops --encrypt /tmp/new-secret.env > secrets/new-secret-dev.env.enc

# Delete plaintext file
rm /tmp/new-secret.env

# Commit encrypted file
git add secrets/new-secret-dev.env.enc
git commit -m "feat(secrets): add new API credentials"
```

### Edit Existing Secrets

```bash
# SOPS will decrypt, open editor, then re-encrypt on save
sops secrets/database-dev.env.enc

# Your $EDITOR opens with plaintext
# Make changes, save, quit
# SOPS automatically re-encrypts
```

### Rotate Secrets

```bash
# Edit secret file
sops secrets/database-production.env.enc

# Change password/key
# Save and commit
git add secrets/database-production.env.enc
git commit -m "chore(secrets): rotate database password"

# Deploy new secrets (see deployment/README.md)
```

---

## File Naming Convention

```
secrets/
├── {service}-{environment}.env.enc
├── database-dev.env.enc           # Development database credentials
├── database-staging.env.enc       # Staging database credentials
├── database-production.env.enc    # Production database credentials
├── fina-cert-staging.p12.enc      # Staging FINA certificate (binary)
├── fina-cert-production.p12.enc   # Production FINA certificate
└── api-keys-production.env.enc    # External API keys
```

**Environment suffixes:**
- `-dev` - Local development
- `-staging` - Staging droplet (cistest.apis-it.hr)
- `-production` - Production droplet (cis.porezna-uprava.hr)

---

## Security Best Practices

### ✅ DO:

- ✅ Encrypt secrets before committing to git
- ✅ Use personal age key for development
- ✅ Keep age private key secure (`~/.age-key` mode 600)
- ✅ Backup age private key (encrypted USB drive + password manager)
- ✅ Use different secrets for dev/staging/production
- ✅ Rotate secrets quarterly (or immediately if compromised)

### ❌ DON'T:

- ❌ Commit plaintext secrets to git (`.env`, `.key`, `.p12`)
- ❌ Share age private key via email/Slack
- ❌ Use production secrets in development
- ❌ Store age private key in cloud storage (Dropbox, Google Drive)
- ❌ Reuse secrets across environments

---

## Troubleshooting

### "Failed to get the data key"

**Cause:** Your age public key not in `.sops.yaml`

**Solution:**
1. Get your public key: `age-keygen -y ~/.age-key`
2. Ask team lead to add your key to `.sops.yaml`
3. Wait for PR merge
4. Pull latest changes: `git pull`

### "No age master key defined"

**Cause:** `.sops.yaml` not configured properly

**Solution:**
- Ensure `.sops.yaml` has valid age public keys
- Check file path matches pattern in `.sops.yaml`

### "mac verification failed: authentication tag mismatch"

**Cause:** File corrupted or wrong decryption key

**Solution:**
- Restore file from git: `git checkout secrets/filename.enc`
- Ensure using correct age key for environment

---

## Emergency: Key Compromise

**If age private key is compromised:**

1. **Generate new key:**
   ```bash
   age-keygen -o ~/.age-key-new
   age-keygen -y ~/.age-key-new  # Get new public key
   ```

2. **Notify team lead immediately**

3. **Team lead updates `.sops.yaml`** with new public key, removes old

4. **Re-encrypt all secrets:**
   ```bash
   # Team lead runs
   sops rotate --age <new_public_key> secrets/*.enc
   ```

5. **Revoke old key access** (remove from `.sops.yaml`)

---

## Production Deployment

**Production age keys are stored on droplet ONLY.**

Location: `/etc/eracun/.age-key` (mode 600, root:root)

**DO NOT:**
- Copy production age key to your laptop
- Share production age key with developers
- Commit production age key to git

**Deployment:**
- Encrypted secrets copied from git to droplet
- systemd `ExecStartPre` decrypts using `/etc/eracun/.age-key`
- Services read from `/run/eracun/secrets.env` (tmpfs)

See `docs/operations/deployment.md` for full process.

---

## References

- **ADR-002:** Secrets Management with SOPS + age
- **SOPS Documentation:** https://github.com/mozilla/sops
- **age Documentation:** https://age-encryption.org/
- **systemd Integration:** See `deployment/systemd/` directory

---

**Questions?** Ask in #eracun-dev Slack channel or open GitHub issue.
