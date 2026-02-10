# ADR-002: Secrets Management with SOPS + age

**Status:** ✅ Accepted

**Date:** 2025-11-09

**Decision Makers:** Technical Lead, System Architect, Security Lead

**Related:** PENDING-001, ADR-001 (Configuration Management)

---

## Context

The eRacun platform handles sensitive cryptographic material and credentials that must be protected:

**Secret Types:**

1. **FINA Certificates (.p12 files)**
   - Private keys for digital signatures (B2B invoices)
   - ZKI security code generation (B2C fiscalization)
   - Cost: ~€40 per 5-year certificate
   - **Critical:** Private key compromise = forged invoices = legal liability

2. **Database Credentials**
   - PostgreSQL passwords
   - Connection strings
   - Read/write access tokens

3. **API Keys**
   - External service integrations
   - Monitoring services
   - Email providers

4. **Encryption Keys**
   - AES-256 keys for data-at-rest encryption
   - JWT signing keys

**Security Requirements:**

- **Confidentiality:** Secrets must not be committed to git in plaintext
- **Integrity:** Prevent unauthorized modification
- **Availability:** Secrets must be accessible to services at runtime
- **Audit Trail:** Track who accesses/modifies secrets
- **Rotation:** Support periodic key rotation
- **Compliance:** Meet Croatian data protection regulations

**Deployment Context:**

- **Platform:** DigitalOcean dedicated droplet (Linux)
- **Orchestration:** systemd (not Kubernetes)
- **Team Size:** Small (2-5 developers initially)
- **Budget:** Open source / free solutions preferred
- **Operational Complexity:** Minimize (no external services to maintain)

**Challenges:**

1. **Git Storage:** How to safely store secrets in version control?
2. **Decryption:** How do services decrypt secrets at runtime?
3. **Key Management:** How to securely manage encryption keys?
4. **Developer Access:** How do developers work with secrets locally?
5. **Rotation:** How to update secrets without downtime?

---

## Decision

**We will use SOPS (Secrets OPerationS) with age encryption for secrets management.**

### Architecture Overview

```
Developer → Encrypts secrets with age → SOPS-encrypted file (*.enc) → Git
                                              ↓
                                   Production Droplet
                                              ↓
                          systemd ExecStartPre (decrypt-secrets.sh)
                                              ↓
                          Decrypted secrets → /run/eracun/secrets.env (tmpfs)
                                              ↓
                          Service reads from tmpfs at startup
```

### Tool Selection

**SOPS (Secrets OPerationS)**
- **Source:** https://github.com/mozilla/sops
- **Maintainer:** Mozilla (open source)
- **License:** MPL 2.0 (free)
- **Purpose:** Encrypt files (YAML, JSON, ENV, binary) for git storage

**age (Actually Good Encryption)**
- **Source:** https://age-encryption.org/
- **Author:** Filippo Valsorda (Google cryptographer)
- **License:** BSD 3-Clause (free)
- **Purpose:** Modern file encryption (simpler than GPG)

### How It Works

**1. Encryption (One-Time Setup)**

```bash
# Generate age key pair
age-keygen -o /etc/eracun/.age-key
# Output: age-secret-key-1abc... (saved to file)
#         Public key: age1xyz...

# Extract public key
age-keygen -y /etc/eracun/.age-key
# Output: age1xyz...

# Configure SOPS to use age key
cat > secrets/.sops.yaml <<EOF
creation_rules:
  - age: age1xyz...  # Public key from above
EOF

# Encrypt secrets file
sops --encrypt secrets/database.env > secrets/database.env.enc

# Commit encrypted file to git
git add secrets/database.env.enc secrets/.sops.yaml
git commit -m "feat(secrets): add encrypted database credentials"
```

**2. Decryption (Service Startup)**

```bash
# systemd ExecStartPre runs this script
#!/bin/bash
# /usr/local/bin/decrypt-secrets.sh

SERVICE_NAME="$1"
AGE_KEY_FILE="/etc/eracun/.age-key"
ENCRYPTED_SECRETS="/etc/eracun/secrets/${SERVICE_NAME}.env.enc"
DECRYPTED_OUTPUT="/run/eracun/secrets.env"

# Create runtime directory (tmpfs - cleared on reboot)
mkdir -p /run/eracun
chmod 700 /run/eracun

# Decrypt using age private key
if [ -f "$ENCRYPTED_SECRETS" ]; then
  sops --decrypt --age "$(cat $AGE_KEY_FILE)" "$ENCRYPTED_SECRETS" > "$DECRYPTED_OUTPUT"
  chmod 600 "$DECRYPTED_OUTPUT"
  chown eracun:eracun "$DECRYPTED_OUTPUT"
fi
```

**3. Service Reads Decrypted Secrets**

```typescript
// Service startup code
import dotenv from 'dotenv';

const secrets = dotenv.parse(
  fs.readFileSync('/run/eracun/secrets.env', 'utf8')
);

const config = {
  database: {
    password: secrets.DB_PASSWORD,
    host: secrets.DB_HOST,
  },
  fina: {
    certPath: '/etc/eracun/secrets/fina-cert.p12',
    certPassword: secrets.FINA_CERT_PASSWORD,
  },
};
```

### Directory Structure

**In Git (eRacun-development/):**

```
secrets/
├── .sops.yaml                    # SOPS configuration (public keys)
├── database.env.enc              # Encrypted DB credentials (IN GIT)
├── fina-cert.p12.enc             # Encrypted FINA certificate (IN GIT)
├── api-keys.env.enc              # Encrypted API keys (IN GIT)
├── database.env.example          # Template (shows structure, no values)
└── README.md                     # Instructions for developers
```

**On Droplet (/etc/eracun/):**

```
/etc/eracun/
├── .age-key                      # Age private key (mode 600, root:root)
└── secrets/                      # Decrypted secrets (mode 700, eracun:eracun)
    ├── fina-cert.p12             # Decrypted FINA certificate
    ├── database.env              # Plaintext DB credentials
    └── api-keys.env

/run/eracun/                      # tmpfs (cleared on reboot)
└── secrets.env                   # Decrypted secrets for running service (600)
```

### Systemd Integration

**Service Unit File:**

```ini
[Unit]
Description=eRacun Email Ingestion Worker
After=network.target

[Service]
Type=simple
User=eracun
Group=eracun

# Decrypt secrets before starting service
ExecStartPre=/usr/local/bin/decrypt-secrets.sh email-worker

# Load decrypted secrets
EnvironmentFile=/run/eracun/secrets.env

# Start service
ExecStart=/usr/local/bin/node dist/index.js

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

# Prevent access to secrets on disk
InaccessiblePaths=/etc/eracun/.age-key
ReadOnlyPaths=/etc/eracun/secrets

[Install]
WantedBy=multi-user.target
```

### Secret Types Handling

**Environment Variables (.env format):**

```bash
# secrets/database.env.enc (encrypted in git)
DB_HOST=db.eracun.internal
DB_PORT=5432
DB_NAME=eracun_production
DB_USER=eracun
DB_PASSWORD=<redacted>
```

**Binary Files (FINA certificates):**

```bash
# Encrypt binary file
sops --encrypt --age <public_key> --input-type binary \
  fina-cert.p12 > fina-cert.p12.enc

# Decrypt (done by systemd ExecStartPre)
sops --decrypt --age "$(cat .age-key)" --input-type binary \
  fina-cert.p12.enc > /etc/eracun/secrets/fina-cert.p12
```

### Key Management

**age Key Pair:**

- **Private Key:** `/etc/eracun/.age-key` (mode 600, root:root)
  - Never committed to git
  - Backed up securely (encrypted USB drive + password manager)

- **Public Key:** In `secrets/.sops.yaml` (committed to git)
  - Used for encryption only
  - Safe to share publicly

**Key Rotation:**

```bash
# Generate new age key
age-keygen -o /etc/eracun/.age-key-new

# Update .sops.yaml with new public key
sops updatekeys secrets/database.env.enc

# Replace old key
mv /etc/eracun/.age-key /etc/eracun/.age-key-old
mv /etc/eracun/.age-key-new /etc/eracun/.age-key

# Re-encrypt all secrets with new key
for file in secrets/*.enc; do
  sops rotate --age "$(age-keygen -y /etc/eracun/.age-key)" "$file"
done
```

### Developer Workflow

**Setup (One-Time):**

```bash
# Developer generates personal age key
age-keygen -o ~/.age-key

# Developer shares public key with team
age-keygen -y ~/.age-key
# Output: age1developer123...

# Team lead adds developer's public key to .sops.yaml
# secrets/.sops.yaml
creation_rules:
  - age: >-
      age1production...,
      age1developer123...,
      age1anotherdeveloper...
```

**Daily Use:**

```bash
# Decrypt secrets for local development
sops --decrypt --age ~/.age-key secrets/database.env.enc > .env

# Make changes
vim secrets/database.env

# Re-encrypt
sops --encrypt --age $(cat secrets/.sops.yaml | yq .creation_rules[0].age) \
  secrets/database.env > secrets/database.env.enc

# Commit
git add secrets/database.env.enc
git commit -m "chore(secrets): rotate database password"
```

### Security Measures

**1. File Permissions**

```bash
# Production droplet
/etc/eracun/.age-key         → 600 (root:root)
/etc/eracun/secrets/         → 700 (eracun:eracun)
/etc/eracun/secrets/*.env    → 600 (eracun:eracun)
/run/eracun/secrets.env      → 600 (eracun:eracun)
```

**2. tmpfs for Decrypted Secrets**

- `/run/eracun/` is tmpfs (RAM filesystem)
- Cleared on every reboot
- Never written to disk
- Reduces forensic exposure

**3. Systemd Hardening**

```ini
# Prevent service from accessing age private key
InaccessiblePaths=/etc/eracun/.age-key

# Secrets directory read-only after decryption
ReadOnlyPaths=/etc/eracun/secrets

# Restrict system access
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
```

**4. Git Protection**

```gitignore
# .gitignore
*.p12
*.pfx
*.key
*.pem
.env
.env.local
secrets.yaml
**/secrets/*.env
!**/secrets/*.enc
```

**5. Pre-Commit Hook**

```bash
#!/bin/bash
# .git/hooks/pre-commit
if git diff --cached | grep -E '(password|secret|api[_-]?key|private[_-]?key).*=' | grep -v '.enc$'; then
  echo "❌ ERROR: Potential plaintext secret detected in commit"
  exit 1
fi
```

---

## Consequences

### Positive

✅ **Git-Friendly**
- Encrypted secrets safely stored in git
- Full audit trail of secret changes
- Diff/merge works on encrypted files

✅ **Simple Operation**
- No external service to maintain (unlike Vault)
- Single binary (SOPS + age)
- Stateless (no database, no server)

✅ **Cost: €0**
- Both tools open source and free
- No licensing fees
- No infrastructure costs

✅ **Modern Cryptography**
- age uses X25519 + ChaCha20-Poly1305
- Better than GPG (simpler, fewer footguns)
- Designed by reputable cryptographer

✅ **Developer Friendly**
- Developers can decrypt with personal age key
- No sharing of production keys
- Clear error messages

✅ **Multi-Environment Support**
- Different age keys for dev/staging/production
- `.sops.yaml` supports per-file key rules
- Easy to add/remove developer access

✅ **Systemd Integration**
- `ExecStartPre` decrypts before service starts
- Failures prevent service startup (fail-safe)
- tmpfs automatically cleared on reboot

### Negative

⚠️ **Key Management Burden**
- age private key is single point of failure
- Must be backed up securely
- **Mitigation:** Encrypted USB backup + password manager + team lead access

⚠️ **No Automatic Rotation**
- Secrets rotation is manual process
- No dynamic secret generation
- **Mitigation:** Document rotation procedures, schedule quarterly reviews

⚠️ **No Audit Logs**
- SOPS doesn't track who decrypted what
- Git shows who encrypted changes
- **Mitigation:** systemd journal logs `ExecStartPre` executions

⚠️ **Decryption Performance**
- ~50-100ms per file decrypt
- Adds to service startup time
- **Mitigation:** Acceptable for startup (not runtime), cache decrypted secrets in tmpfs

⚠️ **Key Compromise Impact**
- If age private key stolen, all secrets exposed
- No revocation mechanism (must re-encrypt everything)
- **Mitigation:** Strong file permissions (600), root-only access, regular rotation

### Neutral

↔️ **Not HSM-Backed**
- age keys are files, not in Hardware Security Module
- **Note:** Acceptable for initial deployment, can migrate FINA certs to HSM later if required

↔️ **Manual Secret Distribution**
- Developers must share public keys via secure channel
- No automated onboarding
- **Note:** Acceptable for small team, formalize process as team grows

---

## Alternatives Considered

### 1. HashiCorp Vault

**Pros:**
- Enterprise-grade, mature
- Dynamic secrets (auto-rotation)
- Audit logging built-in
- Role-based access control

**Cons:**
- Requires Vault server (maintenance overhead)
- HA setup complex (3+ node cluster)
- Operational burden too high for single droplet
- Cost/benefit ratio unfavorable

**Verdict:** Too complex for initial deployment. Consider if scaling to multi-server.

### 2. AWS Secrets Manager / Azure Key Vault

**Pros:**
- Managed service (no maintenance)
- Automatic rotation
- Fine-grained access control

**Cons:**
- Vendor lock-in
- Recurring costs
- DigitalOcean doesn't offer native equivalent
- Network dependency (API calls at runtime)

**Verdict:** Against project principles (open source, DigitalOcean, Unix-native).

### 3. GPG (GNU Privacy Guard)

**Pros:**
- Widely available
- Industry standard
- SOPS supports GPG backend

**Cons:**
- Complex key management (web of trust, keyservers)
- Large keyring files
- age is simpler, modern alternative

**Verdict:** age chosen over GPG (simpler, better UX).

### 4. pass (passwordstore.org)

**Pros:**
- GPG-backed password manager
- Git integration
- Unix philosophy

**Cons:**
- Designed for interactive use, not automation
- No good way to decrypt in systemd ExecStartPre
- Requires GPG (complexity)

**Verdict:** SOPS better suited for automation.

### 5. Ansible Vault

**Pros:**
- Integrated with Ansible (if using for deployment)
- Simple to use

**Cons:**
- Tied to Ansible (not standalone)
- Password-based (harder to automate)
- No per-user access control

**Verdict:** SOPS more flexible, not tied to Ansible.

### 6. git-crypt

**Pros:**
- Transparent encryption in git
- Uses GPG

**Cons:**
- Requires GPG (complexity)
- No age support
- Less flexible than SOPS

**Verdict:** SOPS chosen for age support and flexibility.

---

## Compliance & Security

**Croatian Data Protection:**
- Private keys (FINA certs) protected with age encryption (✅)
- Access control via file permissions (✅)
- Audit trail via git commits (✅)
- Backup procedures documented (✅)

**GDPR Considerations:**
- Secrets don't contain personal data (customer OIBs in DB, not in secrets)
- Access logs via systemd journal (✅)
- Right to erasure: re-encrypt without compromised developer's key (✅)

**Incident Response:**
- **Key Compromise:** Rotate age key, re-encrypt all secrets, deploy new key to droplet
- **Droplet Compromise:** Rotate all secrets (DB passwords, API keys, FINA certs)
- **Git Leak:** Secrets are encrypted, but rotate as precaution

---

## Implementation Checklist

- [x] Create `/docs/adr/002-secrets-management-sops-age.md` (this document)
- [ ] Create `secrets/` directory in repository
- [ ] Create `.sops.yaml` configuration
- [ ] Install SOPS and age on droplet
- [ ] Generate production age key pair
- [ ] Create `decrypt-secrets.sh` script
- [ ] Create `.gitignore` rules for secrets
- [ ] Create pre-commit hook for secret detection
- [ ] Document developer onboarding (share public key)
- [ ] Create operational runbook for key rotation
- [ ] Document in `docs/operations/secrets-management.md`

---

## References

- **PENDING-001:** Configuration & Secrets Management Strategy
- **ADR-001:** Configuration Management Strategy
- **SOPS:** https://github.com/mozilla/sops
- **age:** https://age-encryption.org/
- **age Specification:** https://github.com/C2SP/C2SP/blob/main/age.md
- **systemd ExecStartPre:** https://www.freedesktop.org/software/systemd/man/systemd.service.html#ExecStartPre=
- **Filesystem Hierarchy Standard:** https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html

---

**Approved By:** System Architect, Security Lead
**Implementation Status:** In Progress
**Next Review:** After first production deployment
