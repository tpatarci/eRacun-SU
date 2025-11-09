# PENDING-001: Configuration & Secrets Management Strategy

**Status:** 🔴 CRITICAL - Must address before any service implementation
**Priority:** P0 (Blocking)
**Created:** 2025-11-09
**Updated:** 2025-11-09 (deployment context added)
**Identified By:** Architecture review
**Blocks:** All service development (services need config to run)

---

## Deployment Context (UPDATED)

**Target Environment:** DigitalOcean dedicated droplet (Linux)
**Philosophy:** Classic Unix conventions (filesystem, systemd, POSIX standards)
**Preferences:** Open source, free or affordable solutions

**Implications:**
- **Not Kubernetes initially** - Use systemd for service orchestration
- **Single server deployment** - No container orchestration overhead
- **Unix-native tools** - /etc/ for configs, file permissions for security, systemd credentials
- **Simplicity preferred** - Avoid complex external dependencies (Vault overkill for single droplet)

---

## Problem Statement

**Current Gap:** No defined strategy for:
1. Configuration placement (global vs service-local)
2. Secrets protection (FINA certificates, DB passwords, API keys)
3. Environment separation (dev/staging/production)
4. Configuration discovery by services at runtime
5. Preventing secrets from being committed to Git

**Risk if Not Addressed:**
- 🔴 **Security:** Secrets committed to Git (FINA private keys exposed)
- 🔴 **Compliance:** Private keys not protected per Croatian regulations
- 🟡 **Operations:** No way to deploy services without hardcoded credentials
- 🟡 **Developer Experience:** Confusion about where configs belong

---

## Recommended Solution (Unix/Droplet Optimized)

### Configuration Strategy

**Filesystem-based with Unix permissions:**

```
/etc/eracun/
├── platform.conf              # Global settings (YAML, world-readable 644)
├── services/
│   ├── email-worker.conf      # Service configs (644)
│   ├── xsd-validator.conf
│   └── signature-service.conf
├── environment.conf           # Environment override (staging/production, 644)
└── secrets/                   # Restricted directory (700, root:eracun)
    ├── fina-cert.p12          # FINA certificate (600, eracun:eracun)
    ├── fina-cert.pass         # Certificate password (600)
    ├── database.env           # DB credentials (600)
    └── api-keys.env           # External API keys (600)
```

**Security model:**
- Public configs: `/etc/eracun/*.conf` (mode 644, readable by all services)
- Secrets: `/etc/eracun/secrets/*` (mode 600, owned by `eracun` service user)
- Systemd services run as `eracun` user (not root)
- File permissions enforced by systemd `ProtectSystem=strict`

### Secrets Management Tool

**RECOMMENDED: SOPS (Secrets OPerationS) + age encryption**

**Why:**
- ✅ **Open source** (Mozilla project, free)
- ✅ **Unix-native** (encrypts files, stores in git)
- ✅ **Simple** (single binary, no external service)
- ✅ **Age encryption** (modern, simple key management)
- ✅ **Git-friendly** (encrypted secrets tracked, no drift)
- ✅ **Developer-friendly** (decrypt once, use environment variables)

**How it works:**
```bash
# Encrypt secrets file
sops -e --age <public_key> secrets/database.env > secrets/database.env.enc

# Decrypt at deployment (systemd ExecStartPre)
sops -d secrets/database.env.enc > /run/eracun/database.env

# Service reads from /run/eracun/*.env (tmpfs, cleared on reboot)
```

**Alternative: systemd Credentials (systemd 250+)**
- Native systemd secret management
- Encrypted credentials passed to services
- No external dependencies
- Requires systemd 250+ (Ubuntu 22.04+, Debian 12+)

### Environment Separation

**Multiple DigitalOcean Droplets:**

```
dev.eracun.internal       (10.x.x.1)  - Development testing
staging.eracun.internal   (10.x.x.2)  - Pre-production (cistest.apis-it.hr)
production.eracun.hr      (x.x.x.x)   - Production (cis.porezna-uprava.hr)
```

**OR Single Droplet with systemd instances:**

```
eracun-email-worker@dev.service
eracun-email-worker@staging.service
eracun-email-worker@production.service
```

**Recommended:** Separate droplets (isolation, separate FINA certificates)

---

## Alternative Options (For Reference)

### 1. HashiCorp Vault

- ✅ Enterprise-grade, mature
- ✅ Dynamic secrets (auto-rotation)
- ✅ Audit logging
- ❌ **Operational overhead** (requires Vault server, maintenance)
- ❌ **Complexity overkill** for single droplet
- ⚠️ Open source (free) but complex to operate

**Verdict:** Too complex for initial deployment, consider for future scaling

### 2. Kubernetes Secrets

- ❌ **Not applicable** (not using Kubernetes initially)

### 3. File-based with GPG

- ✅ Traditional Unix approach
- ✅ GPG widely available
- ⚠️ GPG key management complex
- ⚠️ SOPS is better modern alternative

**Verdict:** SOPS replaces this (simpler key management with age)

### 4. pass (passwordstore.org)

- ✅ Unix password manager (GPG-based)
- ✅ Git-backed storage
- ⚠️ Designed for interactive use, not automation
- ⚠️ GPG complexity

**Verdict:** Good for manual secrets, SOPS better for automation

---

### 2. Configuration Hierarchy

**Three-Level Proposal:**

```
Platform-Level (Global)
  ├─ Message bus URLs (RabbitMQ, Kafka)
  ├─ Observability endpoints (Jaeger, Prometheus)
  ├─ Global timeouts, retry policies
  └─ Shared feature flags

Service-Level (Local)
  ├─ Service-specific ports
  ├─ Dependencies (upstream/downstream services)
  ├─ Business logic settings (validation thresholds)
  └─ Performance budgets

Environment-Level (Deployment)
  ├─ FINA URLs (test vs production)
  ├─ Database connection strings
  ├─ S3 bucket names
  └─ Resource limits (CPU/memory)
```

**Questions:**
- Is this hierarchy correct?
- Should we add a fourth level (per-deployment overrides)?
- How do we handle developer-specific local configs?

---

### 3. Directory Structure

**Proposed:**

```
eRacun-development/
├── config/                          # Platform-level config
│   ├── platform.yaml                # Global defaults (IN GIT)
│   ├── secrets.example.yaml         # Secret template (IN GIT)
│   └── environments/
│       ├── dev.yaml                 # Dev overrides (IN GIT)
│       ├── staging.yaml             # Staging overrides (IN GIT)
│       └── production.yaml          # Prod overrides (IN GIT, NO SECRETS)
│
├── services/{category}/{service}/
│   ├── config/
│   │   ├── default.yaml             # Service defaults (IN GIT)
│   │   └── schema.json              # Config validation schema
│   └── .env.example                 # Local dev template (IN GIT)
│
├── infrastructure/
│   ├── vault/                       # Vault policies and paths
│   │   ├── policies/                # Access policies per service
│   │   └── secret-paths.md          # Documentation of secret locations
│   ├── kubernetes/
│   │   └── {service}/
│   │       ├── configmap.yaml       # Non-sensitive K8s config
│   │       └── secret.yaml.example  # Secret template (actual in Vault)
│   └── .gitignore                   # Prevent committing secrets
│
└── .env.example                     # Platform-level dev template (IN GIT)
```

**Questions:**
- Does this structure work with monorepo tooling?
- Should service configs be more nested (e.g., `config/environments/dev.yaml`)?

---

### 4. FINA Certificate Storage

**Critical Decision:** .p12 files contain private keys (MUST NOT be committed to Git)

**Options:**

**A. Vault KV Store (Recommended)**
```
secret/fina/certificates/
  ├─ demo/
  │   ├─ cert_base64
  │   └─ password
  └─ production/
      ├─ cert_base64
      └─ password
```
- Services fetch at startup
- Access controlled by Vault policies
- Audit trail of all accesses

**B. Kubernetes Secret (from Vault)**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fina-cert
data:
  cert.p12: <base64>  # Injected from Vault
  password: <base64>
```
- Mounted as volume in pods
- Still sourced from Vault (not manually created)

**C. External HSM (Future)**
- Hardware Security Module for production
- Private key never leaves HSM
- Highest security, highest cost

**Questions:**
- Which approach for Phase 1 (MVP)?
- Plan for HSM migration later?
- One certificate shared by all services, or per-service?

---

### 5. Secret Categories & Rotation

| Secret Type | Example | Storage | Rotation Frequency |
|-------------|---------|---------|-------------------|
| FINA Certificates | .p12 + password | Vault KV | 5 years (before expiry) |
| Database Credentials | Postgres password | Vault Dynamic | 90 days (auto) |
| API Keys | External services | Vault KV | 180 days |
| Encryption Keys | AES-256 | Vault Transit | Yearly |
| JWT Signing Keys | RS256 private key | Vault KV | Yearly |
| Message Bus | RabbitMQ password | Vault Dynamic | 90 days |

**Questions:**
- Are rotation frequencies acceptable?
- Should we use Vault dynamic secrets for databases (auto-rotation)?
- Or static secrets with manual rotation?

---

### 6. Environment Strategy

**Proposed Environments:**

1. **Local Development**
   - Runs on developer machine
   - Uses `.env` files (NOT committed)
   - Uses FINA demo certificates
   - Points to local Docker services (Postgres, RabbitMQ)

2. **Staging (cistest.apis-it.hr)**
   - Deployed to DigitalOcean Kubernetes
   - Uses Vault for secrets
   - Uses FINA test environment
   - Mirrors production architecture

3. **Production (cis.porezna-uprava.hr)**
   - Deployed to DigitalOcean Kubernetes
   - Separate Vault instance (or namespace)
   - Uses FINA production certificates
   - Full monitoring, alerting

**Questions:**
- Do we need a fourth "preview" environment (for PR testing)?
- Separate Vault clusters per environment or namespaced paths?
- How to handle FINA test credentials (shared across team)?

---

### 7. Configuration Format

**Options:**
- **YAML** - Human-readable, comments allowed, widely used
- **JSON** - Strict typing, no comments, easier to validate
- **TOML** - Middle ground, used by Rust/Go projects

**Recommendation:** YAML (most common for K8s ecosystem)

**Validation:** All configs MUST have JSON Schema validation

**Example:**
```yaml
# config/platform.yaml
platform:
  message_bus:
    rabbitmq_url: amqp://localhost:5672  # Overridden in production
    kafka_brokers:
      - localhost:9092

  observability:
    jaeger_endpoint: http://localhost:14268/api/traces
    prometheus_port: 9090

  timeouts:
    default_request_timeout_ms: 5000
    message_processing_timeout_ms: 30000
```

---

### 8. Security Safeguards

**Git Protection:**

**.gitignore:**
```
*.p12
*.pfx
*.key
*.pem
.env
.env.local
secrets.yaml
**/config/secrets/
```

**Pre-commit Hook:**
```bash
#!/bin/bash
# Detect potential secrets in commits
if git diff --cached | grep -E '(password|secret|api[_-]?key|private[_-]?key).*='; then
  echo "❌ ERROR: Potential secret detected in commit"
  exit 1
fi
```

**Vault Access Control:**
```hcl
# vault/policies/signature-service.hcl
path "secret/data/services/signature-service/*" {
  capabilities = ["read"]
}

path "secret/data/fina/certificates/production" {
  capabilities = ["read"]
}

# No write access to production certs
```

---

### 9. Configuration Loading (Runtime)

**Precedence Order (highest to lowest):**
```
1. Environment Variables (K8s secrets injected)
2. Vault Secrets (fetched at startup)
3. Service config/default.yaml
4. Platform config/platform.yaml
5. Hardcoded defaults (last resort, minimal)
```

**TypeScript Service Example:**
```typescript
// services/signature-service/src/config/loader.ts
import Vault from 'node-vault';
import yaml from 'js-yaml';
import Ajv from 'ajv';

export async function loadConfig() {
  // 1. Load platform defaults
  const platformConfig = yaml.load(
    fs.readFileSync('/config/platform.yaml', 'utf8')
  );

  // 2. Load service defaults
  const serviceConfig = yaml.load(
    fs.readFileSync('./config/default.yaml', 'utf8')
  );

  // 3. Fetch secrets from Vault (production only)
  let secrets = {};
  if (process.env.NODE_ENV === 'production') {
    const vault = Vault({
      endpoint: process.env.VAULT_ADDR,
      token: process.env.VAULT_TOKEN, // K8s service account
    });
    const response = await vault.read('secret/data/services/signature-service');
    secrets = response.data.data;
  } else {
    // Dev: use .env file
    secrets = dotenv.parse(fs.readFileSync('.env', 'utf8'));
  }

  // 4. Merge with precedence
  const config = {
    ...platformConfig,
    ...serviceConfig,
    ...secrets,
    ...process.env, // Environment variables highest priority
  };

  // 5. Validate against schema
  const ajv = new Ajv();
  const schema = JSON.parse(fs.readFileSync('./config/schema.json', 'utf8'));
  const valid = ajv.validate(schema, config);
  if (!valid) {
    throw new Error(`Config validation failed: ${ajv.errorsText()}`);
  }

  return config;
}
```

---

## Unix/Droplet Implementation Details

### Systemd Service Configuration

**Service Template (eracun-email-worker.service):**

```ini
[Unit]
Description=eRacun Email Ingestion Worker
After=network.target postgresql.service rabbitmq-server.service
Wants=postgresql.service rabbitmq-server.service

[Service]
Type=simple
User=eracun
Group=eracun
WorkingDirectory=/opt/eracun/services/email-worker

# Environment files (precedence: later overrides earlier)
EnvironmentFile=/etc/eracun/platform.conf
EnvironmentFile=/etc/eracun/environment.conf
EnvironmentFile=/etc/eracun/services/email-worker.conf
EnvironmentFile=/run/eracun/secrets.env  # Decrypted by ExecStartPre

# Decrypt secrets before starting service (SOPS)
ExecStartPre=/usr/local/bin/decrypt-secrets.sh email-worker

# Start service
ExecStart=/usr/local/bin/node dist/index.js

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/log/eracun /var/lib/eracun

# Resource limits
MemoryMax=1G
CPUQuota=200%

# Restart policy
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### SOPS Decryption Script

**/usr/local/bin/decrypt-secrets.sh:**

```bash
#!/bin/bash
set -euo pipefail

SERVICE_NAME="$1"
AGE_KEY_FILE="/etc/eracun/.age-key"
ENCRYPTED_SECRETS="/etc/eracun/secrets/${SERVICE_NAME}.env.enc"
DECRYPTED_OUTPUT="/run/eracun/secrets.env"

# Create runtime directory (tmpfs, cleared on reboot)
mkdir -p /run/eracun
chmod 700 /run/eracun

# Decrypt secrets using age key
if [ -f "$ENCRYPTED_SECRETS" ]; then
  sops --decrypt --age "$(cat $AGE_KEY_FILE)" "$ENCRYPTED_SECRETS" > "$DECRYPTED_OUTPUT"
  chmod 600 "$DECRYPTED_OUTPUT"
  chown eracun:eracun "$DECRYPTED_OUTPUT"
fi
```

### Directory Structure (Monorepo + System)

**In Git (eRacun-development/):**

```
eRacun-development/
├── config/
│   ├── platform.conf.example      # Template for /etc/eracun/platform.conf
│   ├── environment.conf.example   # Template for environment overrides
│   └── services/
│       ├── email-worker.conf.example
│       └── xsd-validator.conf.example
│
├── secrets/                        # SOPS-encrypted secrets (IN GIT)
│   ├── .sops.yaml                  # SOPS configuration (age keys)
│   ├── database.env.enc            # Encrypted database credentials
│   ├── fina-cert.p12.enc           # Encrypted FINA certificate
│   └── api-keys.env.enc            # Encrypted API keys
│
├── deployment/
│   ├── systemd/                    # Systemd unit files
│   │   ├── eracun-email-worker.service
│   │   ├── eracun-xsd-validator.service
│   │   └── decrypt-secrets.sh
│   └── ansible/                    # Deployment automation (optional)
│       └── deploy-droplet.yml
│
└── .gitignore                      # Prevents committing decrypted secrets
```

**On Droplet (/etc/eracun/):**

```
/etc/eracun/
├── platform.conf                   # Deployed from config/platform.conf.example
├── environment.conf                # Staging or production values
├── services/
│   ├── email-worker.conf
│   └── xsd-validator.conf
├── secrets/                        # Decrypted secrets (NOT in git)
│   ├── fina-cert.p12               # Decrypted FINA certificate
│   ├── database.env                # Plaintext DB credentials
│   └── api-keys.env
└── .age-key                        # Age private key (decrypt SOPS secrets)
```

### Configuration Loading (TypeScript)

```typescript
// services/email-worker/src/config/loader.ts
import fs from 'fs';
import yaml from 'js-yaml';
import dotenv from 'dotenv';

export function loadConfig() {
  // 1. Load platform config (YAML)
  const platformConf = yaml.load(
    fs.readFileSync('/etc/eracun/platform.conf', 'utf8')
  ) as Record<string, any>;

  // 2. Load service-specific config (YAML)
  const serviceConf = yaml.load(
    fs.readFileSync('/etc/eracun/services/email-worker.conf', 'utf8')
  ) as Record<string, any>;

  // 3. Load secrets (env format, decrypted by systemd ExecStartPre)
  const secrets = dotenv.parse(
    fs.readFileSync('/run/eracun/secrets.env', 'utf8')
  );

  // 4. Merge with precedence (later overrides earlier)
  return {
    ...platformConf,
    ...serviceConf,
    ...secrets,
    ...process.env,  // Environment variables highest priority
  };
}
```

### Deployment Workflow

**Initial Droplet Setup:**

```bash
# 1. Create service user
sudo useradd -r -s /bin/false eracun

# 2. Create directories
sudo mkdir -p /etc/eracun/{services,secrets}
sudo mkdir -p /opt/eracun/services
sudo mkdir -p /var/log/eracun
sudo mkdir -p /var/lib/eracun

# 3. Set permissions
sudo chown -R eracun:eracun /etc/eracun /opt/eracun /var/log/eracun /var/lib/eracun
sudo chmod 700 /etc/eracun/secrets

# 4. Install SOPS and age
sudo apt-get install age  # Modern encryption tool
wget https://github.com/mozilla/sops/releases/download/v3.8.1/sops_3.8.1_amd64.deb
sudo dpkg -i sops_3.8.1_amd64.deb

# 5. Generate age key pair (one-time)
age-keygen -o /etc/eracun/.age-key
sudo chmod 600 /etc/eracun/.age-key
sudo chown eracun:eracun /etc/eracun/.age-key

# 6. Copy public key to repository .sops.yaml
age-keygen -y /etc/eracun/.age-key  # Output: age1xxxxxx...
```

**Deployment Process:**

```bash
# 1. Build services locally or in CI
npm run build

# 2. Deploy to droplet
rsync -avz --exclude node_modules services/ deploy@droplet:/opt/eracun/services/

# 3. Copy configs
sudo cp config/platform.conf.example /etc/eracun/platform.conf
sudo cp config/environment-production.conf /etc/eracun/environment.conf

# 4. Decrypt secrets
sudo /usr/local/bin/decrypt-secrets.sh email-worker

# 5. Install systemd units
sudo cp deployment/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# 6. Start services
sudo systemctl enable eracun-email-worker
sudo systemctl start eracun-email-worker
```

---

## Open Questions (Unix/Droplet Context)

1. **Environment Count:** Single droplet (staging + prod via systemd instances) or separate droplets? **Recommend:** Separate droplets
2. **Database:** PostgreSQL on same droplet or DigitalOcean Managed Database? **Recommend:** Managed DB (less ops burden)
3. **Message Bus:** RabbitMQ on droplet or DigitalOcean Managed Kafka? **Recommend:** Self-hosted RabbitMQ (FOSS, lower cost)
4. **Monitoring:** Prometheus + Grafana on droplet or external SaaS? **Recommend:** Self-hosted (cost, data sovereignty)
5. **Age Key Backup:** Where to securely backup age private key? **Recommend:** Encrypted USB drive + password manager
6. **Config Changes:** Restart services or implement live reload (SIGHUP)? **Recommend:** Restart (simpler, safer)
7. **Developer Onboarding:** How to share age private key with team? **Recommend:** Per-developer age keys in .sops.yaml, master key for CI/CD

---

## Deliverables Required (UPDATED)

**When this issue is resolved, we need:**

1. **ADR-001:** Configuration Management Strategy (Unix filesystem-based)
2. **ADR-002:** Secrets Management with SOPS + age
3. **Updated CLAUDE.md** section 3.4 with Unix/systemd details
4. **Directory structure creation:**
   - `config/` with .conf.example templates
   - `secrets/` with .sops.yaml configuration
   - `deployment/systemd/` with service units
   - `.gitignore` updates (prevent decrypted secrets)
5. **Template files:**
   - `config/platform.conf.example`
   - `config/environment-{staging,production}.conf.example`
   - `secrets/database.env.enc` (SOPS-encrypted template)
6. **Scripts:**
   - `decrypt-secrets.sh` (systemd ExecStartPre)
   - `deploy-droplet.sh` (deployment automation)
7. **Documentation:**
   - `docs/operations/droplet-setup.md` (initial server setup)
   - `docs/operations/secrets-management.md` (SOPS + age guide)
   - `docs/operations/deployment.md` (deployment process)
8. **Security:**
   - Pre-commit hook for secret detection
   - Age key generation guide

---

## Dependencies

**Blocks:**
- All service implementation (services need config to run)
- FINA certificate integration (.p12 file storage)
- Database deployment (connection string configuration)
- Message bus setup (RabbitMQ URL configuration)

**Blocked By:**
- None (can be addressed immediately)

---

## Recommendation (UPDATED)

**Priority:** Address NOW (P0 blocker resolved)

**Approach (Unix/Droplet):**

1. **Create ADRs** (1 hour)
   - ADR-001: Configuration strategy (filesystem-based)
   - ADR-002: Secrets management (SOPS + age)

2. **Implement directory structure** (2 hours)
   - Create `config/`, `secrets/`, `deployment/systemd/`
   - Add `.gitignore` rules
   - Create example config templates

3. **Write systemd units** (2 hours)
   - Template service file
   - `decrypt-secrets.sh` script
   - Test on local VM or DigitalOcean test droplet

4. **Document procedures** (2 hours)
   - Droplet setup guide
   - SOPS + age usage guide
   - Deployment process

5. **Update CLAUDE.md** (1 hour)
   - Replace Vault/K8s references with SOPS/systemd
   - Add Unix conventions section

**Total Estimated Effort:** 8 hours (1 day)

**Tools Required:**
- SOPS (https://github.com/mozilla/sops) - Free, open source
- age (https://age-encryption.org/) - Free, open source, modern
- systemd (built into Linux) - Free

**Total Cost:** €0 (all FOSS)

---

## References (UPDATED)

- **SOPS:** https://github.com/mozilla/sops (Mozilla secrets encryption)
- **age:** https://age-encryption.org/ (Modern encryption tool)
- **systemd:** https://systemd.io/ (Service management)
- **12-Factor App:** https://12factor.net/config (Config best practices)
- **CLAUDE.md** section 3.4 (will be updated with Unix approach)

---

**Next Action:** User approval to proceed with Unix/SOPS approach, then create ADRs and implement structure.

**Decision Required:** Confirm SOPS + age + systemd approach is acceptable before proceeding.
