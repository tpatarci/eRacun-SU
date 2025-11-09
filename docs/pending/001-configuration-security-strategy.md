# PENDING-001: Configuration & Secrets Management Strategy

**Status:** 🔴 CRITICAL - Must address before any service implementation
**Priority:** P0 (Blocking)
**Created:** 2025-11-09
**Identified By:** Architecture review
**Blocks:** All service development (services need config to run)

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

## Scope of Decision Required

### 1. Secrets Management Tool Selection

**Options:**
- **HashiCorp Vault** (mentioned in CLAUDE.md section 3.4)
  - ✅ Enterprise-grade, mature
  - ✅ Dynamic secrets (auto-rotation)
  - ✅ Audit logging
  - ⚠️ Operational overhead (requires Vault cluster)

- **Kubernetes Secrets Only**
  - ✅ Simple, native to K8s
  - ✅ Encrypted at rest (if K8s configured)
  - ⚠️ No rotation, no audit trail
  - ⚠️ Less secure (secrets in etcd)

- **SOPS (Secrets OPerationS)**
  - ✅ Encrypted files in Git
  - ✅ Simple, no external service
  - ⚠️ Manual rotation
  - ⚠️ Key management still needed

- **Cloud Provider Managed**
  - DigitalOcean Managed Databases (auto-inject credentials)
  - AWS Secrets Manager / Azure Key Vault integration
  - ✅ Managed service (less ops burden)
  - ⚠️ Vendor lock-in

**Recommendation:** HashiCorp Vault (aligns with CLAUDE.md, best security posture)

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

## Open Questions

1. **Vault Deployment:** Self-hosted or managed service? DigitalOcean doesn't offer managed Vault.
2. **Vault HA:** Single instance (dev) or HA cluster (production)?
3. **Secret Injection:** Vault Agent sidecar or init container?
4. **Config Changes:** How to handle live config reloads without restarting services?
5. **Audit Requirements:** Are Vault audit logs sufficient for Croatian compliance?
6. **Backup Strategy:** How to backup Vault secrets? Encrypted snapshots?
7. **Developer Onboarding:** How do new developers get initial secrets for local dev?

---

## Deliverables Required

**When this issue is resolved, we need:**

1. **ADR-001:** Configuration Management Strategy
2. **ADR-002:** Secrets Management with HashiCorp Vault
3. **Updated CLAUDE.md** section 3.4 with specific implementation
4. **Directory structure creation:**
   - `config/` with platform configs
   - `infrastructure/vault/` with policies
   - `.gitignore` updates
5. **Template files:**
   - `.env.example` (platform)
   - `config/secrets.example.yaml`
   - Service-level `.env.example` template
6. **Pre-commit hook** for secret detection
7. **Vault setup guide** (`docs/operations/vault-setup.md`)
8. **Developer onboarding guide** (`docs/operations/developer-setup.md`)

---

## Dependencies

**Blocks:**
- All service implementation (services can't run without config)
- FINA certificate integration
- Database deployment
- Message bus setup

**Blocked By:**
- None (can be addressed immediately)

---

## Recommendation

**Priority:** Address THIS WEEK before any service coding begins.

**Approach:**
1. Make architectural decisions (Vault vs alternatives, hierarchy, formats)
2. Create ADRs documenting decisions
3. Implement directory structure and templates
4. Set up Vault (dev instance for testing)
5. Document in CLAUDE.md
6. Then proceed with first service specification

**Estimated Effort:** 1-2 days for documentation + structure, 1-2 days for Vault setup

---

## References

- **CLAUDE.md** section 3.4 (mentions Vault, K8s secrets)
- **12-Factor App:** https://12factor.net/config (industry best practices)
- **HashiCorp Vault:** https://www.vaultproject.io/
- **Kubernetes Secrets:** https://kubernetes.io/docs/concepts/configuration/secret/

---

**Next Action:** User decision on approach, then create ADRs and implementation.
