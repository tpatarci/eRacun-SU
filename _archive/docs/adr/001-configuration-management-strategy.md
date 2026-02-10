# ADR-001: Configuration Management Strategy

**Status:** ✅ Accepted

**Date:** 2025-11-09

**Decision Makers:** Technical Lead, System Architect

**Related:** PENDING-001, ADR-002 (Secrets Management)

---

## Context

The eRacun platform is a mission-critical B2B e-invoice processing system that must:

- Support 21+ microservices in a monorepo architecture
- Handle legally binding financial documents with zero error tolerance
- Comply with Croatian Fiskalizacija 2.0 regulations (effective 1 January 2026)
- Run on DigitalOcean dedicated droplets using Unix conventions
- Support multiple environments (development, staging, production)
- Protect sensitive data (FINA certificates, database credentials, API keys)
- Enable developer-friendly local development
- Maintain configuration as code (version controlled, auditable)

**Deployment Context:**

- **Platform:** DigitalOcean dedicated Linux droplet (Ubuntu 22.04+ or Debian 12+)
- **Orchestration:** systemd (not Kubernetes initially)
- **Philosophy:** Classic Unix conventions (filesystem hierarchy, POSIX standards, file permissions)
- **Constraints:** Open source, free or affordable solutions preferred

**Configuration Challenges:**

1. **Hierarchy:** How to organize platform-wide, service-specific, and environment-specific configs?
2. **Discovery:** How do services locate and load configuration at runtime?
3. **Precedence:** What order should configuration sources be merged (environment variables, files, defaults)?
4. **Secrets Separation:** How to separate public config from sensitive secrets? (Addressed in ADR-002)
5. **Developer Experience:** How to enable local development without production credentials?

---

## Decision

**We will adopt a filesystem-based configuration strategy using Unix conventions with systemd integration.**

### Configuration Hierarchy (Three Levels)

**1. Platform-Level Configuration**
- **Location:** `/etc/eracun/platform.conf`
- **Format:** YAML
- **Permissions:** 644 (world-readable)
- **Content:** Global settings shared by all services
  - Message bus URLs (RabbitMQ, Kafka)
  - Observability endpoints (Jaeger, Prometheus)
  - Global timeouts and retry policies
  - Shared feature flags

**Example:**
```yaml
platform:
  message_bus:
    rabbitmq_url: amqp://localhost:5672
    kafka_brokers:
      - localhost:9092

  observability:
    jaeger_endpoint: http://localhost:14268/api/traces
    prometheus_port: 9090

  timeouts:
    default_request_timeout_ms: 5000
    message_processing_timeout_ms: 30000
```

**2. Service-Level Configuration**
- **Location:** `/etc/eracun/services/{service-name}.conf`
- **Format:** YAML
- **Permissions:** 644 (world-readable)
- **Content:** Service-specific settings
  - Service port
  - Dependencies (upstream/downstream services)
  - Business logic thresholds
  - Performance budgets

**Example (`/etc/eracun/services/email-worker.conf`):**
```yaml
service:
  name: email-worker
  port: 3001

  dependencies:
    upstream:
      - imap-server
    downstream:
      - file-parser
      - document-store

  email:
    poll_interval_seconds: 60
    max_attachments_per_email: 10
    max_attachment_size_mb: 10
```

**3. Environment-Level Configuration**
- **Location:** `/etc/eracun/environment.conf`
- **Format:** YAML
- **Permissions:** 644 (world-readable)
- **Content:** Environment-specific overrides (staging vs production)
  - FINA API URLs (test vs production)
  - Database connection strings (non-secret parts)
  - External service endpoints
  - Resource limits

**Example (`environment.conf` for production):**
```yaml
environment: production

fina:
  b2c_endpoint: https://cis.porezna-uprava.hr:8449/FiskalizacijaService
  b2b_endpoint: https://as4-gateway.fina.hr/

database:
  host: db.eracun.internal
  port: 5432
  name: eracun_production

resources:
  max_memory_mb: 1024
  max_cpu_percent: 200
```

### Configuration Loading Precedence

**Order (highest to lowest priority):**

1. **Environment Variables** - Highest priority, set by systemd or manually
2. **Secrets File** - `/run/eracun/secrets.env` (decrypted by systemd ExecStartPre, see ADR-002)
3. **Service Configuration** - `/etc/eracun/services/{service-name}.conf`
4. **Environment Configuration** - `/etc/eracun/environment.conf`
5. **Platform Configuration** - `/etc/eracun/platform.conf`
6. **Hardcoded Defaults** - Lowest priority, minimal fallback values

**Systemd Integration:**

Services use `EnvironmentFile` directive to load configs:

```ini
[Service]
EnvironmentFile=/etc/eracun/platform.conf
EnvironmentFile=/etc/eracun/environment.conf
EnvironmentFile=/etc/eracun/services/email-worker.conf
EnvironmentFile=/run/eracun/secrets.env
```

**Service Code (TypeScript Example):**

```typescript
import fs from 'fs';
import yaml from 'js-yaml';
import dotenv from 'dotenv';

export function loadConfig() {
  // Load YAML configs
  const platformConf = yaml.load(
    fs.readFileSync('/etc/eracun/platform.conf', 'utf8')
  ) as Record<string, any>;

  const environmentConf = yaml.load(
    fs.readFileSync('/etc/eracun/environment.conf', 'utf8')
  ) as Record<string, any>;

  const serviceConf = yaml.load(
    fs.readFileSync('/etc/eracun/services/email-worker.conf', 'utf8')
  ) as Record<string, any>;

  // Load secrets (env format, decrypted by systemd)
  const secrets = dotenv.parse(
    fs.readFileSync('/run/eracun/secrets.env', 'utf8')
  );

  // Merge with precedence (later overrides earlier)
  return {
    ...platformConf,
    ...environmentConf,
    ...serviceConf,
    ...secrets,
    ...process.env,  // Environment variables highest
  };
}
```

### Repository Structure (Git)

**Configuration templates stored in repository:**

```
eRacun-development/
├── config/
│   ├── platform.conf.example
│   ├── environment-dev.conf.example
│   ├── environment-staging.conf.example
│   ├── environment-production.conf.example
│   └── services/
│       ├── email-worker.conf.example
│       ├── xsd-validator.conf.example
│       └── ... (one per service)
```

**Deployment process:**
1. Copy `.example` files to `/etc/eracun/` on droplet
2. Rename (remove `.example` suffix)
3. Customize with environment-specific values
4. Set correct permissions (644)

### Developer Local Development

**Local override using environment variables:**

```bash
# Developer's local .env file (NOT in git)
RABBITMQ_URL=amqp://localhost:5672
DATABASE_HOST=localhost
FINA_CERT_PATH=/home/dev/certs/demo-cert.p12
```

**Or local config override:**

```bash
# Run with custom config path
CONFIG_DIR=./config/local node dist/index.js
```

---

## Consequences

### Positive

✅ **Unix-Native**
- Follows Filesystem Hierarchy Standard (FHS)
- Leverages file permissions for access control
- Familiar to Unix sysadmins

✅ **Systemd Integration**
- `EnvironmentFile` directive provides clean config loading
- `ExecStartPre` allows secret decryption before service start
- Service dependencies (`After`, `Wants`) ensure correct startup order

✅ **Version Controlled**
- Config templates in git with full audit trail
- `.example` suffix prevents committing production values
- Easy to review config changes in pull requests

✅ **Environment Separation**
- Clear distinction between dev/staging/production
- Single repository supports multiple environments
- No hardcoded environment-specific values in code

✅ **Developer Friendly**
- `.example` files serve as documentation
- Local development uses same loading mechanism
- Environment variables for quick overrides

✅ **Simple & Maintainable**
- No external dependencies (no Vault server to maintain)
- Standard YAML format (human-readable, comments supported)
- File-based debugging (cat, less, grep work as expected)

✅ **Performance**
- Config loaded once at startup (no network calls)
- YAML parsing ~1ms overhead
- No external service latency

### Negative

⚠️ **Manual Deployment**
- Requires copying files to `/etc/eracun/` during deployment
- No automatic config sync (Ansible/scripts needed)

⚠️ **No Dynamic Reload**
- Config changes require service restart
- Cannot modify config without downtime
- **Mitigation:** Use systemd `ExecReload` for SIGHUP support (future enhancement)

⚠️ **File Permission Management**
- Must ensure correct ownership and permissions
- `eracun` user must have read access
- **Mitigation:** Deployment scripts enforce permissions

⚠️ **No Built-in Validation**
- YAML syntax errors cause service startup failure
- No schema validation by default
- **Mitigation:** Implement JSON Schema validation in service loader

⚠️ **Secrets in Filesystem**
- Secrets stored on disk (even if encrypted)
- Risk if droplet compromised
- **Mitigation:** Addressed in ADR-002 (SOPS + age encryption, file permissions, tmpfs for decrypted secrets)

### Neutral

↔️ **Not Cloud-Native**
- Does not use Kubernetes ConfigMaps/Secrets
- Not compatible with container orchestration patterns
- **Note:** Acceptable for initial deployment, can migrate later if scaling requires Kubernetes

---

## Alternatives Considered

### 1. Kubernetes ConfigMaps + Secrets

**Rejected:** Not using Kubernetes initially (systemd orchestration chosen for simplicity on DigitalOcean droplets)

### 2. HashiCorp Vault

**Rejected:** Operational overhead too high for single-server deployment. Requires Vault server, HA setup, backup management. Cost/benefit ratio unfavorable for initial deployment.

**Future Consideration:** May adopt if scaling to multi-server deployment.

### 3. Environment Variables Only

**Rejected:** Hard to manage 21+ services with hundreds of config values. No hierarchical structure. No comments or documentation inline.

### 4. JSON Configuration Files

**Rejected:** YAML chosen for human readability and comment support. JSON strict syntax makes manual editing error-prone.

### 5. TOML Configuration Files

**Considered:** Good middle ground between YAML and JSON.

**Rejected:** YAML more familiar in Node.js/TypeScript ecosystem. Better library support.

---

## Compliance & Security

**Croatian Regulatory Requirements:**

- Configuration must support 11-year audit trail (version control: ✅)
- FINA certificate paths must be configurable (environment-specific: ✅)
- Must separate test and production endpoints (environment.conf: ✅)

**Security Considerations:**

- Public configs (644) contain no secrets (enforced by code review)
- Secrets handled separately (see ADR-002)
- File permissions prevent unauthorized access
- Systemd hardening (`ProtectSystem=strict`, `PrivateTmp=true`)

---

## Implementation Checklist

- [x] Create `/docs/adr/001-configuration-management-strategy.md` (this document)
- [ ] Create `config/` directory in repository
- [ ] Create example config files (`.conf.example`)
- [ ] Implement TypeScript config loader (`loadConfig()`)
- [ ] Create systemd service template with `EnvironmentFile` directives
- [ ] Update CLAUDE.md section 3.4 with filesystem-based approach
- [ ] Create deployment script to copy configs to `/etc/eracun/`
- [ ] Document in `docs/operations/configuration.md`

---

## References

- **PENDING-001:** Configuration & Secrets Management Strategy
- **ADR-002:** Secrets Management with SOPS + age
- **Filesystem Hierarchy Standard:** https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html
- **systemd EnvironmentFile:** https://www.freedesktop.org/software/systemd/man/systemd.exec.html#EnvironmentFile=
- **12-Factor App (Config):** https://12factor.net/config

---

**Approved By:** System Architect
**Implementation Status:** In Progress
**Next Review:** After first service deployment
