# CLAUDE.md - Certificate Lifecycle Manager Service

**Service:** `cert-lifecycle-manager`
**Layer:** Management (Layer 10)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **cert-lifecycle-manager** service for the eRacun e-invoice processing platform. This service is **critical for uninterrupted invoice submission** to FINA. Certificate expiration blocks all invoice processing.

**What you're building:**
- X.509 certificate parser (parse .p12 FINA certificates)
- Certificate inventory (track all certs in PostgreSQL)
- Expiration monitor (daily checks, multi-level alerts)
- Certificate deployment (distribute to digital-signature-service)

**Estimated effort:** 4-5 days
**Complexity:** High (~2,200 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/CROATIAN_COMPLIANCE.md`** - FINA certificate requirements (MANDATORY)
4. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
5. **`/services/xsd-validator/`** - Reference implementation pattern
6. **`/services/schematron-validator/`** - Reference observability module
7. **`/docs/adr/002-secrets-management-sops-age.md`** - Certificate encryption (SOPS + age)

**Time investment:** 45-60 minutes reading
**Why mandatory:** Prevents rework, ensures compliance with Croatian law, establishes patterns

---

## 3. ARCHITECTURAL CONTEXT

### 3.1 Where This Service Fits

```
            ┌────────────────────┐
            │  admin-portal-api  │
            │  (admin uploads    │
            │   new .p12 cert)   │
            └────────┬───────────┘
                     │
                     │ POST /api/v1/certificates/upload
                     ▼
            ┌────────────────────┐
            │  THIS SERVICE      │
            │  cert-lifecycle-   │
            │  manager           │
            └────────┬───────────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
        ▼            ▼            ▼
   Parse .p12   Monitor      Deploy cert
   (node-forge) expiration   (SOPS + age)
                     │
                     │ Daily cron check
                     ▼
            ┌────────────────────┐
            │  PostgreSQL        │
            │  certificates      │
            │  (inventory)       │
            └────────┬───────────┘
                     │
                     │ 30/14/7/1 days before expiry
                     ▼
            ┌────────────────────┐
            │  notification-     │
            │  service           │
            │  (expiration       │
            │   alerts)          │
            └────────────────────┘
                     │
                     │ Deploy encrypted cert
                     ▼
            ┌────────────────────┐
            │  /etc/eracun/      │
            │  secrets/certs/    │
            │  fina-prod.p12.enc │
            └────────┬───────────┘
                     │
                     │ Used by
                     ▼
            ┌────────────────────┐
            │  digital-signature-│
            │  service           │
            │  (XMLDSig signing) │
            └────────────────────┘
```

### 3.2 Critical Dependencies

**Upstream (Consumes From):**
- HTTP POST: `/api/v1/certificates/upload` (admin uploads new .p12 cert)
- Scheduled job: Daily expiration check (cron)
- FINA CMS API: Certificate status queries (optional, future)

**Downstream (Produces To):**
- PostgreSQL table: `certificates` (inventory)
- Filesystem: `/etc/eracun/secrets/certs/` (encrypted certificates)
- notification-service: POST `/notifications` (expiration alerts)
- digital-signature-service: Certificate deployment (via file copy + reload)

**No RabbitMQ queues** (HTTP API + cron-based, not message-driven)

### 3.3 Certificate Inventory Schema

**PostgreSQL:**

```sql
CREATE TABLE certificates (
  id BIGSERIAL PRIMARY KEY,
  cert_id UUID UNIQUE NOT NULL,
  cert_type VARCHAR(50) NOT NULL,        -- 'production', 'demo', 'test'
  issuer VARCHAR(100) NOT NULL,          -- 'FINA', 'AKD'
  subject_dn TEXT NOT NULL,              -- Certificate DN
  serial_number VARCHAR(100) NOT NULL,
  not_before TIMESTAMP NOT NULL,
  not_after TIMESTAMP NOT NULL,          -- Expiration date
  status VARCHAR(50) NOT NULL,           -- 'active', 'expiring_soon', 'expired', 'revoked'
  cert_path VARCHAR(255),                -- File path (e.g., /etc/eracun/certs/fina-prod.p12)
  password_encrypted TEXT,               -- Encrypted .p12 password
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_cert_expiration ON certificates(not_after, status);
CREATE INDEX idx_cert_status ON certificates(status);
```

---

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save node-forge pg express axios node-cron prom-client pino opentelemetry uuid
   npm install --save-dev typescript @types/node @types/node-forge @types/express jest @types/jest ts-jest
   ```

2. **Create tsconfig.json** (strict mode)
   ```json
   {
     "compilerOptions": {
       "target": "ES2022",
       "module": "commonjs",
       "strict": true,
       "esModuleInterop": true,
       "outDir": "./dist"
     }
   }
   ```

3. **Create directory structure**
   ```
   src/
   ├── index.ts              # Main entry (HTTP API + cron)
   ├── cert-parser.ts        # X.509 .p12 certificate parsing (node-forge)
   ├── cert-validator.ts     # Certificate validation logic
   ├── repository.ts         # PostgreSQL certificate inventory
   ├── expiration-monitor.ts # Daily expiration checks
   ├── cert-deployer.ts      # Deploy certificates (SOPS + age)
   ├── api.ts                # HTTP REST API (upload, list, deploy)
   ├── alerting.ts           # Expiration alerts (notification-service)
   └── observability.ts      # Metrics, logs, traces (TODO-008)
   tests/
   ├── setup.ts
   ├── fixtures/
   │   └── test-certificate.p12  # Test FINA demo certificate
   ├── unit/
   │   ├── cert-parser.test.ts
   │   ├── cert-validator.test.ts
   │   ├── expiration-monitor.test.ts
   │   └── observability.test.ts
   └── integration/
       ├── api.test.ts
       └── cert-deployment.test.ts
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 3)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 4+ Prometheus metrics (see README.md Section 8)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry)
   - No PII in certificates (public data only)

2. **Implement cert-parser.ts** (X.509 certificate parsing)
   - `parseCertificate(p12Buffer: Buffer, password: string): CertificateInfo`
   - Use node-forge library:
     ```typescript
     import forge from 'node-forge';

     function parseCertificate(p12Buffer: Buffer, password: string) {
       const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
       const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

       const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
       const cert = certBags[forge.pki.oids.certBag][0].cert;

       return {
         subject_dn: cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', '),
         serial_number: cert.serialNumber,
         not_before: cert.validity.notBefore,
         not_after: cert.validity.notAfter,
         issuer: cert.issuer.getField('CN').value
       };
     }
     ```
   - Extract: subject DN, serial number, issuer, validity dates

3. **Implement cert-validator.ts** (Certificate validation)
   - `validateCertificate(cert: CertificateInfo): string[]`
   - Validation rules:
     - Not yet valid (not_before > now)
     - Already expired (not_after < now)
     - Not issued by FINA (`issuer !== 'Fina RDC 2015 CA'`)
     - Invalid serial number format
   - Return array of error messages (empty = valid)

4. **Implement repository.ts** (PostgreSQL operations)
   - Connection pool (min: 10, max: 50)
   - `saveCertificate(cert: Certificate): Promise<void>`
   - `getAllCertificates(): Promise<Certificate[]>`
   - `getAllActiveCertificates(): Promise<Certificate[]>`
   - `getExpiringCertificates(daysThreshold: number): Promise<Certificate[]>`
   - `updateCertificateStatus(certId: string, status: string): Promise<void>`

5. **Implement expiration-monitor.ts** (Daily expiration checks)
   - `checkCertificateExpiration(): Promise<void>`
   - Run daily via node-cron (9 AM)
   - For each active certificate:
     - Calculate days until expiry
     - Alert levels: 30, 14, 7, 1 days
     - Update status: `active` → `expiring_soon` → `expired`
   - Send alerts via notification-service:
     - 30 days: INFO email to admins
     - 14 days: WARNING email + Slack notification
     - 7 days: CRITICAL email + page on-call
     - 1 day: URGENT page + block new submissions
   - Metrics: Track expiring certificates (Prometheus)

6. **Implement cert-deployer.ts** (Certificate deployment)
   - `deployCertificate(certPath: string, password: string): Promise<void>`
   - Steps:
     1. Encrypt certificate with SOPS + age
     2. Copy to `/etc/eracun/secrets/certs/fina-{env}-{timestamp}.p12.enc`
     3. Update digital-signature-service configuration
     4. Reload digital-signature-service (systemctl reload)
     5. Verify new certificate is active (test signature)
   - Security:
     - Store .p12 passwords encrypted (SOPS + age)
     - Never log certificate contents or passwords
     - Restrict file permissions (600, owner: eracun user)

7. **Implement alerting.ts** (Notification logic)
   - `sendExpirationAlert(cert: Certificate, severity: string, daysUntilExpiry: number)`
   - POST to notification-service
   - Alert templates:
     - `certificate_expiring_30days.html`
     - `certificate_expiring_7days.html`
     - `certificate_expired.html`

8. **Implement api.ts** (HTTP REST API)
   - Express server (port 8087)
   - Endpoints:
     - GET `/api/v1/certificates` - List all certificates
     - GET `/api/v1/certificates/:id` - Get certificate details
     - POST `/api/v1/certificates/upload` - Upload new certificate (.p12 file)
     - DELETE `/api/v1/certificates/:id/revoke` - Revoke certificate
     - POST `/api/v1/certificates/:id/deploy` - Deploy certificate
     - GET `/api/v1/certificates/expiring` - List expiring certificates
   - Authentication: JWT validation (from admin-portal-api)

9. **Implement index.ts** (Main entry point)
   - Start HTTP API server
   - Start cron job (daily expiration check at 9 AM)
   - Start Prometheus metrics endpoint (port 9095)
   - Health check endpoint (GET /health, GET /ready)
   - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 3-4)

1. **Create test fixtures**
   - `tests/fixtures/test-certificate.p12` (FINA demo certificate)
   - Mock notification-service (HTTP)
   - Testcontainers for PostgreSQL

2. **Write unit tests** (70% of suite)
   - `cert-parser.test.ts`: X.509 parsing (valid, invalid, wrong password)
   - `cert-validator.test.ts`: Validation rules (expired, not FINA, etc.)
   - `expiration-monitor.test.ts`: Alert triggers (30/14/7/1 days)
   - `observability.test.ts`: Metrics, logging
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `api.test.ts`: All 6 HTTP endpoints
   - `cert-deployment.test.ts`: Upload → parse → store → deploy

4. **Run tests**
   ```bash
   npm test -- --coverage
   ```
   - **MUST achieve 85%+ coverage** (enforced in jest.config.js)

### Phase 4: Documentation (Day 4-5)

1. **Create RUNBOOK.md** (operations guide)
   - Copy structure from `/services/schematron-validator/RUNBOOK.md`
   - Sections: Deployment, Monitoring, Common Issues, Troubleshooting, Disaster Recovery
   - Scenarios:
     - Certificate expires without renewal
     - Certificate revoked by FINA
     - Certificate upload fails (invalid, wrong password)
     - Deployment to digital-signature-service fails
     - FINA renewal process (manual steps)
   - Minimum 10 operational scenarios documented

2. **Create .env.example**
   - All environment variables documented
   - Include: DATABASE_URL, CERT_DIRECTORY, SOPS_AGE_KEY_PATH, NOTIFICATION_SERVICE_URL

3. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image

4. **Create systemd unit file** (`cert-lifecycle-manager.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - InaccessiblePaths: `/etc/eracun/.age-key` (hide encryption keys)
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

5. **Create completion report**
   - File: `/docs/reports/{date}-cert-lifecycle-manager-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 5)

1. **Commit all work**
   ```bash
   git add services/cert-lifecycle-manager/
   git commit -m "feat(cert-lifecycle-manager): implement FINA certificate lifecycle management"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/cert-lifecycle-manager-{your-session-id}
   ```

---

## 5. QUALITY STANDARDS (Non-Negotiable)

### 5.1 Code Quality

- ✅ **TypeScript strict mode** (no `any` types)
- ✅ **ESLint + Prettier** compliant
- ✅ **85%+ test coverage** (enforced in jest.config.js)
- ✅ **All errors explicitly handled** (no swallowed exceptions)

### 5.2 Security

- ✅ **No secrets in code** (use environment variables)
- ✅ **Certificate passwords encrypted** (SOPS + age)
- ✅ **Never log certificate contents** (security risk)
- ✅ **Never log .p12 passwords** (critical security violation)
- ✅ **File permissions: 600** (only eracun user can read)
- ✅ **systemd security hardening** (ProtectSystem=strict, InaccessiblePaths for keys)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **4+ Prometheus metrics**:
  - `certificates_expiring_count` (Gauge, labels: days_until_expiry)
  - `certificate_expiration_alerts_total` (Counter, labels: severity)
  - `certificate_renewals_total` (Counter, labels: status)
  - `certificates_active` (Gauge, labels: cert_type)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - No PII (certificates are public data)

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling
  - Spans: parse_certificate, validate, store, deploy
  - Trace ID for each operation

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Certificate parsing:** <2 seconds
- ✅ **Daily expiration check:** <5 seconds (all certs)
- ✅ **API response:** <200ms

### 5.5 Testing

- ✅ **85%+ coverage** (jest.config.js threshold)
- ✅ **Unit tests:** 70% of suite
- ✅ **Integration tests:** 25% of suite
- ✅ **E2E tests:** 5% of suite (critical paths)
- ✅ **All tests pass** before committing

---

## 6. COMMON PITFALLS (Avoid These)

❌ **DON'T:**
- Use `.clear()` on Prometheus registry (use `.resetMetrics()` in tests)
- Log certificate passwords (critical security violation)
- Log certificate contents (security risk)
- Skip certificate validation (allows invalid certs)
- Store unencrypted certificates in git (use SOPS + age)
- Ignore expiration warnings (blocks all invoice processing)
- Skip FINA issuer validation (allows non-FINA certs)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test expiration monitoring thoroughly (all 4 alert levels)
- Test certificate parsing (valid, invalid, wrong password)
- Document FINA renewal process in RUNBOOK
- Create comprehensive completion report
- Use SOPS + age for certificate encryption

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] Parse X.509 .p12 certificates (node-forge)
- [ ] Track certificates in PostgreSQL inventory
- [ ] Daily expiration checks (cron)
- [ ] Multi-level alerts (30/14/7/1 days)
- [ ] Certificate upload API (admin portal)
- [ ] Deploy certificates to digital-signature-service
- [ ] Encrypt certificates with SOPS + age
- [ ] Certificate validation (FINA issuer, expiry dates)

### 7.2 Non-Functional Requirements
- [ ] Certificate parsing: <2s (benchmarked)
- [ ] Expiration check: <5s (verified)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 4+ Prometheus metrics implemented
- [ ] Security: SOPS + age encryption, systemd hardening applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] Test FINA demo certificate in `tests/fixtures/`
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `cert-lifecycle-manager.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide, FINA renewal process)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/cert-lifecycle-manager-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/CROATIAN_COMPLIANCE.md` - FINA certificate requirements
   - `/docs/adr/002-secrets-management-sops-age.md` - Certificate encryption

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements

4. **Dependencies:**
   - This service has ZERO service dependencies (can implement immediately)
   - Only depends on PostgreSQL and notification-service (HTTP)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ Certificate parsing works (test .p12 file)
✅ Certificate validation works (FINA issuer, expiry)
✅ Daily expiration check works (cron)
✅ Expiration alerts sent (30/14/7/1 days)
✅ Certificate upload API works
✅ Certificate deployment works (SOPS + age)
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (parser, validator, observability)
**Day 2 End:** Repository + expiration monitor complete
**Day 3 End:** API + cert deployer complete
**Day 4 End:** All tests written and passing (85%+ coverage)
**Day 5 End:** Documentation complete, code committed & pushed

**If you're behind schedule:**
- Prioritize expiration monitoring (most critical feature)
- Certificate deployment can be manual initially
- Ensure observability compliance (non-negotiable)
- Ask for help if blocked >2 hours

---

**Status:** 🔴 Ready for Implementation
**Last Updated:** 2025-11-11
**Assigned To:** [Your AI Instance]
**Session ID:** [Your Session ID]

---

## FINAL REMINDER

**Read the specification (`README.md`) thoroughly before writing code.**

This CLAUDE.md provides workflow and context. The README.md provides technical details. Together, they contain everything you need to implement this service to production standards.

**Good luck!**
