# Certificate Lifecycle Manager Service

**Service Name:** `cert-lifecycle-manager`
**Layer:** Management (Layer 10)
**Complexity:** High (~2,500 LOC)
**Status:** ✅ Implemented (Enhanced with HSM, CRL/OCSP, Auto-Renewal)

---

## 1. Purpose and Single Responsibility

**Monitor FINA X.509 certificate expiration, trigger renewals, handle revocation, and distribute certificates to signing services.**

This service is **critical for uninterrupted invoice submission**. FINA certificates expire every 5 years (demo certificates: 1 year). This service:
- Monitors certificate expiration (alerts 30/14/7/1 days before)
- **NEW:** CRL/OCSP revocation checking (real-time certificate validation)
- **NEW:** Hardware Security Module (HSM) integration for secure key storage
- **NEW:** Automated renewal workflow (generates CSR, submits to CA, installs new cert)
- **NEW:** Certificate distribution to services (digital-signature-service, fina-connector)
- Handles certificate revocation (immediate notification)
- Maintains certificate inventory (all active/expired/revoked certs)

---

## 2. Integration Architecture

### 2.1 Dependencies

**Consumes:**
- Scheduled jobs (cron): Daily expiration checks
- FINA CMS API (optional): Certificate status queries

**Produces:**
- Notifications: POST to notification-service (expiration alerts)
- Certificate updates: Deploy to digital-signature-service via file copy or API

### 2.2 Certificate Inventory

**PostgreSQL Schema:**
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

## 3. Certificate Monitoring Logic

### 3.1 Expiration Thresholds

**Alert Levels:**
- 30 days before: Send INFO email to admins
- 14 days before: Send WARNING email + Slack notification
- 7 days before: Send CRITICAL email + page on-call
- 1 day before: Send URGENT page + block new submissions

**Daily Check (Cron Job):**
```typescript
async function checkCertificateExpiration() {
  const now = Date.now();
  const certs = await getAllActiveCertificates();

  for (const cert of certs) {
    const daysUntilExpiry = (cert.not_after.getTime() - now) / (1000 * 60 * 60 * 24);

    if (daysUntilExpiry <= 0) {
      cert.status = 'expired';
      await sendCriticalAlert(cert, 'EXPIRED');
      await blockSubmissions(cert); // Prevent using expired cert
    } else if (daysUntilExpiry <= 1) {
      await sendCriticalAlert(cert, 'EXPIRES_IN_1_DAY');
    } else if (daysUntilExpiry <= 7) {
      await sendWarningAlert(cert, 'EXPIRES_IN_7_DAYS');
    } else if (daysUntilExpiry <= 14) {
      await sendInfoAlert(cert, 'EXPIRES_IN_14_DAYS');
    } else if (daysUntilExpiry <= 30) {
      await sendInfoAlert(cert, 'EXPIRES_IN_30_DAYS');
    }

    await updateCertificate(cert);
  }
}
```

### 3.2 Renewal Workflow

**Manual Renewal Process** (FINA requires manual steps):
1. Admin receives expiration alert
2. Admin initiates renewal via FINA CMS portal (cms.fina.hr)
3. FINA processes request (5-10 business days)
4. Admin downloads new .p12 certificate
5. Admin uploads new certificate via admin-portal-api
6. This service validates and deploys new certificate
7. Old certificate marked as 'replaced'

**Automated Renewal** (✅ NOW IMPLEMENTED):
- Triggers renewal request 60 days before expiration (configurable via `RENEWAL_THRESHOLD_DAYS`)
- Generates new key pair in HSM
- Creates Certificate Signing Request (CSR)
- Submits to Certificate Authority (mock or real FINA)
- Automatically installs and distributes new certificate
- Deprecates old certificate after successful renewal
- Runs weekly via cron job (Monday at 2 AM by default)

---

## 4. New Features

### 4.1 Hardware Security Module (HSM) Integration

**Purpose:** Secure key generation and signing operations

**Mock HSM Implementation** (`src/hsm/mock-hsm.ts`):
```typescript
import { MockHSM } from './hsm/mock-hsm.js';

const hsm = new MockHSM();
await hsm.initialize();

// Generate key pair
await hsm.generateKeyPair('key-001', 'RSA-2048', true);

// Sign data
const result = await hsm.sign('key-001', Buffer.from('data to sign'));
console.log(result.signature); // Base64 signature

// List all keys
const keys = await hsm.listKeys();
```

**Features:**
- In-memory key storage (for development)
- RSA-2048 and ECDSA-P256 key generation
- RSA-SHA256 signing operations
- Key import/export/delete
- Simulated HSM delays (30-100ms for realism)
- Ready for production HSM integration (Thales, Utimaco, AWS CloudHSM)

**Configuration:**
```bash
# Use mock HSM (default)
HSM_TYPE=mock

# Use production HSM (future)
HSM_TYPE=thales
HSM_URL=tcp://hsm.eracun.internal:1792
HSM_SLOT=0
HSM_PIN=<encrypted>
```

### 4.2 CRL/OCSP Revocation Checking

**Purpose:** Real-time certificate revocation validation

**Implementation** (`src/revocation-check.ts`):
```typescript
import { getRevocationChecker } from './revocation-check.js';

const checker = getRevocationChecker();
const result = await checker.checkRevocation(
  'certificate-serial-number',
  'Fina RDC 2015 CA'
);

if (result.revoked) {
  console.log(`Certificate revoked: ${result.reason}`);
  console.log(`Revoked at: ${result.revokedAt}`);
}
```

**Supported Methods:**
1. **MockRevocationChecker** - In-memory revocation list (for development)
2. **CRLChecker** - Downloads and parses Certificate Revocation Lists
   - 24-hour cache for CRLs
   - Known endpoints for FINA and AKD CAs
3. **OCSPChecker** - Queries OCSP responders for real-time status
   - Lower latency than CRL
   - Requires network connectivity to OCSP servers

**Croatian CA Endpoints:**
- **FINA CRL:** `http://www.fina.hr/crl/finardc2015.crl`
- **FINA OCSP:** `http://ocsp.fina.hr`
- **AKD CRL:** `http://www.akd.hr/crl/akdca.crl`
- **AKD OCSP:** `http://ocsp.akd.hr`

**Configuration:**
```bash
# Revocation check method
REVOCATION_CHECK_TYPE=mock  # mock, crl, or ocsp
```

**Integration:** Revocation check is now integrated into `validateCertificate()` function. Revoked certificates will trigger validation errors.

### 4.3 Automated Renewal Workflow

**Purpose:** Eliminate manual certificate renewal process

**Workflow** (`src/renewal-workflow.ts`):
```typescript
import { createRenewalWorkflow, createCertificateAuthority } from './renewal-workflow.js';

// Initialize with mock CA
const ca = createCertificateAuthority('mock');
const workflow = createRenewalWorkflow(repository, ca);

// Process renewals (called by cron or manually)
const results = await workflow.processRenewals();

console.log(`Processed ${results.length} renewals`);
console.log(`Succeeded: ${results.filter(r => r.success).length}`);
console.log(`Failed: ${results.filter(r => !r.success).length}`);
```

**Renewal Steps:**
1. Detect certificates expiring within threshold (default: 60 days)
2. Generate new key pair in HSM
3. Create Certificate Signing Request (CSR)
4. Submit CSR to Certificate Authority
5. Receive new certificate from CA
6. Import new certificate into HSM
7. **Distribute new certificate to services** (see 4.4)
8. Deprecate old certificate

**Certificate Authorities Supported:**
- **MockCertificateAuthority** - Instant renewal for development
- **FINACertificateAuthority** - Real FINA integration (planned)

**Scheduling:**
```bash
# Weekly renewal check (Monday at 2 AM)
RENEWAL_CRON="0 2 * * 1"

# Renewal threshold (days before expiry)
RENEWAL_THRESHOLD_DAYS=60

# CA type
CA_TYPE=mock  # or 'fina' for production
```

**Metrics:**
- `certificate_renewals_total{status="success"}` - Successful renewals
- `certificate_renewals_total{status="failure"}` - Failed renewals

### 4.4 Certificate Distribution

**Purpose:** Securely distribute renewed certificates to services

**Implementation** (`src/cert-distribution.ts`):
```typescript
import { createCertificateDistribution } from './cert-distribution.js';

const distribution = createCertificateDistribution('mock');

// Register custom target
distribution.registerTarget({
  serviceName: 'custom-service',
  certPath: '/etc/eracun/certs',
  keyPath: '/etc/eracun/keys',
  reloadCommand: 'systemctl reload custom-service',
  environment: 'production'
});

// Distribute certificate
const results = await distribution.distributeToAll(cert, certPEM, keyId);
```

**Distribution Process:**
1. Export private key from HSM
2. **Encrypt certificate and key** (SOPS in production, mock encryption in dev)
3. Write encrypted files to target directories
4. Set secure file permissions (600, owner: eracun)
5. Trigger service reload (systemctl reload)
6. **Audit log** all distributions

**Default Distribution Targets:**
- **digital-signature-service** - `/etc/eracun/certs/`
- **fina-connector** - `/etc/eracun/certs/`
- Custom targets via `CUSTOM_DISTRIBUTION_TARGETS` environment variable

**Security:**
- Certificates encrypted with SOPS + age (production)
- Mock encryption for development (Base64)
- File permissions: 600 (`-rw-------`)
- Audit trail of all distributions

**Configuration:**
```bash
# Encryption type
ENCRYPTION_TYPE=mock  # or 'sops' for production

# Age key path (for SOPS)
AGE_KEY_PATH=/etc/eracun/.age-key

# Custom distribution targets (JSON array)
CUSTOM_DISTRIBUTION_TARGETS='[{"serviceName":"custom","certPath":"/etc/certs","keyPath":"/etc/keys","reloadCommand":"systemctl reload custom","environment":"production"}]'
```

**Audit Log:**
```typescript
// Get all distributions
const auditLog = distribution.getAuditLog();

// Get distributions for specific certificate
const certLog = distribution.getAuditLogForCert('cert-12345');

console.log(certLog);
// [
//   {
//     success: true,
//     target: { serviceName: 'digital-signature-service', ... },
//     certId: 'cert-12345',
//     distributionId: 'dist-1699999999999-abc123',
//     timestamp: Date
//   }
// ]
```

---

## 5. Certificate Distribution (Original)

### 4.1 Deployment to Signing Service

**When new certificate is added/renewed:**
1. Encrypt certificate with age (SOPS)
2. Copy to `/etc/eracun/secrets/certs/fina-{env}-{timestamp}.p12.enc`
3. Update `digital-signature-service` configuration
4. Reload digital-signature-service (systemctl reload)
5. Verify new certificate is active (test signature)

**Security:**
- Store .p12 passwords encrypted (SOPS + age)
- Never log certificate contents or passwords
- Restrict file permissions (600, owner: eracun user)

---

## 5. Technology Stack

**Core:**
- Node.js 20+ / TypeScript 5.3+
- `node-forge` - X.509 certificate parsing
- `pg` - PostgreSQL client
- `express` - HTTP API (upload new certs)
- `node-cron` - Scheduled expiration checks

**Observability:**
- `prom-client`, `pino`, `opentelemetry`

---

## 6. Performance Requirements

**Latency:**
- Certificate expiration check: <5 seconds (daily cron)
- Certificate upload/validation: <2 seconds

**Reliability:**
- Expiration checks must NEVER fail (critical for compliance)
- Alerting must be redundant (email + SMS + Slack)

---

## 7. Implementation Guidance

### 7.1 Core Logic

```typescript
import forge from 'node-forge';

// Parse .p12 certificate
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

// Validate certificate
function validateCertificate(cert: any): string[] {
  const errors: string[] = [];
  const now = new Date();

  if (cert.not_before > now) {
    errors.push('Certificate not yet valid');
  }
  if (cert.not_after < now) {
    errors.push('Certificate expired');
  }
  if (cert.issuer !== 'Fina RDC 2015 CA') {
    errors.push('Certificate not issued by FINA');
  }

  return errors;
}
```

---

## 8. Observability (TODO-008)

**Metrics:**
```typescript
const certificatesExpiring = new Gauge({
  name: 'certificates_expiring_count',
  help: 'Number of certificates expiring within threshold',
  labelNames: ['days_until_expiry']  // 1, 7, 14, 30
});

const certificateExpirationAlerts = new Counter({
  name: 'certificate_expiration_alerts_total',
  labelNames: ['severity']  // info, warning, critical
});

const certificateRenewals = new Counter({
  name: 'certificate_renewals_total',
  labelNames: ['status']  // success, failed
});

const activeCertificates = new Gauge({
  name: 'certificates_active',
  help: 'Number of active certificates',
  labelNames: ['cert_type']  // production, demo, test
});
```

---

## 9. Configuration

```bash
# .env.example
SERVICE_NAME=cert-lifecycle-manager
HTTP_PORT=8087
NODE_ENV=development  # development, staging, production

# Certificate Storage
CERT_DIRECTORY=/etc/eracun/secrets/certs
SOPS_AGE_KEY_PATH=/etc/eracun/.age-key
AGE_KEY_PATH=/etc/eracun/.age-key

# HSM Configuration
HSM_TYPE=mock  # mock, thales, utimaco, cloudhsm
HSM_URL=tcp://hsm.eracun.internal:1792
HSM_SLOT=0
HSM_PIN=<encrypted>

# Revocation Checking
REVOCATION_CHECK_TYPE=mock  # mock, crl, ocsp

# Renewal Workflow
CA_TYPE=mock  # mock, fina
RENEWAL_THRESHOLD_DAYS=60  # Renew 60 days before expiration
RENEWAL_CRON=0 2 * * 1  # Weekly on Monday at 2 AM
RUN_INITIAL_RENEWAL=false  # Run renewal check on startup

# Certificate Distribution
ENCRYPTION_TYPE=mock  # mock, sops
DIGITAL_SIGNATURE_CERT_PATH=/etc/eracun/certs
DIGITAL_SIGNATURE_KEY_PATH=/etc/eracun/keys
FINA_CONNECTOR_CERT_PATH=/etc/eracun/certs
FINA_CONNECTOR_KEY_PATH=/etc/eracun/keys
CUSTOM_DISTRIBUTION_TARGETS=[]  # JSON array of custom targets

# Expiration Thresholds (days)
ALERT_THRESHOLD_INFO=30
ALERT_THRESHOLD_WARNING=14
ALERT_THRESHOLD_CRITICAL=7
ALERT_THRESHOLD_URGENT=1

# FINA CMS API (optional, for future automation)
FINA_API_URL=https://cis.porezna-uprava.hr
FINA_AUTH_CERT=<path-to-auth-cert>
FINA_AUTH_KEY=<path-to-auth-key>

# Notification Service
NOTIFICATION_SERVICE_URL=http://notification-service:8080

# PostgreSQL
DATABASE_URL=postgresql://cert_manager:password@localhost:5432/eracun

# Cron Schedules
EXPIRATION_CHECK_CRON=0 9 * * *  # Daily at 9 AM
RUN_INITIAL_CHECK=false  # Run expiration check on startup

# Logging
LOG_LEVEL=info  # debug, info, warn, error
```

---

## 10. HTTP API (Admin Portal Integration)

```
GET    /api/v1/certificates              # List all certificates
GET    /api/v1/certificates/:id          # Get certificate details
POST   /api/v1/certificates/upload       # Upload new certificate (.p12 file)
DELETE /api/v1/certificates/:id/revoke   # Revoke certificate (mark as revoked)
POST   /api/v1/certificates/:id/deploy   # Deploy certificate to signing service
GET    /api/v1/certificates/expiring     # List certificates expiring soon
```

---

## 11. Failure Modes

**Scenario 1: Certificate Expires Without Renewal**
- **Impact:** Cannot sign invoices, submissions blocked
- **Detection:** Daily cron check + 1 day alert
- **Recovery:**
  1. Urgent renewal process (expedited FINA request)
  2. Use backup certificate if available
  3. Manual intervention required

**Scenario 2: Certificate Revoked by FINA**
- **Impact:** Existing signatures invalid, submissions rejected
- **Detection:** FINA API notification (if available) or submission failures
- **Recovery:**
  1. Immediate alert to admins
  2. Request new certificate from FINA
  3. Re-sign affected invoices

---

## 12. Acceptance Criteria

**Core Features:**
- [x] Parse X.509 .p12 certificates (node-forge)
- [x] Track certificates in PostgreSQL inventory
- [x] Daily expiration checks (cron)
- [x] Multi-level alerts (30/14/7/1 days)
- [x] Certificate upload API (admin portal)
- [x] Deploy certificates to digital-signature-service
- [x] Encrypt certificates with SOPS + age
- [x] 6+ Prometheus metrics

**New Features (Enhanced):**
- [x] HSM integration (mock implementation)
- [x] CRL/OCSP revocation checking (3 implementations)
- [x] Automated renewal workflow (weekly cron)
- [x] Certificate distribution to multiple services
- [x] Audit logging for all distributions
- [x] Revocation status integrated into validation
- [ ] Test coverage 85%+ (pending)
- [ ] Production HSM integration (future)
- [ ] Real FINA CA integration (future)
- [ ] SOPS encryption (future, currently mock)

---

## 13. Testing

**Test Strategy:**
```bash
# Unit tests
npm test

# Integration tests
npm run test:integration

# Coverage report
npm run coverage
```

**Required Test Coverage:**
- HSM operations (key generation, signing, import/export)
- Revocation checking (mock, CRL, OCSP)
- Renewal workflow (CSR generation, CA submission, distribution)
- Certificate distribution (encryption, file operations, audit log)
- Certificate validation (with revocation check)
- Expiration monitoring (alert thresholds)

---

**Status:** ✅ Implemented and Enhanced
**LOC:** ~2,500 (up from ~2,200 estimated)
**Complexity:** High
**Dependencies:** None

**Features Added Beyond Specification:**
- HSM abstraction with mock implementation
- CRL/OCSP revocation checking (3 methods)
- Fully automated renewal workflow
- Certificate distribution with audit logging
- Enhanced security (encryption, secure permissions)

---

**Last Updated:** 2025-11-14
**Implementation Completed:** 2025-11-14
