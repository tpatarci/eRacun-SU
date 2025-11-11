# Certificate Lifecycle Manager Service - Specification

**Service Name:** `cert-lifecycle-manager`
**Layer:** Management (Layer 10)
**Complexity:** High (~2,200 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Single Responsibility

**Monitor FINA X.509 certificate expiration, trigger renewals, handle revocation, and distribute certificates to signing services.**

This service is **critical for uninterrupted invoice submission**. FINA certificates expire every 5 years (demo certificates: 1 year). This service:
- Monitors certificate expiration (alerts 30/14/7/1 days before)
- Automates renewal workflow (via FINA CMS API or manual process)
- Handles certificate revocation (immediate notification)
- Distributes renewed certificates to digital-signature-service
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

**Automated Renewal** (future enhancement if FINA provides API):
- Trigger renewal request 60 days before expiration
- Poll FINA API for renewal status
- Automatically download and deploy new certificate

---

## 4. Certificate Distribution

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

# Certificate Storage
CERT_DIRECTORY=/etc/eracun/secrets/certs
SOPS_AGE_KEY_PATH=/etc/eracun/.age-key

# Expiration Thresholds (days)
ALERT_THRESHOLD_INFO=30
ALERT_THRESHOLD_WARNING=14
ALERT_THRESHOLD_CRITICAL=7
ALERT_THRESHOLD_URGENT=1

# FINA CMS API (optional, for future automation)
FINA_CMS_URL=https://cms.fina.hr/api
FINA_CMS_API_KEY=<encrypted>

# Notification Service
NOTIFICATION_SERVICE_URL=http://notification-service:8080

# PostgreSQL
DATABASE_URL=postgresql://cert_manager:password@localhost:5432/eracun

# Cron Schedule
EXPIRATION_CHECK_CRON=0 9 * * *  # Daily at 9 AM
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

- [ ] Parse X.509 .p12 certificates (node-forge)
- [ ] Track certificates in PostgreSQL inventory
- [ ] Daily expiration checks (cron)
- [ ] Multi-level alerts (30/14/7/1 days)
- [ ] Certificate upload API (admin portal)
- [ ] Deploy certificates to digital-signature-service
- [ ] Encrypt certificates with SOPS + age
- [ ] Test coverage 85%+
- [ ] 4+ Prometheus metrics

---

**Status:** 🔴 Ready for Implementation
**Estimate:** 4-5 days | **Complexity:** High (~2,200 LOC)
**Dependencies:** None

---

**Last Updated:** 2025-11-11
