# Improvement Plan: Add Certificate Caching to Digital Signature Service

**Priority:** 🟠 **HIGH**
**Service:** `services/digital-signature-service/`
**Issue ID:** 4.5
**Status:** Performance Bottleneck
**Effort Estimate:** 1 hour
**Impact:** Eliminates 10,000 disk reads/day (5-10ms per signature operation)

---

## Problem Statement

The `digital-signature-service` loads the FINA X.509 certificate from disk **every time a signature is generated**. At 10,000 invoices/hour throughput, this causes 10,000 disk I/O operations per hour.

**Current Code** (lines 69-76, `services/digital-signature-service/src/certificate-parser.ts`):

```typescript
async function loadCertificateFromFile(
  certPath: string,
  password: string
): Promise<ParsedCertificate> {
  // Reads file from disk EVERY TIME THIS IS CALLED
  const certBuffer = await fs.readFile(certPath);
  const parsed = parseCertificate(certBuffer, password);
  return parsed;
}
```

### Performance Impact

- **Disk Reads:** 10,000 invoices/hour = ~2.7 reads/second from disk
- **Latency:** 5-10ms per file read adds directly to signature operation latency
- **Throughput Loss:** At 100ms average signature time, disk I/O is 5-10% of total latency
- **At 100k invoices/hour:** 20,000+ disk reads/hour becomes bottleneck

### Why This Matters

FINA submission is latency-sensitive:
- **Customer SLA:** "How fast can I submit an invoice?" = signature time + SOAP submission time
- **System Throughput:** Parallel signatures limited by disk I/O contention
- **Cost:** Unnecessary disk I/O on production instances

---

## Solution Design

### Pattern: Lazy-Load Certificate at Startup, Reuse for Lifetime

Load certificate once when service starts, cache in memory, reuse for every signature operation.

```typescript
class DigitalSignatureService {
  private cachedCertificate: ParsedCertificate | null = null;

  async initialize(certPath: string, password: string): Promise<void> {
    logger.info('Loading certificate', { path: certPath });

    try {
      // Load once at startup
      this.cachedCertificate = await loadCertificateFromFile(certPath, password);

      logger.info('Certificate loaded', {
        subject: this.cachedCertificate.subject,
        validFrom: this.cachedCertificate.validFrom,
        validUntil: this.cachedCertificate.validUntil,
      });

      // Emit metric for monitoring
      certificateLoadedGauge.set(1);
    } catch (err) {
      logger.error({...}, 'Failed to load certificate');
      certificateLoadedGauge.set(0);
      throw err;
    }
  }

  async signInvoice(invoice: UBLInvoice): Promise<SignedInvoice> {
    if (!this.cachedCertificate) {
      throw new Error('Certificate not loaded - call initialize() first');
    }

    // Reuse cached certificate - no disk I/O
    const signedXml = await this.signXMLWithCertificate(
      invoice.xmlContent,
      this.cachedCertificate
    );

    return { ...invoice, signedXml };
  }
}
```

### Additional: Monitor Certificate Expiration

While we have the certificate loaded, monitor expiration and alert before it expires:

```typescript
private monitorCertificateExpiration(): void {
  const checkInterval = 3600000; // 1 hour

  setInterval(() => {
    if (!this.cachedCertificate) {
      return;
    }

    const now = new Date();
    const expiresIn = this.cachedCertificate.validUntil.getTime() - now.getTime();
    const daysUntilExpiration = Math.ceil(expiresIn / (1000 * 60 * 60 * 24));

    // Metrics for monitoring
    certificateExpirationDaysGauge.set(daysUntilExpiration);

    // Alerts
    if (daysUntilExpiration <= 7) {
      logger.warn('Certificate expiring soon', { days: daysUntilExpiration });
      certificateExpirationAlert.inc();
    } else if (daysUntilExpiration <= 0) {
      logger.error('Certificate has expired!');
      certificateExpiredAlert.inc();
    }
  }, checkInterval);
}
```

---

## Implementation Steps

### Step 1: Update Certificate Parser

**File:** `services/digital-signature-service/src/certificate-parser.ts`

Replace the `loadCertificateFromFile()` function to add logging:

```typescript
export async function loadCertificateFromFile(
  certPath: string,
  password: string
): Promise<ParsedCertificate> {
  const startTime = Date.now();

  const certBuffer = await fs.readFile(certPath);
  const parsed = parseCertificate(certBuffer, password);

  const duration = Date.now() - startTime;
  logger.info('Certificate loaded from disk', {
    path: certPath,
    durationMs: duration,
    subject: parsed.subject,
  });

  return parsed;
}
```

### Step 2: Add Service Initialization

**File:** `services/digital-signature-service/src/index.ts`

Modify to call `initialize()` on startup:

```typescript
const service = new DigitalSignatureService();

const app = express();

// Health check endpoint (before certificate loading)
app.get('/health/ready', (req, res) => {
  // Not ready until certificate loaded
  if (service.isCertificateLoaded()) {
    res.status(200).json({ status: 'ready' });
  } else {
    res.status(503).json({ status: 'starting' });
  }
});

// Initialize certificate on startup
const certPath = process.env.FINA_CERT_PATH || '/etc/eracun/fina-cert.p12';
const certPassword = process.env.FINA_CERT_PASSWORD || '';

service
  .initialize(certPath, certPassword)
  .then(() => {
    logger.info('Service initialized, certificate loaded');
    app.listen(PORT, () => {
      logger.info(`Digital signature service listening on port ${PORT}`);
    });
  })
  .catch(err => {
    logger.error({...}, 'Failed to initialize service');
    process.exit(1);
  });
```

### Step 3: Implement Digital Signature Service

**File:** `services/digital-signature-service/src/digital-signature-service.ts` (NEW or UPDATED)

```typescript
export class DigitalSignatureService {
  private cachedCertificate: ParsedCertificate | null = null;
  private certLoadedAt: Date | null = null;

  async initialize(certPath: string, password: string): Promise<void> {
    logger.info('Initializing digital signature service', { certPath });

    try {
      this.cachedCertificate = await loadCertificateFromFile(certPath, password);
      this.certLoadedAt = new Date();

      logger.info('Certificate cached in memory', {
        subject: this.cachedCertificate.subject,
        validFrom: this.cachedCertificate.validFrom,
        validUntil: this.cachedCertificate.validUntil,
      });

      // Metrics
      certificateLoadedGauge.set(1);
      certificateExpirationDaysGauge.set(
        Math.ceil(
          (this.cachedCertificate.validUntil.getTime() - Date.now()) /
          (1000 * 60 * 60 * 24)
        )
      );

      // Start monitoring expiration
      this.monitorCertificateExpiration();
    } catch (err) {
      logger.error({ error: err }, 'Failed to load certificate');
      certificateLoadedGauge.set(0);
      throw err;
    }
  }

  isCertificateLoaded(): boolean {
    return this.cachedCertificate !== null;
  }

  async signInvoice(invoiceXml: string): Promise<string> {
    if (!this.cachedCertificate) {
      throw new Error('Certificate not loaded. Initialize service first.');
    }

    const startTime = Date.now();

    try {
      // Use cached certificate (no disk I/O)
      const signedXml = await this.signXMLWithCertificate(
        invoiceXml,
        this.cachedCertificate
      );

      const duration = Date.now() - startTime;
      signatureDuration.observe({ operation: 'sign_invoice' }, duration);

      logger.debug('Invoice signed', {
        durationMs: duration,
        xmlSize: invoiceXml.length,
      });

      return signedXml;
    } catch (err) {
      logger.error({ error: err }, 'Failed to sign invoice');
      signatureErrors.inc({ error_type: 'signing_failed' });
      throw err;
    }
  }

  async generateZKI(invoiceData: FINAInvoiceData): Promise<string> {
    if (!this.cachedCertificate) {
      throw new Error('Certificate not loaded. Initialize service first.');
    }

    const startTime = Date.now();

    try {
      // Use cached certificate for ZKI generation
      const zki = await this.computeZKI(invoiceData, this.cachedCertificate);

      const duration = Date.now() - startTime;
      signatureDuration.observe({ operation: 'generate_zki' }, duration);

      return zki;
    } catch (err) {
      logger.error({ error: err }, 'Failed to generate ZKI');
      signatureErrors.inc({ error_type: 'zki_generation_failed' });
      throw err;
    }
  }

  private monitorCertificateExpiration(): void {
    if (!this.cachedCertificate) return;

    const checkInterval = 60 * 60 * 1000; // 1 hour

    const interval = setInterval(() => {
      if (!this.cachedCertificate) {
        clearInterval(interval);
        return;
      }

      const now = new Date();
      const expiresIn = this.cachedCertificate.validUntil.getTime() - now.getTime();
      const daysUntilExpiration = Math.ceil(expiresIn / (1000 * 60 * 60 * 24));

      // Update metric
      certificateExpirationDaysGauge.set(daysUntilExpiration);

      // Alert if expiring soon
      if (daysUntilExpiration <= 30 && daysUntilExpiration > 0) {
        logger.warn('Certificate expiring soon', {
          days: daysUntilExpiration,
          expiresAt: this.cachedCertificate.validUntil,
        });
      } else if (daysUntilExpiration <= 0) {
        logger.error('Certificate has expired!', {
          expiresAt: this.cachedCertificate.validUntil,
        });
        certificateExpiredAlert.inc();
      }
    }, checkInterval);
  }

  private async signXMLWithCertificate(
    xmlContent: string,
    certificate: ParsedCertificate
  ): Promise<string> {
    // Use xmldsig-signer with cached certificate
    const signer = new XMLDSigSigner(certificate);
    return signer.signDocument(xmlContent);
  }

  private async computeZKI(
    invoiceData: FINAInvoiceData,
    certificate: ParsedCertificate
  ): Promise<string> {
    // Compute ZKI (MD5 hash signed with private key)
    const dataToHash = `${invoiceData.brojRacuna}${invoiceData.datumRacuna}`;
    const md5Hash = crypto.createHash('md5').update(dataToHash).digest();

    // Sign with cached certificate's private key
    const signature = crypto.sign(
      'sha256',
      md5Hash,
      {
        key: certificate.privateKeyPEM,
        passphrase: process.env.FINA_CERT_PASSWORD,
      }
    );

    return signature.toString('hex');
  }
}
```

### Step 4: Add Metrics

**File:** `services/digital-signature-service/src/metrics.ts`

Add:
```typescript
export const certificateLoadedGauge = new Gauge({
  name: 'certificate_loaded',
  help: '1 if certificate is loaded and available, 0 otherwise',
});

export const certificateExpirationDaysGauge = new Gauge({
  name: 'certificate_expiration_days',
  help: 'Days remaining until certificate expiration',
});

export const certificateExpiredAlert = new Counter({
  name: 'certificate_expired_total',
  help: 'Number of times certificate expiration was detected',
});

export const certificateExpirationAlert = new Counter({
  name: 'certificate_expiration_warning_total',
  help: 'Number of times certificate expiration warning was issued',
});

export const signatureDuration = new Histogram({
  name: 'signature_duration_ms',
  help: 'Time to generate signature',
  labelNames: ['operation'], // 'sign_invoice', 'generate_zki'
  buckets: [10, 50, 100, 200, 500, 1000],
});

export const signatureErrors = new Counter({
  name: 'signature_errors_total',
  help: 'Signature generation errors',
  labelNames: ['error_type'],
});
```

### Step 5: Add Tests

**File:** `services/digital-signature-service/src/digital-signature-service.spec.ts`

```typescript
describe('DigitalSignatureService', () => {
  let service: DigitalSignatureService;

  beforeEach(() => {
    service = new DigitalSignatureService();
  });

  it('should load certificate once on initialization', async () => {
    const readFileSpy = jest.spyOn(fs, 'readFile');

    await service.initialize(CERT_PATH, CERT_PASSWORD);

    // Should have read file once
    expect(readFileSpy).toHaveBeenCalledTimes(1);

    readFileSpy.mockRestore();
  });

  it('should use cached certificate for all signatures', async () => {
    await service.initialize(CERT_PATH, CERT_PASSWORD);

    const readFileSpy = jest.spyOn(fs, 'readFile');

    // Sign multiple invoices
    await service.signInvoice(INVOICE_XML);
    await service.signInvoice(INVOICE_XML);
    await service.signInvoice(INVOICE_XML);

    // Should not have read file again
    expect(readFileSpy).not.toHaveBeenCalled();

    readFileSpy.mockRestore();
  });

  it('should track signature duration metrics', async () => {
    await service.initialize(CERT_PATH, CERT_PASSWORD);

    const observeSpy = jest.spyOn(signatureDuration, 'observe');

    await service.signInvoice(INVOICE_XML);

    expect(observeSpy).toHaveBeenCalledWith(
      { operation: 'sign_invoice' },
      expect.any(Number)
    );
  });

  it('should reject signing if certificate not loaded', async () => {
    expect(service.signInvoice(INVOICE_XML)).rejects.toThrow(
      'Certificate not loaded'
    );
  });

  it('should monitor certificate expiration', async () => {
    await service.initialize(CERT_PATH, CERT_PASSWORD);

    expect(service.isCertificateLoaded()).toBe(true);
    expect(certificateLoadedGauge.values()).toContain({ labels: {}, value: 1 });
  });
});
```

---

## Validation Checklist

- [ ] Certificate loaded once on service startup
- [ ] No disk I/O during signature operations
- [ ] Metrics track certificate expiration date
- [ ] Alerts if certificate expiring within 30 days
- [ ] Service fails to start if certificate missing (prevents boot with bad config)
- [ ] Tests verify no redundant file reads
- [ ] Signature duration metric reduces by 5-10ms per operation

---

## Acceptance Criteria

✅ **Performance:** Certificate loaded once, no disk I/O per signature
✅ **Reliability:** Certificate expiration monitored and alerted
✅ **Observability:** Metrics for certificate status, expiration, signature duration
✅ **Tests:** Verify single certificate load, no redundant reads
✅ **Backward Compatible:** Signature output unchanged

---

## Performance Impact

**Before Optimization:**
- 10,000 invoices/hour = 10,000 disk reads/hour
- 5-10ms per read = 50-100 seconds of I/O per hour
- Signature latency: ~100ms per invoice

**After Optimization:**
- 1 disk read at startup
- 0ms per signature (cached in memory)
- Signature latency: ~90-95ms per invoice
- **Improvement:** 5-10% latency reduction, no disk I/O in critical path

---

## Deployment Notes

**Rollout Strategy:**
1. Merge to main after code review
2. Deploy to staging
3. Monitor `certificate_loaded` metric (should be 1)
4. Monitor `signature_duration_ms` (should decrease by ~10%)
5. Deploy to production
6. Add alerting on `certificate_expiration_days < 30`

**Configuration:**
```bash
# In systemd service file or .env
FINA_CERT_PATH=/etc/eracun/fina-cert.p12
FINA_CERT_PASSWORD=<secret from SOPS>
```

---

## Related Issues

- Issue 4.1: String slicing for XML manipulation (fragile)
- Issue 4.2: Hard-coded XPath for signature insertion
- Issue 4.3: Redundant XML parsing

---

**Owner:** Codex
**Due Date:** Before production launch
**Blocked By:** None
**Blocks:** None (performance improvement)

