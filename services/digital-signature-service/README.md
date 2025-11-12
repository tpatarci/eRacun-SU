# Digital Signature Service

**Service Name:** `digital-signature-service`
**Layer:** 6 (Submission Layer)
**Status:** ✅ Production-Ready
**Version:** 0.1.0

---

## 1. Purpose and Single Responsibility

**Sign UBL invoices with qualified XMLDSig signatures using FINA X.509 certificates for Croatian e-invoice fiscalization.**

This service implements:
- **XMLDSig signature generation** (enveloped signatures per W3C standard)
- **ZKI code generation** for B2C fiscalization (MD5 + RSA signing)
- **Signature verification** (XMLDSig validation)
- **Certificate management** (load and validate FINA .p12 certificates)

---

## 2. Integration Architecture

### 2.1 Dependencies

**Upstream (Consumes From):**
- Filesystem: FINA X.509 certificates (`.p12` format) from `/etc/eracun/secrets/certs/`
- HTTP: UBL 2.1 invoice XML documents (from transformation services)

**Downstream (Produces To):**
- HTTP Response: Signed XML documents
- HTTP Response: ZKI codes for fiscalization

**No message queues** - This is a synchronous HTTP API service.

### 2.2 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/sign/ubl` | POST | Sign UBL 2.1 invoice with XMLDSig |
| `/api/v1/sign/xml` | POST | Sign generic XML document |
| `/api/v1/sign/zki` | POST | Generate ZKI code for B2C fiscalization |
| `/api/v1/verify/ubl` | POST | Verify UBL invoice signature |
| `/api/v1/verify/xml` | POST | Verify XMLDSig signature in XML |
| `/api/v1/verify/zki` | POST | Verify ZKI code |
| `/api/v1/certificates` | GET | Get loaded certificate information |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |
| `/metrics` | GET | Prometheus metrics (port 9096) |

---

## 3. Technology Stack

**Core:**
- Node.js 20+
- TypeScript 5.3+
- Express 4.x

**XMLDSig & Cryptography:**
- `xml-crypto` - XMLDSig implementation
- `node-forge` - X.509 certificate parsing, RSA cryptography
- `xml2js` - XML parsing

**Observability:**
- `prom-client` - Prometheus metrics
- `pino` - Structured JSON logging
- `@opentelemetry/*` - Distributed tracing

---

## 4. Quick Start

### 4.1 Installation

```bash
cd services/digital-signature-service
npm install
```

### 4.2 Configuration

Create `.env` file:

```bash
cp .env.example .env
```

Configure certificate paths:

```bash
# Service Configuration
SERVICE_NAME=digital-signature-service
NODE_ENV=development
HTTP_PORT=8088

# Certificate Storage
CERT_DIRECTORY=/etc/eracun/secrets/certs
DEFAULT_CERT_PATH=/etc/eracun/secrets/certs/fina-demo.p12
DEFAULT_CERT_PASSWORD=your-cert-password

# Observability
LOG_LEVEL=info
METRICS_PORT=9096
```

### 4.3 Run Service

```bash
# Development (with hot reload)
npm run dev

# Production
npm run build
npm start
```

### 4.4 Run Tests

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

---

## 5. API Usage Examples

### 5.1 Sign UBL Invoice

```bash
curl -X POST http://localhost:8088/api/v1/sign/ubl \
  -H "Content-Type: application/xml" \
  --data @invoice.xml \
  -o signed-invoice.xml
```

### 5.2 Generate ZKI Code

```bash
curl -X POST http://localhost:8088/api/v1/sign/zki \
  -H "Content-Type: application/json" \
  -d '{
    "oib": "12345678901",
    "issueDateTime": "2026-01-15T10:30:00",
    "invoiceNumber": "1",
    "businessPremises": "ZAGREB1",
    "cashRegister": "POS1",
    "totalAmount": "125.00"
  }'
```

**Response:**
```json
{
  "zki": "a1b2c3d4e5f6789012345678901234ab",
  "zki_formatted": "a1b2c3d4-e5f67890-12345678-901234ab"
}
```

### 5.3 Verify XMLDSig Signature

```bash
curl -X POST http://localhost:8088/api/v1/verify/ubl \
  -H "Content-Type: application/xml" \
  --data @signed-invoice.xml
```

**Response:**
```json
{
  "isValid": true,
  "errors": [],
  "certificateInfo": {
    "subject": "CN=Test Company, O=Test d.o.o., C=HR",
    "issuer": "CN=Fina RDC 2015 CA, O=FINA, C=HR",
    "serialNumber": "123456789",
    "notBefore": "2025-01-01T00:00:00.000Z",
    "notAfter": "2026-01-01T00:00:00.000Z"
  }
}
```

---

## 6. FINA Certificate Requirements

### 6.1 Certificate Acquisition

**Demo Certificate (FREE, 1-year validity):**
- Portal: https://cms.fina.hr/
- Use for testing in `cistest.apis-it.hr` environment
- **DO NOT use in production**

**Production Certificate (~39.82 EUR + VAT, 5-year validity):**
- Portal: https://cms.fina.hr/
- Processing time: 5-10 business days
- Requires company registration documents

### 6.2 Certificate Storage

**Location:** `/etc/eracun/secrets/certs/`

**Security:**
- Encrypt with SOPS + age (see ADR-002)
- File permissions: 600 (owner read/write only)
- Never commit to git (`.gitignore` protection)
- Password stored separately in environment variables

**Example:**
```bash
# Store certificate
sudo mkdir -p /etc/eracun/secrets/certs
sudo cp fina-demo.p12 /etc/eracun/secrets/certs/
sudo chmod 600 /etc/eracun/secrets/certs/fina-demo.p12
sudo chown eracun:eracun /etc/eracun/secrets/certs/fina-demo.p12

# Set password in .env
echo "DEFAULT_CERT_PASSWORD=your-password" >> .env
```

---

## 7. XMLDSig Signature Format

**Standard:** W3C XMLDSig 1.0 (Enveloped Signature)
**Canonicalization:** Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)
**Signature Algorithm:** RSA-SHA256
**Digest Algorithm:** SHA-256

**Signature Structure:**
```xml
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="">
              <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              </ds:Transforms>
              <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
              <ds:DigestValue>BASE64_HASH</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>BASE64_RSA_SIGNATURE</ds:SignatureValue>
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>BASE64_CERTIFICATE</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </ds:Signature>
      </ext:ExtensionContent>
    </ext:UBLExtension>
  </ext:UBLExtensions>
  <!-- Rest of invoice -->
</Invoice>
```

---

## 8. ZKI Code Algorithm

**Purpose:** Security code for B2C fiscalization (Croatian law requirement)

**Algorithm:**
1. Concatenate: `OIB + IssueDateTime + InvoiceNumber + BusinessPremises + CashRegister + TotalAmount`
2. Compute MD5 hash of concatenated string
3. Sign MD5 hash with private key (RSA)
4. Convert signature to hexadecimal
5. Result: 32-character hex string

**Example:**
```
Input: OIB=12345678901, DateTime=2026-01-15T10:30:00, Invoice=1, Premises=ZAGREB1, POS=POS1, Amount=125.00
Concatenated: 123456789012026-01-15T10:30:001ZAGREB1POS1125.00
MD5 Hash: [binary hash]
RSA Signature: [binary signature]
ZKI Output: a1b2c3d4e5f6789012345678901234ab
```

---

## 9. Observability (TODO-008 Compliance)

### 9.1 Prometheus Metrics

**Counters:**
- `digital_signature_total{operation, status}` - Total signature operations
- `certificate_operations_total{operation, status}` - Certificate operations
- `digital_signature_errors_total{error_type}` - Signature errors
- `xmldsig_validations_total{result}` - XMLDSig validations

**Histograms:**
- `digital_signature_duration_seconds{operation}` - Operation duration

**Gauges:**
- `active_certificates_count` - Number of loaded certificates
- `digital_signature_service_up` - Service health (1=up, 0=down)

### 9.2 Structured Logging

**Format:** JSON (Pino)
**Fields:** `timestamp`, `level`, `service`, `request_id`, `message`

**PII Protection:**
- OIB numbers masked: `***********`
- Certificate passwords redacted: `[REDACTED]`
- Private keys NEVER logged

### 9.3 Distributed Tracing

**OpenTelemetry Spans:**
- `load_certificate_from_file`
- `parse_certificate`
- `validate_certificate`
- `sign_xml_document`
- `sign_ubl_invoice`
- `generate_zki`
- `verify_xml_signature`
- `verify_zki`

**Sampling:** 100% (per TODO-008 decision)

---

## 10. Performance Requirements

**Latency Targets:**
- XML signing: <1 second (p95)
- ZKI generation: <100ms (p95)
- Signature verification: <500ms (p95)

**Throughput:**
- 100+ signatures/second (sustained)
- 1,000+ ZKI codes/second (sustained)

**Resource Limits:**
- Memory: 512MB (burst to 1GB)
- CPU: 0.5 cores (burst to 2 cores)
- Max XML size: 10MB

---

## 11. Security Considerations

### 11.1 Certificate Protection

**CRITICAL:** Private key compromise = forged invoices = legal liability

**Requirements:**
- Store in encrypted format (SOPS + age)
- File permissions: 600
- Password in environment variables (never hardcoded)
- Audit all certificate operations
- Monitor for unauthorized access

### 11.2 XML Security

**Protections:**
- XXE (XML External Entity) attacks prevented
- Size limits enforced (max 10MB)
- Canonicalization prevents whitespace manipulation
- Signature verification includes certificate chain validation

---

## 12. Deployment

### 12.1 systemd Service

**Service File:** `/etc/systemd/system/digital-signature-service.service`

```ini
[Unit]
Description=Digital Signature Service (eRacun)
After=network.target

[Service]
Type=simple
User=eracun
Group=eracun
WorkingDirectory=/opt/eracun/services/digital-signature-service
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=10

# Environment
Environment=NODE_ENV=production
EnvironmentFile=/etc/eracun/services/digital-signature-service.env

# Security Hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=/var/log/eracun

[Install]
WantedBy=multi-user.target
```

### 12.2 Deployment Steps

```bash
# 1. Build service
npm run build

# 2. Copy to deployment location
sudo mkdir -p /opt/eracun/services/digital-signature-service
sudo cp -r dist package.json node_modules /opt/eracun/services/digital-signature-service/

# 3. Install systemd service
sudo cp digital-signature-service.service /etc/systemd/system/
sudo systemctl daemon-reload

# 4. Start service
sudo systemctl enable digital-signature-service
sudo systemctl start digital-signature-service

# 5. Verify service
sudo systemctl status digital-signature-service
curl http://localhost:8088/health
```

---

## 13. Troubleshooting

### 13.1 Certificate Loading Fails

**Error:** `Failed to load certificate from /path/to/cert.p12`

**Causes:**
- File not found
- Wrong password
- Incorrect file format
- Insufficient permissions

**Solutions:**
```bash
# Check file exists
ls -l /etc/eracun/secrets/certs/fina-demo.p12

# Check permissions
sudo chmod 600 /etc/eracun/secrets/certs/fina-demo.p12
sudo chown eracun:eracun /etc/eracun/secrets/certs/fina-demo.p12

# Verify certificate format
openssl pkcs12 -info -in /etc/eracun/secrets/certs/fina-demo.p12
```

### 13.2 Signature Verification Fails

**Error:** `Signature verification failed`

**Causes:**
- Document modified after signing
- Invalid certificate
- Wrong canonicalization
- Expired certificate

**Solutions:**
- Re-sign document
- Verify certificate validity dates
- Check certificate issuer (must be FINA or AKD)
- Review XMLDSig structure

### 13.3 Service Not Ready

**Error:** `Service not ready - No certificate loaded`

**Cause:** Default certificate not configured

**Solution:**
```bash
# Set environment variables
export DEFAULT_CERT_PATH=/etc/eracun/secrets/certs/fina-demo.p12
export DEFAULT_CERT_PASSWORD=your-password

# Restart service
sudo systemctl restart digital-signature-service
```

---

## 14. Testing

### 14.1 Test Coverage

**Target:** 85%+ coverage (enforced in jest.config.js)

**Current Coverage:**
- Unit tests: 70% of test suite
- Integration tests: 25% of test suite
- E2E tests: 5% of test suite

### 14.2 Test Data

**Test Certificates:**
- `tests/fixtures/test-certificate.p12` - Demo FINA certificate
- Password: `test123`

**Test UBL Invoices:**
- `tests/fixtures/test-invoice.xml` - Valid UBL 2.1 invoice

### 14.3 Running Tests

```bash
# All tests
npm test

# Coverage report
npm run test:coverage

# Watch mode
npm run test:watch

# Specific test file
npm test -- tests/unit/zki-generator.test.ts
```

---

## 15. Related Documentation

- **W3C XMLDSig Specification:** https://www.w3.org/TR/xmldsig-core/
- **FINA Certificate Guide:** `/docs/research/XMLDSIG_GUIDE.md`
- **Croatian Compliance:** `/CROATIAN_COMPLIANCE.md` (Section 8.4)
- **External Integrations:** `/docs/standards/EXTERNAL_INTEGRATIONS.md` (Section 2.6)
- **Secrets Management:** `/docs/adr/002-secrets-management-sops-age.md`

---

## 16. License

**UNLICENSED** - Private, proprietary software for eRacun platform

---

**Maintainer:** eRacun Development Team
**Last Updated:** 2025-11-12
**Service Version:** 0.1.0
**Status:** ✅ Production-Ready
