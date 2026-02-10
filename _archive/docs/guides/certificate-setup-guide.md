# FINA Certificate Setup Guide

**Acquiring and Managing Digital Certificates for Croatian Fiscalization**

## Overview

This guide covers the complete process of acquiring, installing, and managing FINA X.509 digital certificates required for Croatian e-invoice fiscalization. These certificates are mandatory for signing invoices and submitting them to the Tax Authority.

**Certificate Types:**
- **Production Certificates:** ~39.82 EUR + VAT per 5-year certificate
- **Demo Certificates:** FREE for testing (1-year validity)

**Issuer:** FINA (Croatian Financial Agency) or AKD (alternative provider)

---

## 1. Prerequisites

### 1.1 Legal Requirements

- [ ] **Company registered** in Croatia (OIB assigned)
- [ ] **VAT registration** (if applicable)
- [ ] **FiskAplikacija registration** (ePorezna portal account)
- [ ] **Authorized signatory** (CEO or authorized person)

### 1.2 Technical Requirements

- [ ] **NIAS authentication** (eOsobna or similar)
- [ ] **Email address** (for certificate delivery)
- [ ] **Secure storage** for private keys
- [ ] **Backup solution** for certificate files

---

## 2. Certificate Types and Costs

### 2.1 FINA Application Certificates

**Purpose:** Sign e-invoices for fiscalization

**Specifications:**
- **Algorithm:** RSA 2048-bit or higher
- **Hash:** SHA-256
- **Format:** PKCS#12 (.p12 file)
- **Validity:** 5 years (production), 1 year (demo)
- **Issuer:** Fina Root CA → Fina RDC 2015 CA → Application Certificate

**Pricing (2025):**
```
Production Certificate: 39.82 EUR + VAT (per 5 years)
Demo Certificate:       FREE (per 1 year)
Renewal (30 days early): Same price as new certificate
Replacement (lost):      Same price as new certificate
```

### 2.2 Alternative Providers

**AKD (Agencija za komercijalnu djelatnost):**
- Similar pricing to FINA
- Same technical specifications
- Alternative if FINA unavailable

---

## 3. Acquiring a Demo Certificate (Testing)

### 3.1 Access FINA Portal

1. **Navigate to:** https://cms.fina.hr
2. **Login with:** NIAS authentication (eOsobna, mobile banking, etc.)
3. **Select:** "Demo certifikati za testiranje"

### 3.2 Request Demo Certificate

1. **Fill Application Form:**
   - Company name (OIB)
   - Authorized person details
   - Email for delivery
   - Purpose: Fiscalization testing

2. **Submit Request**

3. **Wait for Processing:**
   - Processing time: 1-2 business days
   - Email notification when ready

### 3.3 Download Certificate

1. **Check Email** for download link
2. **Download .p12 file**
3. **Note password** (provided in email or portal)

### 3.4 Verify Certificate

```bash
# Extract certificate information
openssl pkcs12 -in demo-certificate.p12 -info -noout

# Verify certificate chain
openssl pkcs12 -in demo-certificate.p12 -chain -nokeys
```

**Expected Output:**
```
MAC verified OK
Bag Attributes
    localKeyID: XX XX XX XX
    friendlyName: FINA Demo Certificate
subject=CN=FINA Demo, O=Your Company d.o.o., C=HR
issuer=CN=Fina RDC 2015 CA, O=FINA, C=HR
```

---

## 4. Acquiring a Production Certificate

### 4.1 Preparation

**Required Documents:**
- [ ] Company registration certificate (izvadak)
- [ ] OIB certificate
- [ ] Proof of VAT registration (if applicable)
- [ ] Authorized signatory documentation
- [ ] Power of attorney (if submitter ≠ authorized signatory)

### 4.2 FiskAplikacija Registration

1. **Access Portal:** https://cis.porezna-uprava.hr
2. **Login:** NIAS authentication
3. **Register Information System Provider:**
   - Provider name (your company)
   - Contact information
   - Technical contact
   - OIB

4. **Grant Fiscalization Authorization:**
   - Authorize provider to submit invoices
   - Specify scope (B2C, B2B, B2G)
   - Set validity period

### 4.3 Certificate Application

1. **Access CMS Portal:** https://cms.fina.hr
2. **Login:** NIAS authentication
3. **Select:** "Aplikacijski certifikati"
4. **Fill Application:**
   - Certificate type: Fiscalization
   - Validity: 5 years
   - Company details (auto-filled from OIB)
   - Authorized person
   - Email for delivery
   - Billing information

5. **Payment:**
   - Online payment (card or bank transfer)
   - Amount: 39.82 EUR + VAT
   - Payment confirmation (keep receipt)

6. **Submit Application**

### 4.4 Certificate Issuance

**Processing Time:** 5-10 business days

**Status Tracking:**
- Portal: Check "Moji certifikati" status
- Email: Notifications at each stage

**Stages:**
1. Application received
2. Payment confirmed
3. Certificate generated
4. Certificate ready for download

### 4.5 Download Production Certificate

1. **Check Email** for download notification
2. **Login to CMS Portal**
3. **Navigate to:** "Moji certifikati"
4. **Download .p12 file**
5. **Generate password** (portal provides secure password)
6. **Backup immediately** (see Section 7)

---

## 5. Certificate Installation

### 5.1 Encrypt with SOPS

**CRITICAL:** Never store unencrypted certificates in git!

```bash
# Encrypt certificate with SOPS
cd /path/to/eRacun-development
sops --encrypt secrets/certs/production.p12 > secrets/certs/production.p12.enc

# Delete unencrypted file
shred -u secrets/certs/production.p12

# Verify encryption
sops --decrypt secrets/certs/production.p12.enc | file -
# Output: data (encrypted)
```

### 5.2 Store Certificate Password

```bash
# Add password to encrypted environment file
sops secrets/envs/production.enc.env

# Add line:
FINA_CERT_PASSWORD=your-secure-password-here
```

### 5.3 Install in Application

**Option A: File-based (Development/Staging):**
```typescript
// services/digital-signature-service/src/config.ts
export const config = {
  certificate: {
    path: process.env.FINA_CERT_PATH || '/etc/eracun/certs/production.p12',
    password: process.env.FINA_CERT_PASSWORD,
  },
};
```

**Option B: HSM (Production - Future):**
```typescript
// services/digital-signature-service/src/config.ts
export const config = {
  certificate: {
    hsmEnabled: true,
    hsmSlot: parseInt(process.env.HSM_SLOT || '0', 10),
    hsmPin: process.env.HSM_PIN,
    certLabel: 'FINA_PRODUCTION',
  },
};
```

### 5.4 Verify Installation

```bash
# Start digital-signature-service
docker-compose up digital-signature-service

# Check logs
docker-compose logs digital-signature-service | grep certificate

# Expected output:
# "Certificate loaded successfully: CN=Your Company d.o.o., validity: 2025-01-01 to 2030-01-01"
```

---

## 6. Certificate Lifecycle Management

### 6.1 Monitoring Expiry

**Automated Monitoring (Recommended):**
```typescript
// services/cert-lifecycle-manager/src/index.ts
import { checkCertificateExpiry } from './expiry-checker';

// Check daily
setInterval(async () => {
  const expiryInfo = await checkCertificateExpiry('/etc/eracun/certs/production.p12');

  if (expiryInfo.daysRemaining <= 30) {
    await sendAlert({
      severity: 'critical',
      message: `Certificate expires in ${expiryInfo.daysRemaining} days`,
      action: 'Renew certificate immediately',
    });
  }
}, 24 * 60 * 60 * 1000); // Daily
```

**Manual Check:**
```bash
# Extract certificate and check dates
openssl pkcs12 -in production.p12 -clcerts -nokeys | openssl x509 -noout -dates

# Output:
# notBefore=Jan  1 00:00:00 2025 GMT
# notAfter=Jan  1 23:59:59 2030 GMT
```

### 6.2 Certificate Renewal

**Timeline:**
- **30 days before expiry:** Initiate renewal process
- **15 days before expiry:** CRITICAL - Escalate if not completed
- **0 days after expiry:** Certificate invalid, fiscalization blocked

**Renewal Process:**
1. Apply for new certificate (same process as initial)
2. Download new certificate
3. Test new certificate in staging
4. Deploy to production (zero-downtime deployment)
5. Verify submissions work
6. Revoke old certificate (after 7 days grace period)

### 6.3 Certificate Revocation

**When to Revoke:**
- Private key compromised
- Certificate lost or stolen
- Employee with access terminated
- Company name change
- Migration to new certificate

**Revocation Process:**
1. **Login to CMS Portal:** https://cms.fina.hr
2. **Navigate to:** "Moji certifikati"
3. **Select certificate** to revoke
4. **Click:** "Opozovi certifikat"
5. **Confirm:** Reason for revocation
6. **Wait:** 24-48 hours for CRL update

**Verify Revocation:**
```bash
# Download CRL
wget http://crl.fina.hr/fina-rdc-2015-ca.crl

# Check if certificate is revoked
openssl crl -in fina-rdc-2015-ca.crl -text -noout | grep -A 2 "Serial Number: <your-cert-serial>"
```

---

## 7. Backup and Disaster Recovery

### 7.1 Certificate Backup

**Backup Strategy:**
- **Primary:** Encrypted in git (`secrets/certs/production.p12.enc`)
- **Secondary:** Secure offline storage (USB drive, safe)
- **Tertiary:** Encrypted cloud backup (optional)

**Create Backup:**
```bash
# Backup encrypted certificate
cp secrets/certs/production.p12.enc /media/usb/eracun-backups/$(date +%Y%m%d)-production.p12.enc

# Backup age encryption key (CRITICAL!)
sudo cp /etc/eracun/.age-key /media/usb/eracun-backups/$(date +%Y%m%d)-age-key
sudo chmod 400 /media/usb/eracun-backups/$(date +%Y%m%d)-age-key

# Store USB drive in physical safe
```

### 7.2 Disaster Recovery

**Scenario 1: Certificate File Lost**
```bash
# Restore from git
git pull origin main
sops --decrypt secrets/certs/production.p12.enc > /tmp/production.p12

# Verify certificate
openssl pkcs12 -in /tmp/production.p12 -info -noout

# Re-encrypt and deploy
sops --encrypt /tmp/production.p12 > secrets/certs/production.p12.enc
shred -u /tmp/production.p12
```

**Scenario 2: Password Lost**
- **Cannot recover password** from FINA
- **Must revoke certificate** and request new one
- **Downtime:** 5-10 business days
- **Cost:** 39.82 EUR + VAT

**Scenario 3: Server Compromise**
- **Immediately revoke certificate**
- **Request new certificate**
- **Rotate all secrets**
- **Forensic investigation**

### 7.3 High Availability Setup

**Multiple Certificates (Optional for Enterprise):**
```bash
# Primary certificate
FINA_CERT_PRIMARY=/etc/eracun/certs/production-primary.p12

# Backup certificate (different serial, same validity)
FINA_CERT_BACKUP=/etc/eracun/certs/production-backup.p12

# Automatic failover in digital-signature-service
```

---

## 8. Security Best Practices

### 8.1 Private Key Protection

- [ ] **Never commit** unencrypted .p12 files to git
- [ ] **Use SOPS** encryption for all certificate files
- [ ] **Restrict access** to certificate files (chmod 600)
- [ ] **Separate passwords** for dev/staging/production
- [ ] **Rotate passwords** annually
- [ ] **Use HSM** for production (when available)

### 8.2 Access Control

**Who Should Have Access:**
- DevOps team (encrypted certificate deployment)
- Security team (monitoring, incident response)
- Compliance team (audit, verification)

**Who Should NOT Have Access:**
- Developers (use demo certificates in development)
- QA team (use demo certificates in staging)
- External contractors (unless explicitly authorized)

**Access Logging:**
```bash
# Log all certificate access
sudo auditctl -w /etc/eracun/certs/ -p rwa -k certificate_access

# View access logs
sudo ausearch -k certificate_access
```

### 8.3 systemd Protection

```ini
# deployment/systemd/eracun-digital-signature-service.service
[Service]
# Hide certificates from service process
InaccessiblePaths=/etc/eracun/.age-key
InaccessiblePaths=/etc/eracun/certs/

# Decrypt certificate at startup
ExecStartPre=/usr/local/bin/sops-decrypt.sh digital-signature-service

# Certificate available via environment variable
EnvironmentFile=/run/eracun/digital-signature-service.env
```

---

## 9. Testing with Demo Certificate

### 9.1 FINA Test Environment

**Test Endpoint:**
```
https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest
```

**Test OIBs:**
```
Issuer:    12345678901
Operator:  98765432109
Recipient: 11111111117
```

### 9.2 Test Submission

```bash
# Test signature with demo certificate
curl -X POST http://localhost:8088/api/v1/sign/ubl \
  -H "Content-Type: application/xml" \
  -d @tests/fixtures/sample-invoice.xml

# Submit to FINA test environment
curl -X POST http://localhost:8090/api/v1/fina/submit \
  -H "Content-Type: application/xml" \
  -H "X-Certificate: DEMO" \
  -d @tests/fixtures/signed-invoice.xml
```

### 9.3 Validate Test Results

**Expected Response (Success):**
```xml
<soap:Envelope>
  <soap:Body>
    <FiskalizacijaResponse>
      <JIR>12345678-1234-5678-1234-567812345678</JIR>
      <Status>SUCCESS</Status>
    </FiskalizacijaResponse>
  </soap:Body>
</soap:Envelope>
```

**Common Test Errors:**
- `INVALID_CERTIFICATE`: Demo certificate not recognized
- `EXPIRED_CERTIFICATE`: Demo certificate expired (1-year validity)
- `INVALID_OIB`: Test OIB not in allowed list
- `INVALID_SIGNATURE`: XMLDSig signature verification failed

---

## 10. Production Deployment Checklist

- [ ] Production certificate acquired from FINA
- [ ] Certificate validity verified (5 years from issue date)
- [ ] Certificate encrypted with SOPS
- [ ] Certificate password stored in encrypted vault
- [ ] Backup certificates created (minimum 2 copies)
- [ ] Offline backup stored securely (safe, locked cabinet)
- [ ] Certificate expiry monitoring configured (30-day alert)
- [ ] Automatic renewal workflow tested
- [ ] Revocation procedure documented
- [ ] Disaster recovery procedure tested
- [ ] Access control configured (minimal privileges)
- [ ] systemd hardening applied
- [ ] Test submission to FINA test environment successful
- [ ] Production submission tested in staging
- [ ] Team trained on certificate management
- [ ] Documentation updated with certificate details

---

## 11. Troubleshooting

### 11.1 Certificate Import Failed

**Error:** `Error: unable to load PKCS#12: mac verify failure`

**Cause:** Incorrect password

**Solution:**
```bash
# Verify password in environment
echo $FINA_CERT_PASSWORD

# Try importing with explicit password
openssl pkcs12 -in production.p12 -passin pass:your-password -info
```

### 11.2 Certificate Expired

**Error:** `Error: certificate has expired`

**Immediate Action:**
1. Check production certificate dates
2. If expired, switch to backup certificate (if available)
3. Initiate emergency certificate renewal
4. Notify stakeholders of service disruption

**Prevention:**
- Set up 30-day, 15-day, 7-day expiry alerts
- Test renewal process quarterly

### 11.3 FINA Rejects Certificate

**Error:** `Error: FINA_CERTIFICATE_NOT_RECOGNIZED`

**Possible Causes:**
- Demo certificate used in production
- Certificate revoked
- Certificate not registered in FiskAplikacija
- Wrong certificate type (personal instead of application)

**Solution:**
```bash
# Verify certificate type
openssl pkcs12 -in production.p12 -clcerts -nokeys | openssl x509 -noout -subject

# Should contain:
# subject=CN=<Company Name>, O=<Company>, C=HR (NOT personal name)
```

---

## 12. Cost Summary

**Initial Setup (Year 1):**
```
Demo Certificate (testing):    0 EUR
Production Certificate:       39.82 EUR + VAT
Total Year 1:                ~47 EUR
```

**Annual Costs (Years 2-5):**
```
No renewal costs (5-year validity)
Total Years 2-5:             0 EUR
```

**Renewal (Year 6):**
```
New Production Certificate:   39.82 EUR + VAT
Total Year 6:                ~47 EUR
```

**Total 10-Year Cost:**
```
2 certificates × 47 EUR =    ~94 EUR
Average per year:            ~9.40 EUR
```

---

## Related Documentation

- **Compliance Requirements:** @docs/COMPLIANCE_REQUIREMENTS.md
- **Security Standards:** @docs/SECURITY.md
- **SOPS Secrets Management:** @docs/SOPS_SECRETS_MANAGEMENT.md
- **Digital Signature Service:** @services/digital-signature-service/README.md
- **cert-lifecycle-manager:** @services/cert-lifecycle-manager/README.md

---

**Last Updated:** 2025-11-14
**Document Owner:** Compliance Team
**Contact:** certificates@eracun.hr
