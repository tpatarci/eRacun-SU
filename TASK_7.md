# TASK 7: Certificate and Secrets Management Audit

## Task Priority
**CRITICAL** - Certificates required for FINA integration by January 1, 2026

## Objective
Audit all certificates, secrets, and encryption keys to ensure proper management, security, and timely renewal. Focus on FINA certificates, mTLS certificates, and SOPS encryption.

## Scope
Complete audit of:
- FINA fiscalization certificates (demo and production)
- mTLS certificates for inter-service communication
- SOPS/age encryption keys
- API keys and credentials
- Certificate lifecycle management
- Secret rotation procedures

## Detailed Approach

### 1. FINA Certificate Status (Day 1)
**Demo certificate verification:**
```bash
# Check demo certificate
openssl pkcs12 -in /etc/eracun/certs/fina-demo.p12 \
  -info -noout -passin pass:${DEMO_CERT_PASSWORD}

# Verify expiration
openssl pkcs12 -in /etc/eracun/certs/fina-demo.p12 \
  -nodes -passin pass:${DEMO_CERT_PASSWORD} | \
  openssl x509 -noout -enddate

# Test connectivity
curl --cert-type P12 \
  --cert /etc/eracun/certs/fina-demo.p12:${DEMO_CERT_PASSWORD} \
  https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest
```

**Production certificate checklist:**
- [ ] Application submitted to FINA
- [ ] Cost (~39.82 EUR + VAT) approved
- [ ] 5-10 business day timeline tracked
- [ ] NIAS authentication configured
- [ ] CMS portal access verified
- [ ] Backup certificate considered

### 2. mTLS Certificate Audit (Day 1-2)
**Inter-service certificates:**
```bash
# Check all service certificates
for cert in /etc/eracun/certs/services/*.crt; do
  echo "=== ${cert} ==="
  openssl x509 -in "${cert}" -noout -enddate
  openssl x509 -in "${cert}" -noout -subject
done

# Verify cert-lifecycle-manager
systemctl status cert-lifecycle-manager
journalctl -u cert-lifecycle-manager --since "1 week ago"
```

**Certificate validation checklist:**
- [ ] All certificates valid (not expired)
- [ ] 90-day rotation configured
- [ ] Automated renewal working
- [ ] CRL/OCSP configured
- [ ] Certificate chain complete
- [ ] Private keys properly protected

### 3. SOPS/age Encryption Review (Day 2)
**Encrypted secrets verification:**
```bash
# Check all SOPS encrypted files
find /etc/eracun -name "*.yaml" -exec \
  head -1 {} \; | grep -c "sops:"

# Verify age keys permissions
ls -la /etc/eracun/.age-key
# Should be 400 (-r--------)

# Test decryption service
systemctl status sops-decrypt
ls -la /run/eracun/  # Should be tmpfs
```

**SOPS checklist:**
- [ ] All secrets encrypted (no plaintext)
- [ ] Age keys backed up securely
- [ ] Decryption service operational
- [ ] Runtime secrets in tmpfs
- [ ] Key rotation procedure documented
- [ ] Audit log for decryption events

### 4. API Keys and Credentials (Day 2-3)
**External service credentials audit:**
```bash
# List all configured API keys (encrypted)
sops -d /etc/eracun/secrets/api-keys.yaml | \
  jq 'keys'

# Verify each service has required credentials
```

**Credential inventory:**
| Service | Credential Type | Status | Expiry | Rotation |
|---------|----------------|---------|---------|----------|
| FINA | X.509 Certificate | ? | ? | Manual |
| Croatian Registry | API Key | ? | ? | ? |
| Email Provider | API Key | ? | ? | ? |
| SMS Provider | API Key | ? | ? | ? |
| Monitoring | API Key | ? | ? | ? |

### 5. Secret Rotation Testing (Day 3)
**Simulate certificate rotation:**
```bash
# Generate new test certificate
openssl req -x509 -newkey rsa:4096 \
  -keyout test.key -out test.crt \
  -days 30 -nodes

# Replace service certificate
mv /etc/eracun/certs/services/old.crt{,.backup}
cp test.crt /etc/eracun/certs/services/old.crt

# Restart service and verify
systemctl restart eracun-service
# Check logs for certificate errors
```

**Rotation procedures checklist:**
- [ ] Zero-downtime rotation possible
- [ ] Rollback procedure documented
- [ ] Notification before expiry
- [ ] Automated where possible
- [ ] Manual procedures for FINA certs
- [ ] Audit trail maintained

### 6. Key Management Security (Day 3-4)
**HSM consideration for production:**
- [ ] HSM evaluation completed
- [ ] Cost-benefit analysis done
- [ ] FIPS 140-2 Level 2+ if required
- [ ] Key backup strategy defined
- [ ] Disaster recovery plan includes keys
- [ ] Compliance requirements met

### 7. Certificate Expiry Monitoring (Day 4)
**Alerting configuration:**
```prometheus
# Prometheus alerts for certificates
- alert: CertificateExpiringSoon
  expr: x509_cert_expiry - time() < 30 * 86400
  annotations:
    summary: "Certificate expiring in <30 days"

- alert: CertificateExpired
  expr: x509_cert_expiry - time() < 0
  annotations:
    summary: "Certificate has expired!"
```

## Required Tools
- OpenSSL for certificate inspection
- SOPS CLI for secret management
- age for encryption
- cert-manager or similar for lifecycle
- Monitoring tools (Prometheus)

## Pass/Fail Criteria

### MUST PASS (Certificate requirements)
- ✅ FINA demo certificate valid and tested
- ✅ Production certificate process started
- ✅ All service certificates valid
- ✅ No plaintext secrets in repository
- ✅ Certificate monitoring active

### RED FLAGS (Security failures)
- ❌ Expired certificates in production
- ❌ Plaintext secrets found
- ❌ No certificate rotation plan
- ❌ Missing FINA certificates
- ❌ Weak encryption keys

## Deliverables
1. **Certificate Inventory** - All certificates with expiry dates
2. **Secret Audit Report** - Security assessment
3. **Rotation Schedule** - Planned certificate renewals
4. **FINA Certificate Status** - Timeline to production
5. **Security Recommendations** - HSM and improvements

## Time Estimate
- **Duration:** 4 days
- **Effort:** 1 security engineer
- **Prerequisites:** Access to all certificates and secrets

## Risk Factors
- **Critical Risk:** FINA certificate not ready by deadline
- **High Risk:** Certificate expiry causing outage
- **High Risk:** Compromised private keys
- **Medium Risk:** Manual rotation errors
- **Low Risk:** Monitoring gaps

## Escalation Path
For certificate issues:
1. Check expiry dates immediately
2. Initiate renewal process
3. For FINA: Contact support at 01 4404 707
4. Implement temporary workaround if needed
5. Document in incident report

## Certificate Timeline (FINA)
- **September 1, 2025:** Demo certificate acquisition
- **October 1, 2025:** Production application submission
- **November 1, 2025:** Production certificate ready
- **December 1, 2025:** Final testing with production cert
- **January 1, 2026:** Go-live with production certificate

## Related Documentation
- @docs/guides/certificate-setup.md
- @docs/adr/ADR-002-secrets-management.md
- @docs/SECURITY.md (Section 1: Secrets Management)
- FINA portal: cms.fina.hr
- Certificate provider documentation

## Security Checklist
- [ ] All certificates use strong algorithms (RSA 2048+)
- [ ] Private keys never in version control
- [ ] Passphrases complex and unique
- [ ] Key storage follows least privilege
- [ ] Backup keys stored offline
- [ ] Recovery procedure tested
- [ ] Compliance audit trail complete
- [ ] Team trained on procedures
- [ ] Documentation up to date
- [ ] Emergency contacts listed

## Notes
Certificate management is critical for FINA integration. The production certificate must be obtained well before the January 1, 2026 deadline to allow for testing and potential issues. Consider having backup certificates ready.