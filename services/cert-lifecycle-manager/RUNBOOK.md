# Certificate Lifecycle Manager - Operational Runbook

**Service:** cert-lifecycle-manager
**Purpose:** Manage FINA X.509 certificates for invoice signing
**On-Call Priority:** P1 (15-minute response time - certificate expiration blocks ALL invoice processing)

---

## Quick Reference

### Service Status
```bash
# Check service status
systemctl status eracun-cert-lifecycle-manager

# View recent logs
journalctl -u eracun-cert-lifecycle-manager -n 100 --no-pager

# Check health endpoint
curl http://localhost:8087/health

# Check metrics
curl http://localhost:8087/metrics | grep cert_
```

### Emergency Contacts
- **FINA Certificate Support:** 01 4404 707 (Mon-Fri 08:00-16:00)
- **Platform Team:** [Insert on-call contact]
- **Security Team:** [Insert security contact for certificate issues]

---

## Common Incidents

### 1. Certificate Expires in < 7 Days (CRITICAL)

**Alert:** `CertificateExpiringSoon`
**Symptoms:** `certificates_expiring_count{days="7"}` > 0

#### Immediate Actions

⚠️ **This is critical** - certificate expiration blocks ALL invoice fiscalization.

1. Check expiring certificates:
```bash
curl http://localhost:8087/api/v1/certificates/expiring
```

2. Verify expiration dates:
```bash
curl http://localhost:8087/api/v1/certificates | jq '.[] | select(.status == "expiring_soon")'
```

3. Check if renewal is in progress:
```bash
# Check if new certificate uploaded
curl http://localhost:8087/api/v1/certificates | jq '.[] | select(.created_at > "2025-11-01")'
```

#### Resolution

**If new certificate available:**
```bash
# Upload new certificate via admin portal
curl -X POST http://localhost:8087/api/v1/certificates/upload \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -F "certificate=@fina-new-certificate.p12" \
  -F "password=$CERT_PASSWORD" \
  -F "certType=production"

# Deploy to digital-signature-service
curl -X POST http://localhost:8087/api/v1/certificates/{cert-id}/deploy \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**If certificate not yet ordered:**
1. **URGENT:** Contact FINA immediately (01 4404 707)
2. Request expedited processing (mention critical deadline)
3. Provide company OIB and current certificate serial number
4. Processing time: 5-10 business days (request 48-hour rush if possible)

**If FINA cannot deliver in time:**
- Escalate to CTO immediately
- Consider manual invoice submission as fallback
- Document all affected invoices for post-recovery reconciliation

#### Verification
```bash
# Verify new certificate active
curl http://localhost:8087/api/v1/certificates | jq '.[] | select(.status == "active")'

# Test signature with new certificate
curl http://localhost:3002/health  # digital-signature-service
```

---

### 2. Certificate Expired (URGENT - P0)

**Alert:** `CertificateExpired`
**Symptoms:** Service cannot sign invoices, ALL fiscalization blocked

#### Immediate Actions

🚨 **CRITICAL OUTAGE** - ALL invoice processing stopped

1. Assess impact:
```bash
# Check how many certificates expired
curl http://localhost:8087/api/v1/certificates | jq '.[] | select(.status == "expired")' | jq -s 'length'

# Check time since expiration
curl http://localhost:8087/api/v1/certificates | jq '.[] | select(.status == "expired") | {serial: .serialNumber, expired_at: .notAfter}'
```

2. Check for backup certificate:
```bash
# List all production certificates
curl http://localhost:8087/api/v1/certificates | jq '.[] | select(.certType == "production")'
```

#### Resolution

**If backup certificate exists:**
```bash
# Activate backup certificate immediately
curl -X POST http://localhost:8087/api/v1/certificates/{backup-cert-id}/deploy \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Verify digital-signature-service reloaded
systemctl status eracun-digital-signature
```

**If no backup certificate:**
1. **URGENT:** Page on-call manager immediately
2. Switch to demo certificate temporarily (if available):
```bash
# Deploy demo certificate as emergency fallback
curl -X POST http://localhost:8087/api/v1/certificates/{demo-cert-id}/deploy \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
3. Contact FINA for emergency certificate issuance
4. Document affected period for compliance reporting

#### Post-Incident

- Root cause analysis: Why weren't expiration alerts acted upon?
- Review alert thresholds (currently 30/14/7/1 days)
- Implement automatic certificate renewal process
- Add redundant monitoring (external service)

---

### 3. Certificate Upload Fails (WARNING)

**Symptoms:** Admin unable to upload new certificate via portal

#### Diagnosis

1. Check service logs:
```bash
journalctl -u eracun-cert-lifecycle-manager -n 50 | grep ERROR
```

2. Common errors:
   - Invalid password: "Invalid certificate password or corrupt .p12 file"
   - Corrupt file: "No certificate found in .p12 file"
   - Wrong issuer: "Certificate not issued by FINA or AKD"

3. Test certificate manually:
```bash
# Test certificate parsing locally
openssl pkcs12 -in certificate.p12 -noout -passin pass:$PASSWORD
```

#### Resolution

**For invalid password:**
```bash
# Verify password with FINA documentation
# Common issue: Copy-paste includes whitespace

# Test with trimmed password
PASSWORD=$(echo "$RAW_PASSWORD" | tr -d '[:space:]')
```

**For corrupt file:**
```bash
# Check file integrity
md5sum certificate.p12

# Compare with FINA-provided checksum
# If mismatch, re-download from FINA CMS portal
```

**For wrong issuer:**
```bash
# Verify certificate issuer
openssl pkcs12 -in certificate.p12 -noout -passin pass:$PASSWORD -info

# Accepted issuers:
# - Fina RDC 2015 CA
# - Fina Root CA
# - AKD (alternative CA)
```

---

### 4. Daily Expiration Check Not Running (WARNING)

**Symptoms:** No expiration alerts received for days

#### Diagnosis

1. Check cron schedule:
```bash
# View current cron configuration
grep EXPIRATION_CHECK_CRON /etc/eracun/cert-lifecycle-manager.env

# Check systemd timer (if using)
systemctl list-timers | grep cert
```

2. Check last execution:
```bash
# View last cron execution in logs
journalctl -u eracun-cert-lifecycle-manager --since "1 week ago" | grep "expiration check"
```

3. Verify notification-service reachable:
```bash
curl http://localhost:8088/health  # notification-service
```

#### Resolution

**If cron not configured:**
```bash
# Verify environment variable
echo $EXPIRATION_CHECK_CRON  # Should be "0 9 * * *" (daily at 9 AM)

# Restart service to reload configuration
systemctl restart eracun-cert-lifecycle-manager
```

**If notification-service down:**
```bash
# Check notification service
systemctl status eracun-notification-service

# Restart if needed
systemctl restart eracun-notification-service
```

**Manual trigger (emergency):**
```bash
# Trigger expiration check immediately via API
curl -X POST http://localhost:8087/api/v1/internal/check-expiration \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

### 5. Certificate Deployment Fails (WARNING)

**Symptoms:** Certificate uploaded but not deployed to digital-signature-service

#### Diagnosis

1. Check deployment status:
```bash
curl http://localhost:8087/api/v1/certificates/{cert-id} | jq '.deploymentStatus'
```

2. Check file permissions:
```bash
ls -la /etc/eracun/secrets/certs/
# Should be: -rw------- 1 eracun eracun
```

3. Check SOPS encryption:
```bash
# Verify age key accessible
ls -la /etc/eracun/.age-key
# Should exist and be readable by eracun user
```

#### Resolution

**For permission issues:**
```bash
# Fix certificate directory permissions
sudo chown -R eracun:eracun /etc/eracun/secrets/certs/
sudo chmod 700 /etc/eracun/secrets/certs/
sudo chmod 600 /etc/eracun/secrets/certs/*.p12
```

**For SOPS encryption issues:**
```bash
# Test age encryption
sops --encrypt --age $(cat /etc/eracun/.age-key | grep public-key | cut -d: -f2) \
  /etc/eracun/secrets/certs/test.txt

# If fails, verify age key format
cat /etc/eracun/.age-key
# Should contain: AGE-SECRET-KEY-...
```

**For digital-signature-service not reloading:**
```bash
# Manual reload
systemctl reload eracun-digital-signature

# If reload fails, full restart
systemctl restart eracun-digital-signature

# Verify new certificate loaded
curl http://localhost:3002/api/v1/certificates
```

---

## Maintenance Procedures

### FINA Certificate Renewal (Critical - Do This 30+ Days Before Expiry)

#### Step 1: Order New Certificate from FINA

1. Login to FINA CMS portal: https://cms.fina.hr
2. Navigate to: "Zahtjevi" → "Novi zahtjev"
3. Select: "Kvalificirani certifikat za aplikaciju"
4. Fill in details:
   - Company OIB
   - Contact person
   - Email address
   - Certificate type: Production or Demo
5. Submit request
6. Wait 5-10 business days

#### Step 2: Download Certificate

1. Receive email notification from FINA
2. Login to FINA CMS portal
3. Download .p12 file
4. **CRITICAL:** Save password from email (will need it)
5. Verify file integrity (check MD5 hash if provided)

#### Step 3: Upload Certificate to System

1. Login to admin portal
2. Navigate to: Certificates → Upload New
3. Upload .p12 file
4. Enter password
5. Select certificate type: Production
6. Submit

#### Step 4: Verify Certificate

```bash
# Check certificate uploaded successfully
curl http://localhost:8087/api/v1/certificates | jq '.[] | select(.serialNumber == "NEW_SERIAL")'

# Verify certificate details
curl http://localhost:8087/api/v1/certificates/{cert-id} | jq '.'

# Check expiration date (should be 5 years in future)
curl http://localhost:8087/api/v1/certificates/{cert-id} | jq '.notAfter'
```

#### Step 5: Deploy Certificate

```bash
# Deploy to digital-signature-service
curl -X POST http://localhost:8087/api/v1/certificates/{cert-id}/deploy \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Verify deployment
curl http://localhost:3002/api/v1/certificates | jq '.[] | select(.serialNumber == "NEW_SERIAL")'
```

#### Step 6: Test Certificate

```bash
# Test signature generation
curl -X POST http://localhost:3002/api/v1/sign/ubl \
  -H "Content-Type: application/json" \
  -d '{"xmlDocument": "<test>...</test>"}'

# Should return signed XML without errors
```

#### Step 7: Revoke Old Certificate

```bash
# Wait 24 hours to ensure new certificate working

# Revoke old certificate
curl -X DELETE http://localhost:8087/api/v1/certificates/{old-cert-id}/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Verify old certificate status
curl http://localhost:8087/api/v1/certificates/{old-cert-id} | jq '.status'
# Should be: "revoked"
```

### Weekly Tasks

```bash
# Check certificate inventory
curl http://localhost:8087/api/v1/certificates | jq 'length'

# Review expiring certificates
curl http://localhost:8087/api/v1/certificates/expiring

# Check alert history
journalctl -u eracun-cert-lifecycle-manager --since "1 week ago" | grep alert

# Verify daily checks running
journalctl -u eracun-cert-lifecycle-manager --since "1 week ago" | grep "expiration check"
```

### Monthly Tasks

```bash
# Review certificate expiration timeline
curl http://localhost:8087/api/v1/certificates | jq '.[] | {serial: .serialNumber, expires: .notAfter, days: (.notAfter | fromdateiso8601 - now) / 86400 | floor}'

# Test certificate upload process (demo cert)
# Upload demo certificate, verify parsing, deploy, revoke

# Review alert thresholds
# Current: 30/14/7/1 days
# Adjust if needed based on FINA renewal SLA

# Test disaster recovery
# Simulate certificate expiration, verify failover to backup
```

### Database Maintenance

```sql
-- Check certificate inventory
SELECT cert_type, status, COUNT(*) as count
FROM certificates
GROUP BY cert_type, status;

-- Find expiring certificates
SELECT serial_number, not_after,
       EXTRACT(DAY FROM (not_after - NOW())) as days_until_expiry
FROM certificates
WHERE status IN ('active', 'expiring_soon')
ORDER BY not_after ASC;

-- Clean up old revoked certificates (after 2 years)
DELETE FROM certificates
WHERE status = 'revoked'
  AND updated_at < NOW() - INTERVAL '2 years';
```

---

## Monitoring Dashboards

### Key Metrics to Monitor

1. **Certificates Expiring Soon**
   ```
   certificates_expiring_count{days="30"}
   certificates_expiring_count{days="14"}
   certificates_expiring_count{days="7"}
   certificates_expiring_count{days="1"}
   ```

2. **Active Certificates by Type**
   ```
   certificates_active{cert_type="production"}
   certificates_active{cert_type="demo"}
   ```

3. **Certificate Operations**
   ```
   certificate_operations_total{operation="upload"}
   certificate_operations_total{operation="deploy"}
   certificate_operations_total{operation="revoke"}
   ```

4. **Expiration Alerts Sent**
   ```
   certificate_expiration_alerts_total{severity="info"}
   certificate_expiration_alerts_total{severity="warning"}
   certificate_expiration_alerts_total{severity="critical"}
   certificate_expiration_alerts_total{severity="urgent"}
   ```

### Grafana Dashboard

Recommended panels:
- Certificate expiration timeline (gauge showing days until next expiry)
- Active certificates by type (pie chart)
- Certificate operations over time (line chart)
- Alert distribution (stacked bar chart)

---

## Emergency Procedures

### Complete Service Failure

1. **Assess impact:**
```bash
# Check service status
systemctl status eracun-cert-lifecycle-manager

# Check if digital-signature-service affected
systemctl status eracun-digital-signature

# Can invoices still be signed?
curl http://localhost:3002/health
```

2. **Emergency restart:**
```bash
systemctl restart eracun-cert-lifecycle-manager

# Wait 10 seconds for startup
sleep 10

# Check health
curl http://localhost:8087/health
```

3. **If restart fails:**
```bash
# Check logs for errors
journalctl -u eracun-cert-lifecycle-manager -n 100

# Common issues:
# - Database connection failure → Check PostgreSQL
# - Missing environment variables → Check /etc/eracun/cert-lifecycle-manager.env
# - Corrupt certificate file → Restore from backup
```

4. **If database corrupted:**
```bash
# Restore from backup
pg_restore -h localhost -U eracun -d eracun_certs < /backups/certificates_latest.dump

# Restart service
systemctl restart eracun-cert-lifecycle-manager
```

### Certificate File System Corruption

1. **Verify corruption:**
```bash
# Check certificate directory
ls -la /etc/eracun/secrets/certs/

# Attempt to read certificates
for cert in /etc/eracun/secrets/certs/*.p12; do
  echo "Checking $cert"
  openssl pkcs12 -in "$cert" -noout -passin pass:$PASSWORD || echo "CORRUPT: $cert"
done
```

2. **Restore from backup:**
```bash
# Restore certificates from backup
sudo rsync -av /backups/eracun/certs/ /etc/eracun/secrets/certs/

# Fix permissions
sudo chown -R eracun:eracun /etc/eracun/secrets/certs/
sudo chmod 700 /etc/eracun/secrets/certs/
sudo chmod 600 /etc/eracun/secrets/certs/*.p12
```

3. **Re-deploy certificates:**
```bash
# Restart digital-signature-service to reload certificates
systemctl restart eracun-digital-signature

# Verify certificates loaded
curl http://localhost:3002/api/v1/certificates
```

---

## Escalation Procedures

### When to Escalate

| Severity | Escalation Time | Escalation Path |
|----------|----------------|----------------|
| P0 - Certificate expired | Immediate | Platform Team Lead → CTO → FINA |
| P1 - Expiring < 7 days | 15 minutes | Senior Engineer → Platform Team Lead |
| P2 - Expiring < 30 days | 1 hour | Team Channel → Senior Engineer |
| P3 - Certificate upload issue | Next business day | Team Channel |

### Escalation Contacts

1. **Certificate Issues:**
   - FINA Support: 01 4404 707
   - Security Team: [Contact]
   - Certificate Authority (AKD): [Contact if using AKD]

2. **Technical Issues:**
   - Platform Team: [Slack channel]
   - Database Issues: [DBA email]
   - Security/Encryption Issues: [Security team]

3. **Business Impact:**
   - Compliance Team: [Contact] - Must notify if certificate expired
   - Management: [Contact] - Escalate if >1 hour outage
   - Legal: [Contact] - If invoices submitted with expired certificate

---

## Disaster Recovery

### RTO/RPO Targets

- **RTO (Recovery Time Objective):** 30 minutes
- **RPO (Recovery Point Objective):** 1 hour

### Recovery Procedure

1. **Restore database:**
```bash
# Stop service
systemctl stop eracun-cert-lifecycle-manager

# Restore database
pg_restore -h localhost -U eracun -d eracun_certs < /backups/certificates_latest.dump

# Verify restore
psql -h localhost -U eracun -d eracun_certs -c "SELECT COUNT(*) FROM certificates;"
```

2. **Restore certificate files:**
```bash
# Restore encrypted certificates
sudo rsync -av /backups/eracun/certs/ /etc/eracun/secrets/certs/

# Restore SOPS age key
sudo cp /backups/eracun/age-key /etc/eracun/.age-key
sudo chmod 600 /etc/eracun/.age-key
```

3. **Verify recovery:**
```bash
# Start service
systemctl start eracun-cert-lifecycle-manager

# Check health
curl http://localhost:8087/health

# List certificates
curl http://localhost:8087/api/v1/certificates | jq 'length'
```

4. **Reconciliation:**
```sql
-- Identify certificates uploaded since last backup
SELECT cert_id, serial_number, created_at
FROM certificates
WHERE created_at > (SELECT MAX(backup_timestamp) FROM backup_log);

-- These will need to be re-uploaded manually
```

---

## Troubleshooting Guide

### Service Won't Start

**Symptom:** `systemctl start` fails

**Check:**
1. Environment variables: `cat /etc/eracun/cert-lifecycle-manager.env`
2. Database connection: `psql $DATABASE_URL -c 'SELECT 1'`
3. Port availability: `lsof -i :8087`
4. Logs: `journalctl -u eracun-cert-lifecycle-manager -n 50`

### Expiration Alerts Not Sending

**Symptom:** No alerts received despite certificates expiring soon

**Check:**
1. Cron schedule: `grep EXPIRATION_CHECK_CRON /etc/eracun/cert-lifecycle-manager.env`
2. Notification service: `curl http://localhost:8088/health`
3. Last check time: `journalctl -u eracun-cert-lifecycle-manager | grep "expiration check"`
4. Alert configuration: Check notification-service templates exist

### Certificate Parsing Fails

**Symptom:** Upload fails with parsing error

**Check:**
1. File format: `file certificate.p12` (should be "data" or "PKCS#12")
2. Password correct: Test with `openssl pkcs12 -in certificate.p12 -noout -passin pass:$PASSWORD`
3. Issuer valid: Extract and verify issuer is FINA or AKD
4. Not expired: Check certificate dates

---

## Change Log

| Date | Change | Author |
|------|--------|--------|
| 2025-11-12 | Initial runbook | System |

---

## Document Review

**Review Frequency:** Quarterly
**Next Review:** 2026-02-12
**Document Owner:** Platform Team Lead
