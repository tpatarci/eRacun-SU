# Disaster Recovery Procedures

**eRačun Platform - Team 3: External Integration & Compliance**

## Overview

This document defines disaster recovery procedures for the eRačun electronic invoice processing platform. These procedures ensure business continuity in the event of catastrophic failure, data loss, or security incidents.

**Recovery Objectives:**
- **RTO (Recovery Time Objective):** 1 hour
- **RPO (Recovery Point Objective):** 5 minutes

**Regulatory Requirement:** Croatian Fiskalizacija 2.0 mandates 11-year data retention. Data loss is not acceptable and may result in €66,360 fines + criminal liability.

---

## 1. Disaster Scenarios

### 1.1 Severity Levels

**Level 1 - Critical (Full System Down):**
- Complete data center outage
- Multiple server failures
- Database corruption or loss
- Security breach requiring full shutdown

**Level 2 - Major (Partial Service Outage):**
- Single service failure
- Database unavailable
- Message broker failure
- Network connectivity loss

**Level 3 - Minor (Degraded Performance):**
- High latency
- Circuit breaker trips
- Certificate expiry
- Disk space issues

### 1.2 Common Disaster Scenarios

| Scenario | Likelihood | Impact | RTO | RPO |
|----------|------------|--------|-----|-----|
| **Server hardware failure** | High | High | 1 hour | 5 min |
| **Database corruption** | Medium | Critical | 2 hours | 5 min |
| **Security breach** | Low | Critical | 4 hours | 0 (forensics) |
| **Data center outage** | Very Low | Critical | 4 hours | 5 min |
| **Certificate expiry** | Low | High | 30 min | 0 |
| **Human error (config)** | Medium | Medium | 30 min | 0 |

---

## 2. Backup Strategy

### 2.1 Database Backups (PostgreSQL)

**Continuous WAL Archiving:**
```bash
# PostgreSQL WAL archiving configuration
# /etc/postgresql/15/main/postgresql.conf

wal_level = replica
archive_mode = on
archive_command = 'cp %p /var/lib/postgresql/wal_archive/%f'
archive_timeout = 300  # 5 minutes
```

**Daily Full Backups:**
```bash
#!/bin/bash
# /usr/local/bin/postgres-backup.sh

BACKUP_DIR="/var/backups/postgresql"
DATE=$(date +%Y%m%d-%H%M%S)

# Full database dump
pg_dumpall -U postgres | gzip > $BACKUP_DIR/full-backup-$DATE.sql.gz

# Verify backup
gunzip -t $BACKUP_DIR/full-backup-$DATE.sql.gz

# Encrypt with age
age --encrypt --recipient $(cat /etc/eracun/.age-public-key) \
    $BACKUP_DIR/full-backup-$DATE.sql.gz \
    > $BACKUP_DIR/full-backup-$DATE.sql.gz.age

# Upload to offsite storage
rclone copy $BACKUP_DIR/full-backup-$DATE.sql.gz.age remote:eracun-backups/

# Retain backups: 7 daily, 4 weekly, 12 monthly
find $BACKUP_DIR -name "full-backup-*.sql.gz" -mtime +7 -delete
```

**Automated Schedule (cron):**
```cron
# Daily backups at 2 AM
0 2 * * * /usr/local/bin/postgres-backup.sh

# Weekly verification at 3 AM Sunday
0 3 * * 0 /usr/local/bin/verify-backups.sh
```

### 2.2 Application Backups

**Docker Volumes:**
```bash
# Backup Docker volumes
docker run --rm \
    -v eracun_cert_data:/data \
    -v /var/backups:/backup \
    alpine tar czf /backup/cert_data-$(date +%Y%m%d).tar.gz /data
```

**Configuration Files:**
```bash
# Backup systemd units, nginx config, etc.
tar czf /var/backups/config-$(date +%Y%m%d).tar.gz \
    /etc/systemd/system/eracun-*.service \
    /etc/nginx/ \
    /etc/eracun/

# Encrypt
age --encrypt --recipient $(cat /etc/eracun/.age-public-key) \
    /var/backups/config-$(date +%Y%m%d).tar.gz \
    > /var/backups/config-$(date +%Y%m%d).tar.gz.age
```

### 2.3 Archive Storage (11-Year Retention)

**Geographic Redundancy:**
- **Primary:** DigitalOcean Spaces (Frankfurt)
- **Secondary:** DigitalOcean Spaces (Amsterdam)
- **Tertiary:** Offline tape backup (physical safe)

**Backup Verification:**
```bash
# Monthly integrity check
#!/bin/bash
# Verify archive checksums

ARCHIVE_DIR="/mnt/archive/invoices"

find $ARCHIVE_DIR -name "*.xml" | while read file; do
    # Verify XML signature
    /usr/local/bin/verify-xml-signature.sh "$file"

    # Verify checksum
    sha256sum -c "$file.sha256"

    # Log results
    echo "$(date) $file: OK" >> /var/log/eracun/archive-verification.log
done
```

---

## 3. Recovery Procedures

### 3.1 Database Recovery

**Scenario 1: Restore from Full Backup**
```bash
#!/bin/bash
# Full database restoration

# Stop all services
systemctl stop eracun-*

# Download latest backup
rclone copy remote:eracun-backups/full-backup-latest.sql.gz.age /tmp/

# Decrypt
age --decrypt --identity /etc/eracun/.age-key \
    /tmp/full-backup-latest.sql.gz.age \
    > /tmp/full-backup-latest.sql.gz

# Decompress
gunzip /tmp/full-backup-latest.sql.gz

# Drop existing databases (CAREFUL!)
sudo -u postgres psql -c "DROP DATABASE IF EXISTS eracun_fina CASCADE;"
sudo -u postgres psql -c "DROP DATABASE IF EXISTS eracun_archive CASCADE;"

# Restore
sudo -u postgres psql < /tmp/full-backup-latest.sql

# Verify
sudo -u postgres psql -d eracun_fina -c "SELECT COUNT(*) FROM invoices;"

# Restart services
systemctl start eracun-*

# Verify services
curl http://localhost:8090/health
```

**Scenario 2: Point-in-Time Recovery (PITR)**
```bash
#!/bin/bash
# Restore to specific timestamp

TARGET_TIME="2025-11-14 14:30:00"

# Stop PostgreSQL
systemctl stop postgresql

# Restore base backup
cd /var/lib/postgresql/15/main
rm -rf *
tar xzf /var/backups/postgresql/base-backup-latest.tar.gz

# Configure recovery
cat > recovery.conf <<EOF
restore_command = 'cp /var/lib/postgresql/wal_archive/%f %p'
recovery_target_time = '$TARGET_TIME'
recovery_target_action = 'promote'
EOF

# Start PostgreSQL (enters recovery mode)
systemctl start postgresql

# Monitor recovery
tail -f /var/log/postgresql/postgresql-15-main.log
# Wait for: "LOG: database system is ready to accept connections"

# Verify
sudo -u postgres psql -d eracun_fina -c "SELECT MAX(created_at) FROM invoices;"
```

### 3.2 Service Recovery

**Scenario: Service Failure**
```bash
#!/bin/bash
# Recover failed service

SERVICE="eracun-fina-connector"

# Check service status
systemctl status $SERVICE

# Check logs
journalctl -u $SERVICE -n 100 --no-pager

# Attempt restart
systemctl restart $SERVICE

# If restart fails, redeploy from git
cd /opt/eracun/services/fina-connector
git fetch origin main
git reset --hard origin/main
npm install --production
npm run build

# Restart service
systemctl restart $SERVICE

# Verify health
curl http://localhost:8090/health

# If still failing, rollback to previous version
git log --oneline -n 10
git reset --hard <previous-commit-hash>
npm install --production
npm run build
systemctl restart $SERVICE
```

**Scenario: All Services Down (Full Outage)**
```bash
#!/bin/bash
# Full system recovery

# 1. Verify infrastructure
systemctl status postgresql
systemctl status rabbitmq-server
systemctl status nginx

# 2. Start infrastructure services
systemctl start postgresql
systemctl start rabbitmq-server
systemctl start nginx

# 3. Verify infrastructure health
pg_isready -U postgres
rabbitmqctl status
curl http://localhost/

# 4. Start application services in order
SERVICES=(
    "eracun-cert-lifecycle-manager"
    "eracun-digital-signature-service"
    "eracun-fina-connector"
    "eracun-porezna-connector"
    "eracun-archive-service"
    "eracun-reporting-service"
    "eracun-dead-letter-handler"
)

for service in "${SERVICES[@]}"; do
    echo "Starting $service..."
    systemctl start $service
    sleep 5
    systemctl status $service
done

# 5. Verify all services
for service in "${SERVICES[@]}"; do
    curl http://localhost:$(get_service_port $service)/health
done

# 6. Run smoke tests
/usr/local/bin/smoke-tests.sh
```

### 3.3 Certificate Recovery

**Scenario: Certificate Lost or Corrupted**
```bash
#!/bin/bash
# Restore FINA certificate from backup

# Decrypt certificate from git
cd /home/eracun/eRacun-development
git pull origin main
sops --decrypt secrets/certs/production.p12.enc > /tmp/production.p12

# Verify certificate
openssl pkcs12 -in /tmp/production.p12 -info -noout -passin pass:$FINA_CERT_PASSWORD

# Copy to runtime location
sudo cp /tmp/production.p12 /etc/eracun/certs/production.p12
sudo chmod 600 /etc/eracun/certs/production.p12
sudo chown eracun:eracun /etc/eracun/certs/production.p12

# Cleanup
shred -u /tmp/production.p12

# Restart digital-signature-service
systemctl restart eracun-digital-signature-service

# Verify
curl -X POST http://localhost:8088/api/v1/sign/ubl \
    -H "Content-Type: application/xml" \
    -d @tests/fixtures/sample-invoice.xml
```

### 3.4 RabbitMQ Recovery

**Scenario: Message Queue Corruption**
```bash
#!/bin/bash
# Recover RabbitMQ from backup

# Stop RabbitMQ
systemctl stop rabbitmq-server

# Backup corrupted data
mv /var/lib/rabbitmq /var/lib/rabbitmq.corrupted

# Restore from backup
tar xzf /var/backups/rabbitmq-latest.tar.gz -C /var/lib/

# Set permissions
chown -R rabbitmq:rabbitmq /var/lib/rabbitmq

# Start RabbitMQ
systemctl start rabbitmq-server

# Verify
rabbitmqctl status
rabbitmqctl list_queues

# Recreate queues if needed
/usr/local/bin/setup-rabbitmq.sh
```

---

## 4. Security Incident Response

### 4.1 Incident Detection

**Automated Alerts:**
- Failed authentication (5+ attempts)
- Unauthorized access attempts
- Certificate validation failures
- File integrity changes
- Unusual API usage patterns

**Manual Detection:**
- User reports
- Performance anomalies
- Unexpected service behavior
- Compliance audit findings

### 4.2 Incident Response Workflow

**Phase 1: Detection and Analysis (0-15 minutes)**
1. **Alert received** or incident reported
2. **Severity assessment** (Critical/High/Medium/Low)
3. **Incident commander assigned** (on-call rotation)
4. **Initial investigation** (logs, metrics, traces)
5. **Stakeholder notification** (CTO, Security Team)

**Phase 2: Containment (15-60 minutes)**
1. **Isolate affected systems**
   - Stop compromised services
   - Block suspicious IP addresses
   - Revoke compromised credentials
2. **Preserve evidence**
   - Snapshot VM/containers
   - Copy logs before rotation
   - Capture network traffic
3. **Assess damage**
   - Identify compromised data
   - Check for lateral movement
   - Verify backup integrity

**Phase 3: Eradication (1-4 hours)**
1. **Remove threat**
   - Patch vulnerabilities
   - Remove malware/backdoors
   - Rotate all credentials
2. **Forensic analysis**
   - Root cause investigation
   - Timeline reconstruction
   - Attack vector identification

**Phase 4: Recovery (4-8 hours)**
1. **Restore from clean backups**
2. **Rebuild affected systems**
3. **Gradual service restoration**
4. **Enhanced monitoring**
5. **User communication**

**Phase 5: Post-Incident (24-72 hours)**
1. **Post-mortem meeting**
2. **Incident report**
3. **Lessons learned**
4. **Process improvements**
5. **Regulatory reporting** (GDPR: 72 hours for data breaches)

### 4.3 Security Incident Playbooks

**Playbook 1: Ransomware Attack**
```bash
# IMMEDIATE ACTIONS (DO NOT DELAY)
1. Disconnect from network (prevent spread)
   sudo iptables -P INPUT DROP
   sudo iptables -P OUTPUT DROP

2. Snapshot all systems (preserve evidence)
   # DigitalOcean
   doctl compute droplet snapshot <droplet-id> --snapshot-name "ransomware-$(date +%Y%m%d)"

3. DO NOT PAY RANSOM (illegal, funds terrorism)

4. Contact authorities
   - Croatian Cyber Security Center: +385 1 6125 555
   - CERT.hr: cert@cert.hr

5. Restore from backups
   # Verify backups not encrypted
   /usr/local/bin/verify-backups.sh

   # Restore to new clean infrastructure
   /usr/local/bin/full-restore.sh
```

**Playbook 2: Data Breach**
```bash
# IMMEDIATE ACTIONS
1. Identify scope of breach
   # Check audit logs
   sudo ausearch -m USER_AUTH -sv no

2. Revoke compromised credentials
   # Rotate all API keys
   sops /etc/eracun/secrets.yaml
   # Generate new keys

3. Notify affected parties (GDPR: 72 hours)
   # Send notifications
   /usr/local/bin/breach-notification.sh

4. Engage forensics team
   # Preserve evidence
   tar czf /var/backups/forensics-$(date +%Y%m%d).tar.gz /var/log/

5. Report to authorities (if personal data)
   # AZOP (Croatian DPA): azop@azop.hr
```

**Playbook 3: Certificate Compromise**
```bash
# IMMEDIATE ACTIONS
1. Revoke certificate
   # Login to FINA CMS portal
   # Revoke certificate immediately

2. Request emergency certificate
   # Contact FINA: 01 4404 707
   # Request expedited processing

3. Deploy backup certificate (if available)
   sops --decrypt secrets/certs/backup.p12.enc > /tmp/backup.p12
   sudo cp /tmp/backup.p12 /etc/eracun/certs/production.p12
   systemctl restart eracun-digital-signature-service

4. Monitor for fraudulent signatures
   # Check all signatures in last 24 hours
   SELECT * FROM invoices WHERE created_at > NOW() - INTERVAL '24 hours';

5. Notify FINA and clients
   # Email stakeholders
   # Publish incident notice
```

---

## 5. Testing and Drills

### 5.1 Disaster Recovery Testing Schedule

**Monthly:**
- [ ] Database backup restoration (staging)
- [ ] Service failover testing
- [ ] Certificate recovery drill

**Quarterly:**
- [ ] Full system recovery drill
- [ ] Security incident simulation (tabletop exercise)
- [ ] Multi-region failover test (when applicable)

**Annually:**
- [ ] Complete disaster recovery simulation (production-like)
- [ ] Third-party disaster recovery audit
- [ ] Update disaster recovery plan

### 5.2 Test Procedure Template

```markdown
# DR Test: [Scenario Name]
Date: YYYY-MM-DD
Tester: [Name]
Environment: [staging/production]

## Objective
[What are we testing?]

## Prerequisites
- [ ] Backup exists (verified)
- [ ] Test environment prepared
- [ ] Stakeholders notified
- [ ] Rollback plan ready

## Steps
1. [Step 1]
2. [Step 2]
...

## Success Criteria
- [ ] RTO met (<1 hour)
- [ ] RPO met (<5 minutes)
- [ ] All services operational
- [ ] Data integrity verified

## Results
- Actual RTO: ___
- Actual RPO: ___
- Issues encountered: ___
- Lessons learned: ___

## Action Items
- [ ] [Action 1]
- [ ] [Action 2]
```

---

## 6. Communication Plan

### 6.1 Stakeholder Notification Matrix

| Severity | Notify Within | Stakeholders |
|----------|---------------|--------------|
| **Critical** | 15 minutes | CTO, Security Team, Compliance, All Clients |
| **High** | 30 minutes | CTO, Security Team, Affected Clients |
| **Medium** | 1 hour | DevOps Team, Account Managers |
| **Low** | 4 hours | DevOps Team (internal) |

### 6.2 Communication Templates

**Template: Critical Outage Notification**
```
Subject: [CRITICAL] eRačun Service Outage - Incident #[ID]

Dear [Client],

We are currently experiencing a critical service outage affecting [services].

Incident Details:
- Started: [Timestamp]
- Impact: [Description]
- Estimated Resolution: [Time]

Current Status:
[Brief status update]

Actions Being Taken:
1. [Action 1]
2. [Action 2]

We will provide updates every 30 minutes until resolved.

For urgent matters, contact: support@eracun.hr

Sincerely,
eRačun Team
```

---

## 7. Critical Contacts

### 7.1 Internal Team

| Role | Name | Phone | Email | Backup |
|------|------|-------|-------|--------|
| **Incident Commander** | [Name] | [Phone] | [Email] | [Backup] |
| **CTO** | [Name] | [Phone] | [Email] | - |
| **DevOps Lead** | [Name] | [Phone] | [Email] | [Backup] |
| **Security Lead** | [Name] | [Phone] | [Email] | [Backup] |

### 7.2 External Contacts

| Organization | Purpose | Contact | Phone |
|--------------|---------|---------|-------|
| **FINA** | Certificate Support | 01 4404 707 | support@fina.hr |
| **DigitalOcean** | Infrastructure | - | https://cloud.digitalocean.com/support |
| **CERT.hr** | Security Incidents | +385 1 6125 555 | cert@cert.hr |
| **AZOP** | Data Protection | - | azop@azop.hr |

---

## 8. Post-Disaster Verification

**Checklist:**
- [ ] All services operational
- [ ] Database integrity verified
- [ ] Archive storage accessible
- [ ] Backups functional
- [ ] Certificates valid
- [ ] Security scans clean
- [ ] Performance normal
- [ ] Monitoring operational
- [ ] Client notifications sent
- [ ] Post-mortem scheduled

---

## Related Documentation

- **Operations:** @docs/OPERATIONS.md
- **Security:** @docs/SECURITY.md
- **Deployment:** @docs/DEPLOYMENT_GUIDE.md
- **Certificate Management:** @docs/guides/certificate-setup-guide.md
- **RabbitMQ Migration:** @docs/guides/rabbitmq-migration-guide.md

---

**Last Updated:** 2025-11-14
**Next Review:** 2026-02-14 (Quarterly)
**Document Owner:** DevOps Team
**Emergency Contact:** +385 XX XXX XXXX
