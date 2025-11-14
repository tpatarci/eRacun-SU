# TASK 9: Disaster Recovery and Rollback Readiness

## Task Priority
**CRITICAL** - System must maintain operations for legal compliance

## Objective
Validate disaster recovery procedures, rollback capabilities, and business continuity plans to ensure the system can recover from failures within defined RTO/RPO targets and maintain compliance during incidents.

## Scope
Comprehensive DR testing covering:
- Backup and restore procedures
- Rollback mechanisms (<5 minutes)
- Failover capabilities
- Data recovery validation
- Business continuity planning
- Incident response procedures

## Detailed Approach

### 1. Backup Verification (Day 1)
**Current backup status:**
```bash
# Check PostgreSQL backups
ls -la /backup/postgres/
pg_dump --version

# Verify WAL archiving
psql -c "SELECT * FROM pg_stat_archiver;"

# Test backup integrity
pg_restore --list /backup/postgres/latest.dump | head -20

# Check backup encryption
file /backup/postgres/*.dump.gpg
```

**Backup checklist:**
- [ ] Daily full backups running
- [ ] WAL archiving enabled
- [ ] Backups encrypted (GPG/AES-256)
- [ ] Offsite copies created
- [ ] 30-day retention verified
- [ ] Backup monitoring active

### 2. Recovery Time Testing (Day 1-2)
**RTO validation (1 hour target):**
```bash
# Simulate database failure and recovery
START_TIME=$(date +%s)

# Stop database
systemctl stop postgresql

# Restore from backup
pg_restore -d eracun /backup/postgres/latest.dump

# Start database
systemctl start postgresql

# Verify data integrity
psql -c "SELECT COUNT(*) FROM invoices;"

END_TIME=$(date +%s)
RECOVERY_TIME=$((END_TIME - START_TIME))
echo "Recovery completed in ${RECOVERY_TIME} seconds"
```

**Recovery targets:**
- [ ] RTO: 1 hour achieved
- [ ] RPO: 5 minutes achieved
- [ ] Service restoration automated
- [ ] Data integrity maintained
- [ ] Audit trail preserved
- [ ] Compliance data intact

### 3. Service Rollback Testing (Day 2)
**Quick rollback (<5 minutes):**
```bash
# Deploy bad version
rsync -avz bad-version/ /opt/eracun/services/invoice-gateway-api/

# Service fails
systemctl status eracun-invoice-gateway-api

# Execute rollback
sudo rsync -avz \
  /opt/eracun/backups/invoice-gateway-api-prev/ \
  /opt/eracun/services/invoice-gateway-api/

sudo systemctl restart eracun-invoice-gateway-api

# Verify service restored
curl http://localhost:3001/health
```

**Rollback procedures checklist:**
- [ ] Previous version archived
- [ ] Rollback script tested
- [ ] <5 minute execution time
- [ ] Database migrations reversible
- [ ] Configuration rollback included
- [ ] Zero data loss confirmed

### 4. Failover Simulation (Day 2-3)
**Primary server failure:**
```bash
# Simulate primary failure
ssh primary-server sudo shutdown -h now

# Verify secondary takes over
ssh secondary-server systemctl status eracun-*

# Test service availability
for endpoint in api.eracun.hr staging.eracun.internal; do
  curl -f https://${endpoint}/health || echo "FAILED: ${endpoint}"
done
```

**Failover capabilities:**
- [ ] Secondary server ready
- [ ] Database replication working
- [ ] Load balancer switches automatically
- [ ] DNS failover configured
- [ ] Message queues replicated
- [ ] Monitoring alerts triggered

### 5. Data Recovery Validation (Day 3)
**Point-in-time recovery test:**
```bash
# Restore to specific timestamp
RECOVERY_TARGET="2025-11-13 14:30:00"

# Create recovery instance
pg_basebackup -h localhost -D /tmp/recovery

# Configure recovery
cat > /tmp/recovery/recovery.conf <<EOF
recovery_target_time = '${RECOVERY_TARGET}'
recovery_target_action = 'promote'
EOF

# Start recovery instance
pg_ctl -D /tmp/recovery start

# Verify data at target time
psql -p 5433 -c "SELECT COUNT(*) FROM invoices WHERE created_at < '${RECOVERY_TARGET}';"
```

**PITR validation checklist:**
- [ ] Any point within 30 days recoverable
- [ ] Transaction consistency maintained
- [ ] Foreign keys intact
- [ ] No phantom reads
- [ ] Archive logs accessible
- [ ] Recovery documented

### 6. Business Continuity Testing (Day 3-4)
**Critical function validation during outage:**
- [ ] Invoice submission queued
- [ ] Validation continues offline
- [ ] FINA submissions retry automatically
- [ ] Archive remains accessible
- [ ] Audit logging uninterrupted
- [ ] Compliance maintained

**Manual procedures ready:**
```bash
# Generate compliance report manually
./scripts/emergency-compliance-report.sh

# Export critical data
./scripts/export-pending-invoices.sh

# Switch to manual processing
./scripts/enable-manual-mode.sh
```

### 7. Incident Response Drill (Day 4)
**Runbook execution:**
1. **Detection** - Alert received
2. **Assessment** - Impact determined
3. **Communication** - Stakeholders notified
4. **Mitigation** - Service restored
5. **Resolution** - Root cause fixed
6. **Post-mortem** - Lessons learned

**Response team checklist:**
- [ ] On-call roster current
- [ ] Escalation paths defined
- [ ] Communication templates ready
- [ ] Runbooks accessible
- [ ] War room procedures known
- [ ] Regulatory notification process

## Required Tools
- pg_dump/pg_restore for PostgreSQL
- rsync for file synchronization
- Backup verification scripts
- Monitoring dashboards
- Communication tools (Slack/PagerDuty)
- Documentation wiki

## Pass/Fail Criteria

### MUST PASS (DR requirements)
- ✅ RTO <1 hour demonstrated
- ✅ RPO <5 minutes achieved
- ✅ Rollback <5 minutes
- ✅ All data recoverable
- ✅ Compliance maintained during incident

### RED FLAGS (DR failures)
- ❌ Backup corruption detected
- ❌ Recovery exceeds RTO
- ❌ Data loss beyond RPO
- ❌ Rollback procedures fail
- ❌ No failover capability

## Deliverables
1. **DR Test Report** - All scenarios with timings
2. **Recovery Runbooks** - Step-by-step procedures
3. **Backup Verification Log** - Integrity confirmed
4. **BCP Documentation** - Business continuity plan
5. **Incident Response Plan** - Team procedures

## Time Estimate
- **Duration:** 4 days
- **Effort:** 1 senior engineer + operations team
- **Prerequisites:** Backup systems operational

## Risk Factors
- **Critical Risk:** No viable backups
- **High Risk:** Recovery time exceeds RTO
- **High Risk:** Untested procedures
- **Medium Risk:** Team unfamiliar with runbooks
- **Low Risk:** Minor data inconsistencies

## Escalation Path
During disaster:
1. Activate incident commander
2. Open war room (physical/virtual)
3. Execute relevant runbook
4. Communicate status every 30 minutes
5. Post-incident review within 48 hours

## DR Architecture
```
┌──────────────┐        ┌──────────────┐
│   Primary    │◄──────►│  Secondary   │
│   Droplet    │  Sync  │   Droplet    │
└──────┬───────┘        └──────┬───────┘
       │                       │
       ▼                       ▼
┌──────────────┐        ┌──────────────┐
│  PostgreSQL  │◄──────►│  PostgreSQL  │
│   Primary    │  Stream│   Replica    │
└──────────────┘        └──────────────┘
       │
       ▼
┌──────────────┐
│   Backups    │
│  (Encrypted) │
│   Off-site   │
└──────────────┘
```

## Related Documentation
- @docs/DEPLOYMENT_GUIDE.md (Section 6: Rollback Procedure)
- @docs/OPERATIONS.md (Disaster Recovery section)
- @docs/operations/incident-response.md
- @docs/runbooks/database-recovery.md
- @docs/runbooks/service-rollback.md

## DR Checklist
- [ ] Backups automated and verified
- [ ] Recovery procedures documented
- [ ] Failover tested monthly
- [ ] Rollback tested weekly
- [ ] Team trained quarterly
- [ ] Runbooks updated regularly
- [ ] Contact list current
- [ ] Vendor support contracts active
- [ ] Insurance coverage adequate
- [ ] Compliance requirements met during DR

## Notes
Disaster recovery capability is essential for maintaining compliance during incidents. The system must be able to continue processing invoices or queue them reliably during outages. Regular DR drills are mandatory.