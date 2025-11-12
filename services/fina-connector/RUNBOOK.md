# FINA Connector Service - Operational Runbook

**Service:** fina-connector
**Purpose:** B2C invoice fiscalization with Croatian Tax Authority (FINA)
**On-Call Priority:** P1 (15-minute response time)

---

## Quick Reference

### Service Status
```bash
# Check service status
systemctl status eracun-fina-connector

# View recent logs
journalctl -u eracun-fina-connector -n 100 --no-pager

# Check health endpoint
curl http://localhost:3003/health

# Check metrics
curl http://localhost:3003/metrics | grep fina_
```

### Emergency Contacts
- **FINA Support:** 01 4404 707 (Mon-Fri 08:00-16:00)
- **Platform Team:** [Insert on-call contact]
- **Database Admin:** [Insert DBA contact]

---

## Common Incidents

### 1. High Error Rate (CRITICAL)

**Alert:** `FINAHighErrorRate`
**Symptoms:** `fina_fiscalization_total{status="failure"}` increasing rapidly

#### Diagnosis

1. Check error distribution:
```bash
curl -s http://localhost:3003/metrics | grep 'fina_errors_total'
```

2. Review recent logs:
```bash
journalctl -u eracun-fina-connector -n 50 | grep ERROR
```

3. Common error codes:
   - `s:001` - Invalid request format
   - `s:002` - Invalid ZKI code
   - `s:003` - Certificate validation failed
   - `s:004` - Duplicate invoice
   - `NETWORK_ERROR` - FINA unavailable

#### Resolution

**For `s:003` (Certificate expired):**
```bash
# Check certificate status
curl http://localhost:3002/api/v1/certificates

# If expired, restart digital-signature-service with new certificate
systemctl restart eracun-digital-signature
```

**For `NETWORK_ERROR` (FINA unavailable):**
```bash
# Verify FINA endpoint
curl -I https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl

# Check offline queue stats
curl http://localhost:3003/queue/stats

# If offline queue enabled, invoices will be queued automatically
# Monitor queue depth and wait for FINA recovery
```

**For `s:001` or `s:002` (Data validation errors):**
```bash
# Check incoming message format in RabbitMQ
# These indicate upstream data quality issues
# Escalate to data ingestion team
```

#### Verification
```bash
# Monitor error rate decreasing
watch -n 5 'curl -s http://localhost:3003/metrics | grep fina_fiscalization_total'
```

---

### 2. Offline Queue Growing (WARNING)

**Alert:** `FINAOfflineQueueGrowing`
**Symptoms:** `fina_offline_queue_depth > 100`

#### Diagnosis

1. Check queue stats:
```bash
curl http://localhost:3003/queue/stats
```

2. Check FINA API availability:
```bash
curl -I https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl
```

3. Check service logs for patterns:
```bash
journalctl -u eracun-fina-connector -n 200 | grep -E '(offline|queue|retry)'
```

#### Resolution

**If FINA is down (planned maintenance):**
- Offline queue will handle up to 48 hours of requests
- Monitor queue depth
- Ensure database has capacity (estimate 1KB per entry)
- No immediate action required if queue age < 36 hours

**If FINA is down (unplanned outage):**
```bash
# Estimate queue capacity
QUEUE_DEPTH=$(curl -s http://localhost:3003/queue/stats | jq '.pending')
HOURS_REMAINING=$(echo "scale=2; (48 - ($QUEUE_DEPTH * 0.01))" | bc)

echo "Queue can handle $HOURS_REMAINING more hours"

# If < 12 hours remaining, contact FINA support immediately
```

**If queue growing despite FINA being available:**
```bash
# Check for stuck processing
curl -s http://localhost:3003/queue/stats | jq '.processing'

# If processing count is high, restart service
systemctl restart eracun-fina-connector
```

#### Verification
```bash
# Monitor queue depth stabilizing
watch -n 10 'curl -s http://localhost:3003/queue/stats'
```

---

### 3. Offline Queue Expiring Soon (URGENT)

**Alert:** `FINAOfflineQueueExpiringSoon`
**Symptoms:** `fina_offline_queue_max_age_seconds > 172800` (48 hours)

#### Immediate Actions

⚠️ **This is urgent** - invoices will lose fiscalization compliance if not submitted within 48 hours.

1. Check oldest entry age:
```bash
curl -s http://localhost:3003/queue/stats | jq '.oldestEntryAge'
```

2. Check FINA API status:
```bash
curl https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl
```

3. If FINA is available but queue not draining:
```bash
# Check service status
systemctl status eracun-fina-connector

# If service stuck, restart immediately
systemctl restart eracun-fina-connector

# Monitor queue processing
journalctl -u eracun-fina-connector -f | grep 'offline queue'
```

4. If FINA unavailable:
```bash
# Escalate to FINA support IMMEDIATELY (01 4404 707)
# Document expected data loss
# Notify compliance team
```

#### Post-Incident

- Review failed invoices:
```sql
SELECT invoice_id, created_at, last_error
FROM offline_queue
WHERE status = 'failed'
ORDER BY created_at DESC;
```

- Generate incident report
- Notify affected customers
- Review 48-hour grace period sufficiency

---

### 4. Service Crash Loop (CRITICAL)

**Symptoms:** Service repeatedly restarting

#### Diagnosis

1. Check service status:
```bash
systemctl status eracun-fina-connector
```

2. Review startup logs:
```bash
journalctl -u eracun-fina-connector -n 100 --no-pager
```

3. Common causes:
   - Database connection failure
   - RabbitMQ connection failure
   - Missing environment variables
   - WSDL loading failure

#### Resolution

**For database connection failure:**
```bash
# Test database connectivity
psql $DATABASE_URL -c 'SELECT 1'

# If database unavailable, check PostgreSQL service
systemctl status postgresql
```

**For RabbitMQ connection failure:**
```bash
# Check RabbitMQ status
systemctl status rabbitmq-server

# Check connection string
grep RABBITMQ_URL /etc/eracun/fina-connector.env
```

**For missing environment variables:**
```bash
# Verify environment file
cat /etc/eracun/fina-connector.env

# Compare with .env.example
diff /etc/eracun/fina-connector.env /opt/eracun/services/fina-connector/.env.example
```

**For WSDL loading failure:**
```bash
# Test FINA WSDL endpoint
curl -I $(grep FINA_WSDL_URL /etc/eracun/fina-connector.env | cut -d= -f2)

# If FINA unavailable, service will fail to start
# Temporary workaround: Use cached WSDL (if available)
```

---

### 5. Slow Processing (PERFORMANCE)

**Symptoms:** `fina_fiscalization_duration_seconds{quantile="0.99"} > 10s`

#### Diagnosis

1. Check latency distribution:
```bash
curl -s http://localhost:3003/metrics | grep fina_fiscalization_duration_seconds
```

2. Check component latencies:
```bash
# Digital signature service response time
curl -w "@-" -o /dev/null -s http://localhost:3002/health <<'EOF'
time_total: %{time_total}s
EOF

# FINA API response time (via logs)
journalctl -u eracun-fina-connector -n 100 | grep 'duration_ms'
```

3. Common causes:
   - Digital signature service slow
   - FINA API slow
   - Database query slow (offline queue)
   - RabbitMQ backpressure

#### Resolution

**For digital signature service slow:**
```bash
# Check signature service load
curl http://localhost:3002/metrics | grep duration

# If overloaded, scale horizontally or restart
systemctl restart eracun-digital-signature
```

**For FINA API slow:**
- Check FINA status page (if available)
- Contact FINA support if persistent
- No action required - retry logic will handle

**For database slow:**
```bash
# Check database connections
curl -s http://localhost:3003/metrics | grep pg_pool

# Check slow queries
psql $DATABASE_URL -c "SELECT query, mean_exec_time FROM pg_stat_statements WHERE mean_exec_time > 1000 ORDER BY mean_exec_time DESC LIMIT 10;"

# If queue table large, clean up old entries
psql $DATABASE_URL -c "DELETE FROM offline_queue WHERE created_at < NOW() - INTERVAL '48 hours';"
```

---

## Maintenance Procedures

### Routine Maintenance

#### Weekly Tasks
```bash
# Check offline queue health
curl http://localhost:3003/queue/stats

# Review error logs for patterns
journalctl -u eracun-fina-connector --since "1 week ago" | grep ERROR | sort | uniq -c

# Verify certificate expiration
curl http://localhost:3002/api/v1/certificates | jq '.certificates[].validTo'
```

#### Monthly Tasks
```bash
# Clean up expired queue entries (automatic, but verify)
psql $DATABASE_URL -c "SELECT COUNT(*) FROM offline_queue WHERE created_at < NOW() - INTERVAL '48 hours';"

# Review metrics trends
# Check Grafana dashboard (if available)

# Test disaster recovery
# Simulate FINA outage and verify offline queue behavior
```

### Certificate Renewal

FINA certificates expire every 5 years. Renewal required 30 days before expiration.

#### Renewal Process

1. Check current certificate expiration:
```bash
curl http://localhost:3002/api/v1/certificates | jq '.certificates[].validTo'
```

2. Obtain new certificate from FINA:
   - Contact FINA support (01 4404 707)
   - Request certificate renewal
   - Wait 5-10 business days

3. Install new certificate:
```bash
# Copy certificate to secure location
sudo cp new-certificate.p12 /etc/eracun/certificates/fina-production.p12
sudo chmod 600 /etc/eracun/certificates/fina-production.p12
sudo chown eracun:eracun /etc/eracun/certificates/fina-production.p12

# Restart digital-signature-service
systemctl restart eracun-digital-signature
systemctl status eracun-digital-signature

# Verify new certificate loaded
curl http://localhost:3002/api/v1/certificates
```

4. Restart fina-connector:
```bash
systemctl restart eracun-fina-connector
```

5. Verify fiscalization working:
```bash
# Monitor successful fiscalizations
watch -n 5 'curl -s http://localhost:3003/metrics | grep fina_jir_received_total'
```

### Database Maintenance

#### Backup
```bash
# Backup offline queue (before maintenance)
pg_dump -h localhost -U eracun -d eracun_fina -t offline_queue > offline_queue_backup.sql
```

#### Index Maintenance
```sql
-- Reindex if query performance degrades
REINDEX TABLE offline_queue;

-- Analyze table statistics
ANALYZE offline_queue;
```

#### Storage Cleanup
```sql
-- Remove failed entries older than 7 days (after investigation)
DELETE FROM offline_queue
WHERE status = 'failed'
  AND created_at < NOW() - INTERVAL '7 days';

-- Vacuum table
VACUUM ANALYZE offline_queue;
```

### Deployment Procedure

#### Rolling Deployment

1. Pull latest code:
```bash
cd /opt/eracun/services/fina-connector
git pull origin main
```

2. Install dependencies:
```bash
npm install
```

3. Build:
```bash
npm run build
```

4. Run tests:
```bash
npm test
```

5. Restart service:
```bash
systemctl restart eracun-fina-connector
```

6. Verify health:
```bash
# Wait 10 seconds for startup
sleep 10

# Check health
curl http://localhost:3003/health

# Monitor logs
journalctl -u eracun-fina-connector -f
```

7. Monitor metrics for 5 minutes:
```bash
# Check error rate
watch -n 5 'curl -s http://localhost:3003/metrics | grep fina_fiscalization_total'
```

8. Rollback if issues:
```bash
# Stop service
systemctl stop eracun-fina-connector

# Restore previous version
git checkout <previous-commit>
npm install
npm run build

# Start service
systemctl start eracun-fina-connector
```

---

## Monitoring Dashboards

### Key Metrics to Monitor

1. **Fiscalization Success Rate**
   ```
   rate(fina_fiscalization_total{status="success"}[5m]) /
   rate(fina_fiscalization_total[5m])
   ```

2. **Latency (P99)**
   ```
   histogram_quantile(0.99, fina_fiscalization_duration_seconds_bucket)
   ```

3. **Error Rate**
   ```
   rate(fina_fiscalization_total{status="failure"}[5m])
   ```

4. **Offline Queue Depth**
   ```
   fina_offline_queue_depth
   ```

5. **Oldest Queue Entry**
   ```
   fina_offline_queue_max_age_seconds / 3600  # Convert to hours
   ```

### Grafana Dashboard

Recommended panels:
- Fiscalization throughput (req/sec)
- Success vs failure rate
- Latency heatmap
- Offline queue size over time
- Error distribution by code

---

## Emergency Procedures

### Complete Service Failure

1. **Assess impact:**
```bash
# Check how long service has been down
systemctl status eracun-fina-connector | grep 'Active:'

# Estimate queued invoices
# Assume 100 invoices/hour during business hours
```

2. **Emergency restart:**
```bash
systemctl restart eracun-fina-connector
```

3. **If restart fails:**
```bash
# Check dependencies
systemctl status postgresql rabbitmq-server

# Start dependencies if needed
systemctl start postgresql rabbitmq-server

# Retry restart
systemctl restart eracun-fina-connector
```

4. **If still failing:**
```bash
# Run service in debug mode
cd /opt/eracun/services/fina-connector
LOG_LEVEL=debug node dist/index.js
```

5. **Notify stakeholders:**
   - Customers (if public-facing)
   - Compliance team (if 48-hour deadline at risk)
   - Management (if prolonged outage)

### FINA Outage

1. **Verify outage:**
```bash
curl -I https://cis.porezna-uprava.hr:8449/FiskalizacijaService
```

2. **Enable offline queue (if not already):**
```bash
# Check configuration
grep OFFLINE_QUEUE_ENABLED /etc/eracun/fina-connector.env

# If disabled, enable and restart
echo "OFFLINE_QUEUE_ENABLED=true" >> /etc/eracun/fina-connector.env
systemctl restart eracun-fina-connector
```

3. **Monitor queue growth:**
```bash
watch -n 60 'curl -s http://localhost:3003/queue/stats'
```

4. **Estimate capacity:**
```bash
# Calculate hours until queue full (assuming 10KB/entry, 10GB database)
CURRENT_DEPTH=$(curl -s http://localhost:3003/queue/stats | jq '.pending')
RATE=100  # invoices/hour (estimate)
CAPACITY=1000000  # 1M entries

HOURS_REMAINING=$(echo "scale=2; ($CAPACITY - $CURRENT_DEPTH) / $RATE" | bc)
echo "Queue can handle $HOURS_REMAINING more hours"
```

5. **If capacity insufficient:**
   - Provision additional database storage
   - Consider alternative fiscalization methods
   - Contact FINA support for ETA

### Data Loss Prevention

If 48-hour deadline approaching:

1. **Export queued invoices:**
```sql
COPY (SELECT invoice_id, request FROM offline_queue WHERE status = 'pending')
TO '/tmp/pending_invoices.json';
```

2. **Manual fiscalization (last resort):**
   - Use FINA web portal
   - Submit critical invoices manually
   - Document manual submissions

3. **Post-recovery reconciliation:**
```sql
-- Mark manually submitted invoices as processed
UPDATE offline_queue
SET status = 'completed'
WHERE invoice_id IN ('manual-id-1', 'manual-id-2', ...);
```

---

## Escalation Procedures

### When to Escalate

| Severity | Escalation Time | Escalation Path |
|----------|----------------|----------------|
| P0 - Complete service failure | Immediate | Platform Team Lead → CTO |
| P1 - High error rate | 15 minutes | Senior Engineer → Platform Team Lead |
| P2 - Performance degradation | 1 hour | Team Channel → Senior Engineer |
| P3 - Minor issues | Next business day | Team Channel |

### Escalation Contacts

1. **Technical Issues:**
   - Platform Team: [Slack channel]
   - Database Issues: [DBA email]
   - Network Issues: [Network team]

2. **External Dependencies:**
   - FINA Support: 01 4404 707
   - Digital signature service: [Service owner]

3. **Business Impact:**
   - Compliance Team: [Contact]
   - Management: [Contact]

---

## Disaster Recovery

### RTO/RPO Targets

- **RTO (Recovery Time Objective):** 1 hour
- **RPO (Recovery Point Objective):** 5 minutes

### Recovery Procedure

1. **Restore from backup:**
```bash
# Restore database
psql $DATABASE_URL < offline_queue_backup.sql

# Restart service
systemctl start eracun-fina-connector
```

2. **Verify recovery:**
```bash
# Check offline queue
curl http://localhost:3003/queue/stats

# Monitor processing
journalctl -u eracun-fina-connector -f
```

3. **Reconciliation:**
```sql
-- Identify potentially lost invoices
SELECT invoice_id, created_at
FROM offline_queue
WHERE created_at > (SELECT MAX(created_at) FROM backup_table)
  AND status != 'completed';
```

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
