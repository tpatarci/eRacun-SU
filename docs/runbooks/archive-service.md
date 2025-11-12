# Archive Service Operational Runbook

**Service:** archive-service
**Owner:** Platform Engineering Lead
**On-Call Escalation:** P0 incidents require immediate response
**Last Updated:** 2025-11-12

---

## Service Overview

The archive-service provides regulatory-compliant 11-year retention of e-invoices with immutable storage, digital signature verification, and forensic audit trails. This service is CRITICAL for Croatian Fiscalization Law compliance.

**Key Dependencies:**
- PostgreSQL (archive_metadata schema)
- DigitalOcean Spaces (eracun-archive-hot-eu, eracun-archive-warm-eu)
- AWS S3 Glacier Deep Archive (eracun-archive-cold-eu)
- RabbitMQ (archive.commands queue)
- digital-signature-service (signature validation)
- cert-lifecycle-manager (certificate trust bundles)

**systemd Units:**
- `archive-service.service` - REST API server
- `archive-ingest-worker.service` - RabbitMQ consumer
- `archive-verifier.timer` + `archive-verifier.service` - Monthly validation

---

## Common Operations

### Service Health Check

```bash
# Check service status
systemctl status archive-service archive-ingest-worker

# Check API health endpoint
curl -f http://localhost:9310/health || echo "API unhealthy"

# Check metrics endpoint
curl -s http://localhost:9310/metrics | grep archive_

# Check RabbitMQ queue depth
rabbitmqctl list_queues name messages | grep archive-service.ingest
```

**Expected Values:**
- API health: 200 OK
- Queue depth: <1000 messages (normal), >5000 (investigate backlog)
- Prometheus metrics: `archive_ingestion_success_total` incrementing

---

### Service Restart Procedure

**When to Restart:**
- Configuration changes deployed to `/etc/eracun/services/archive-service.conf`
- New service version deployed to `/opt/eracun/services/archive-service/`
- Memory leak suspected (RSS >2GB for extended period)
- Circuit breaker stuck open (check logs)

**Procedure:**

```bash
# 1. Verify no critical operations in progress
tail -n 100 /var/log/eracun/archive-service.log | grep "CRITICAL\|ERROR"

# 2. Gracefully stop workers (drains in-flight messages)
systemctl stop archive-ingest-worker.service

# 3. Verify queue consumer disconnected
rabbitmqctl list_consumers | grep archive-service
# Should return empty

# 4. Stop API server (drains active connections, max 30s)
systemctl stop archive-service.service

# 5. Reload systemd configuration
systemctl daemon-reload

# 6. Start services
systemctl start archive-service.service
systemctl start archive-ingest-worker.service

# 7. Verify startup
systemctl status archive-service archive-ingest-worker
curl -f http://localhost:9310/health

# 8. Monitor logs for errors
journalctl -u archive-service -u archive-ingest-worker -f
```

**Rollback Procedure:**
```bash
# If new version fails health checks
systemctl stop archive-service archive-ingest-worker
rsync -av /opt/eracun/services/archive-service.backup/ /opt/eracun/services/archive-service/
systemctl start archive-service archive-ingest-worker
```

---

## Incident Response

### P0: Archive Service Down

**Symptoms:**
- Health check returns 500 or times out
- RabbitMQ queue depth rapidly increasing
- No new documents archived (check `archive_ingestion_success_total` metric)

**Diagnosis:**

```bash
# Check service logs
journalctl -u archive-service -u archive-ingest-worker --since "10 minutes ago" | grep ERROR

# Check PostgreSQL connectivity
psql $ARCHIVE_DATABASE_URL -c "SELECT 1" || echo "Database unreachable"

# Check S3 connectivity
aws s3 ls s3://eracun-archive-hot-eu/ --endpoint-url=$SPACES_ENDPOINT || echo "S3 unreachable"

# Check RabbitMQ connectivity
rabbitmqctl cluster_status
```

**Resolution:**

1. **Database Failure:** Promote hot standby, update connection string in `/etc/eracun/services/archive-service.conf`, restart services
2. **S3 Failure:** Verify DigitalOcean status page, circuit breaker should queue messages to DLQ, escalate to infrastructure team
3. **RabbitMQ Failure:** Restart RabbitMQ server, messages should persist in durable queues
4. **OOM Killer:** Check `dmesg | grep -i kill`, increase systemd memory limit, restart service

**Escalation Path:**
- 0-15 min: On-call engineer investigates
- 15-30 min: Escalate to Platform Engineering Lead
- 30-60 min: Escalate to CTO + notify Compliance Officer (regulatory risk)

---

### P1: Archive Signature Validation Failing

**Symptoms:**
- `archive_signature_validation_failed_total` metric increasing
- Emails from `archive-verifier.service` reporting invalid signatures
- Invoices marked `signature_status = 'INVALID'` in database

**Diagnosis:**

```bash
# Query failed validations
psql $ARCHIVE_DATABASE_URL <<EOF
SELECT invoice_id, checked_at, result, failure_reason
FROM signature_integrity_checks
WHERE result = 'INVALID'
ORDER BY checked_at DESC
LIMIT 20;
EOF

# Check digital-signature-service health
curl -f http://localhost:9301/health || echo "Signature service down"

# Verify certificate trust bundles
curl -s http://localhost:9302/v1/certificates/trust-bundle | jq .
```

**Resolution:**

1. **Expired Certificates:** Expected after 5 years - mark as `EXPIRED` (not `INVALID`), log warning, no P0 escalation
2. **Corrupted XML:** Cross-check with replica bucket:
   ```bash
   aws s3 cp s3://eracun-archive-hot-eu-central/{key} /tmp/replica.xml
   aws s3 cp s3://eracun-archive-hot-eu/{key} /tmp/primary.xml
   sha512sum /tmp/primary.xml /tmp/replica.xml
   ```
   If hashes differ → data corruption, restore from replica
3. **Certificate Trust Chain Broken:** Update trust bundle from cert-lifecycle-manager, re-run validation
4. **digital-signature-service Down:** Restart service, validation will retry automatically

**Data Corruption Recovery:**
```bash
# Restore from replica bucket
INVOICE_ID="uuid-here"
OBJECT_KEY=$(psql $ARCHIVE_DATABASE_URL -t -c "SELECT object_key FROM storage_locations WHERE invoice_id='$INVOICE_ID' AND tier='HOT'")
aws s3 cp s3://eracun-archive-hot-eu-central/$OBJECT_KEY s3://eracun-archive-hot-eu/$OBJECT_KEY

# Trigger revalidation
curl -X POST http://localhost:9310/v1/archive/invoices/$INVOICE_ID/validate \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

### P1: Dead Letter Queue Accumulating Messages

**Symptoms:**
- `rabbitmqctl list_queues` shows `archive.commands.dlq` depth >100
- Ingestion failures logged (database constraints, S3 timeouts, validation errors)

**Diagnosis:**

```bash
# Inspect DLQ messages
rabbitmqctl list_queues name messages messages_ready messages_unacknowledged | grep dlq

# Sample message from DLQ (requires RabbitMQ Management plugin)
curl -u admin:$RABBITMQ_ADMIN_PASS http://localhost:15672/api/queues/%2F/archive.commands.dlq/get \
  -d '{"count":1,"ackmode":"ack_requeue_false","encoding":"auto"}' \
  -H "Content-Type: application/json" | jq .
```

**Resolution:**

1. **Transient Failures (network timeouts):** Replay DLQ after confirming dependencies healthy
2. **Schema Validation Errors:** Fix producer service (ubl-transformer, fina-connector), do NOT replay invalid messages
3. **Duplicate invoice_id:** Expected (idempotency), safe to discard
4. **Oversized Messages:** Reject at producer, implement size check before publishing

**DLQ Replay Procedure:**
```bash
# Move messages from DLQ back to main queue (requires shovel plugin)
rabbitmqctl set_parameter shovel archive-dlq-replay \
  '{"src-uri":"amqp://","src-queue":"archive.commands.dlq","dest-uri":"amqp://","dest-queue":"archive-service.ingest"}'

# Monitor replay progress
watch -n 5 'rabbitmqctl list_queues name messages | grep archive'

# Remove shovel when complete
rabbitmqctl clear_parameter shovel archive-dlq-replay
```

---

### P2: Cold Storage Restore Delayed

**Symptoms:**
- User requests invoice older than 1 year
- GET `/v1/archive/invoices/{id}` returns `202 Accepted` with restore job ID
- Restore not completing within 48-hour SLA

**Diagnosis:**

```bash
# Check Glacier restore job status
INVOICE_ID="uuid-here"
GLACIER_JOB_ID=$(psql $ARCHIVE_DATABASE_URL -t -c \
  "SELECT glacier_job_id FROM storage_locations WHERE invoice_id='$INVOICE_ID' AND tier='COLD'")

aws glacier describe-job --account-id - --vault-name eracun-archive-cold-eu \
  --job-id $GLACIER_JOB_ID --region eu-central-1
```

**Resolution:**

1. **Job Still In Progress:** Normal, Glacier Deep Archive takes 12-48 hours, notify user of SLA
2. **Job Failed:** Retry restore request:
   ```bash
   aws glacier initiate-job --account-id - --vault-name eracun-archive-cold-eu \
     --job-parameters '{"Type":"archive-retrieval","ArchiveId":"'$ARCHIVE_ID'","Tier":"Bulk"}' \
     --region eu-central-1
   ```
3. **Archive Missing:** Check audit logs for deletion event, restore from backup location, escalate to security team

---

### P2: Archive Service High Memory Usage

**Symptoms:**
- `systemctl status archive-service` shows RSS >1.5GB
- Prometheus `process_resident_memory_bytes` metric trending upward
- OOM killer warnings in `dmesg`

**Diagnosis:**

```bash
# Check current memory usage
systemctl status archive-service | grep Memory

# Heap snapshot (requires Node.js --inspect)
kill -USR2 $(pidof node)  # Triggers heap snapshot in /tmp/

# Analyze top memory consumers in logs
journalctl -u archive-service | grep "heap snapshot" | tail -n 1
```

**Resolution:**

1. **Memory Leak:** Restart service (temporary), analyze heap snapshot with Chrome DevTools, file bug report
2. **High Throughput:** Normal during batch operations, increase systemd `MemoryMax` if sustained
3. **Large Message Buffering:** Implement streaming for large XML uploads (>10MB)

**Temporary Mitigation:**
```bash
# Increase memory limit
systemctl set-property archive-service.service MemoryMax=2G
systemctl restart archive-service
```

---

## Maintenance Tasks

### Monthly: Manual Signature Validation Audit

**Trigger:** First Monday of each month (automated by `archive-verifier.timer`)

**Procedure:**

```bash
# Verify timer is enabled
systemctl status archive-verifier.timer

# Manually trigger if timer missed
systemctl start archive-verifier.service

# Monitor progress
journalctl -u archive-verifier -f

# Verify completion
psql $ARCHIVE_DATABASE_URL <<EOF
SELECT
  DATE(checked_at) as validation_date,
  result,
  COUNT(*) as count
FROM signature_integrity_checks
WHERE checked_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(checked_at), result
ORDER BY validation_date DESC;
EOF
```

**Expected Output:**
- `VALID`: >99.9% of invoices
- `EXPIRED`: <0.1% (certificates older than 5 years)
- `INVALID`: 0 (P0 escalation if >0)

---

### Quarterly: Disaster Recovery Drill

**Objective:** Verify backup/restore procedures meet RTO ≤1h, RPO ≤5m

**Procedure:**

```bash
# 1. Simulate primary region failure (dev environment only)
sudo iptables -A OUTPUT -d $PRIMARY_S3_ENDPOINT -j DROP

# 2. Update configuration to point to replica
sed -i 's/eracun-archive-hot-eu/eracun-archive-hot-eu-central/' /etc/eracun/services/archive-service.conf

# 3. Restart services
systemctl restart archive-service archive-ingest-worker

# 4. Verify failover success
curl -f http://localhost:9310/health
curl http://localhost:9310/v1/archive/invoices?limit=10 | jq .

# 5. Restore primary region connectivity
sudo iptables -D OUTPUT -d $PRIMARY_S3_ENDPOINT -j DROP
sed -i 's/eracun-archive-hot-eu-central/eracun-archive-hot-eu/' /etc/eracun/services/archive-service.conf
systemctl restart archive-service archive-ingest-worker

# 6. Document results in docs/reports/YYYY-MM-DD-dr-drill.md
```

**Pass Criteria:**
- Failover completed in <60 minutes
- No data loss (verify invoice counts match)
- All API endpoints functional on replica region

---

### Annual: Certificate Renewal

**Trigger:** 30 days before FINA certificate expiration (cert-lifecycle-manager alerts)

**Procedure:**

1. **Acquire New Certificate:** Contact FINA support (01 4404 707), 5-10 business day lead time
2. **Update Certificate Store:** Deploy new .p12 to `/etc/eracun/secrets/fina-cert-new.p12.enc` (SOPS encrypted)
3. **Update Trust Bundle:** `curl -X POST http://localhost:9302/v1/certificates/refresh`
4. **Zero-Downtime Rotation:** digital-signature-service loads new cert without restart
5. **Verify:** Test signature validation with new cert via `/validate` endpoint
6. **Archive Old Certificate:** Move old cert to `/etc/eracun/secrets/archive/fina-cert-old-YYYY.p12.enc`

**See Also:** `services/cert-lifecycle-manager/README.md` for detailed renewal procedures

---

## Monitoring & Alerting

### Key Metrics (Prometheus)

| Metric | Alert Threshold | Severity |
|--------|----------------|----------|
| `archive_ingestion_success_total` | No increase in 10 minutes | P0 |
| `archive_ingestion_failure_total` | >10/minute | P1 |
| `archive_queue_depth` | >5000 messages | P1 |
| `archive_signature_validation_failed_total` | >0 INVALID (not EXPIRED) | P0 |
| `archive_api_response_time_p95` | >500ms | P2 |
| `archive_s3_circuit_breaker_open` | open for >5 minutes | P1 |
| `archive_database_connection_pool_exhausted` | >0 | P1 |

### Log Patterns to Alert On

```bash
# P0 Alerts
journalctl -u archive-service | grep "FATAL\|Database connection pool exhausted\|S3 Object Lock failed"

# P1 Alerts
journalctl -u archive-service | grep "Circuit breaker opened\|Signature validation failed\|DLQ depth exceeded"
```

### Health Check Endpoints

```bash
# Liveness (restart if fails)
curl -f http://localhost:9310/health/live

# Readiness (remove from load balancer if fails)
curl -f http://localhost:9310/health/ready

# Metrics (Prometheus scrape)
curl http://localhost:9310/metrics
```

---

## Troubleshooting Decision Tree

```
Archive Service Issue
├── API Returns 500
│   ├── Check logs: journalctl -u archive-service | grep ERROR
│   ├── Database down? → Promote hot standby
│   ├── S3 down? → Circuit breaker should activate
│   └── OOM? → Increase memory limit, restart
├── Queue Depth Increasing
│   ├── Worker crashed? → systemctl restart archive-ingest-worker
│   ├── Database slow? → Check pg_stat_activity
│   └── S3 slow? → Check DigitalOcean status page
├── Signature Validation Failing
│   ├── Expired cert? → Mark EXPIRED (not INVALID)
│   ├── Corrupted XML? → Restore from replica
│   └── Trust chain broken? → Refresh trust bundle
└── Cold Storage Restore Delayed
    ├── Glacier job still running? → Wait (48h SLA)
    ├── Job failed? → Retry restore
    └── Archive missing? → Restore from backup, escalate
```

---

## Emergency Contacts

| Role | Contact | Availability |
|------|---------|-------------|
| On-Call Engineer | PagerDuty rotation | 24/7 |
| Platform Engineering Lead | [Email] | Business hours |
| Database Administrator | [Email] | Business hours |
| Compliance Officer | [Email] | Business hours (P0 escalation required) |
| FINA Technical Support | 01 4404 707 | Business hours |
| DigitalOcean Support | support.digitalocean.com | 24/7 (ticket) |

---

## References

- **Architecture:** `docs/adr/004-archive-compliance-layer.md`
- **Service README:** `services/archive-service/README.md`
- **Compliance Requirements:** `CLAUDE.md` §8 (Regulatory Compliance)
- **Deployment:** `deployment/systemd/archive-service.service`
- **Related Services:** `services/digital-signature-service/`, `services/cert-lifecycle-manager/`

---

**Runbook Version:** 1.0.0
**Last Reviewed:** 2025-11-12
**Next Review:** 2026-01-12 (quarterly)
