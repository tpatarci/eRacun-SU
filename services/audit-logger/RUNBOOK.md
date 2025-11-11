# Audit Logger Service - Operations Runbook

**Service:** audit-logger
**Owner:** Platform Team
**On-Call:** platform-oncall@eracun.hr
**Last Updated:** 2025-11-11

---

## Table of Contents

1. [Service Overview](#1-service-overview)
2. [Architecture](#2-architecture)
3. [Deployment](#3-deployment)
4. [Monitoring & Alerts](#4-monitoring--alerts)
5. [Incident Response](#5-incident-response)
6. [Maintenance](#6-maintenance)
7. [Troubleshooting](#7-troubleshooting)
8. [Disaster Recovery](#8-disaster-recovery)

---

## 1. Service Overview

### 1.1 Purpose

The Audit Logger service provides an **immutable, cryptographically-chained audit trail** for all invoice processing operations in the eRacun platform. This service is **mission-critical** for Croatian regulatory compliance (11-year retention requirement).

### 1.2 Key Responsibilities

- Consume audit events from Kafka topic `audit-log`
- Write events to PostgreSQL with hash chain integrity
- Provide gRPC API for audit trail queries
- Verify hash chain integrity on-demand
- Expose Prometheus metrics and health endpoints

### 1.3 Service Level Objectives (SLOs)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Availability | 99.9% | Uptime monitoring |
| Write Latency (p95) | < 200ms | Prometheus histogram |
| Query Latency (p95) | < 100ms | Prometheus histogram |
| Kafka Consumer Lag | < 100 messages | Kafka metrics |
| Data Loss | 0 events | Manual verification |

### 1.4 Dependencies

- **PostgreSQL** (managed database) - CRITICAL
- **Kafka** (message bus) - CRITICAL
- **Jaeger** (distributed tracing) - Non-critical
- **Prometheus** (metrics) - Non-critical

### 1.5 Service Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP | Health checks, metrics |
| 50051 | gRPC | Query API |

### 1.6 Key Contacts

- **Primary On-Call:** platform-oncall@eracun.hr
- **Escalation:** cto@eracun.hr
- **Database Team:** dba@eracun.hr
- **Infrastructure Team:** infra@eracun.hr

---

## 2. Architecture

### 2.1 System Diagram

```
┌─────────────────┐
│  Producer       │
│  Services       │
│  (xsd-validator,│
│   schematron,   │
│   ai-validator) │
└────────┬────────┘
         │ Publish events
         ▼
┌─────────────────┐
│  Kafka Topic    │
│  "audit-log"    │
└────────┬────────┘
         │ Consume (zero data loss)
         ▼
┌─────────────────┐        ┌─────────────────┐
│  Audit Logger   │───────▶│  PostgreSQL     │
│  Service        │ Write  │  (append-only)  │
│                 │◀───────│  Hash chain     │
└────────┬────────┘  Read  └─────────────────┘
         │
         │ gRPC API
         ▼
┌─────────────────┐
│  Query Clients  │
│  (dashboards,   │
│   reports)      │
└─────────────────┘
```

### 2.2 Data Flow

1. **Write Path** (Kafka → PostgreSQL)
   - Consumer polls Kafka topic
   - Parse JSON event payload
   - Fetch previous event hash
   - Calculate SHA-256 hash (event + previous_hash)
   - INSERT into `audit_events` table
   - Commit Kafka offset (only after successful write)

2. **Read Path** (gRPC API)
   - Client calls `GetAuditTrail(invoice_id)`
   - Query PostgreSQL: `SELECT * WHERE invoice_id = $1`
   - Return events ordered by timestamp
   - Record metrics (request count, latency)

3. **Integrity Verification**
   - Client calls `VerifyIntegrity(start_time, end_time)`
   - Fetch all events in time range
   - Iterate and verify `previous_hash` links to prior `event_hash`
   - Return list of broken chains (if any)

### 2.3 Hash Chain Structure

Each audit event contains:
```json
{
  "event_id": "evt-001",
  "previous_hash": "abc123...", // Hash of evt-000
  "event_hash": "def456...",    // SHA-256(evt-001 + previous_hash)
  ...
}
```

**Properties:**
- First event has `previous_hash = null`
- Each subsequent event links to previous event
- Any tampering breaks the chain (detected by verification)
- Immutable: No UPDATE or DELETE operations allowed

### 2.4 Database Schema

```sql
CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY,
  event_id VARCHAR(64) NOT NULL,
  invoice_id VARCHAR(64) NOT NULL,
  service_name VARCHAR(64) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  timestamp_ms BIGINT NOT NULL,
  user_id VARCHAR(64),
  request_id VARCHAR(64) NOT NULL,
  metadata JSONB NOT NULL,
  previous_hash VARCHAR(64),
  event_hash VARCHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_invoice_id ON audit_events(invoice_id);
CREATE INDEX idx_timestamp ON audit_events(timestamp_ms);
CREATE INDEX idx_service_event ON audit_events(service_name, event_type);
```

**CRITICAL:** Do not add UPDATE or DELETE triggers. Append-only.

---

## 3. Deployment

### 3.1 Prerequisites

- Ubuntu 22.04 LTS or Debian 12+ droplet
- Node.js 20.x installed
- PostgreSQL 14+ (managed database recommended)
- Kafka 3.x accessible
- `eracun` system user created

### 3.2 Initial Deployment

```bash
# 1. Create user
sudo useradd -r -s /bin/false -U eracun

# 2. Create directories
sudo mkdir -p /opt/eracun/services/audit-logger
sudo mkdir -p /etc/eracun
sudo mkdir -p /run/eracun
sudo mkdir -p /opt/eracun/services/audit-logger/logs

# 3. Deploy service files
cd /path/to/eRacun-development/services/audit-logger
npm run build
sudo rsync -av dist/ /opt/eracun/services/audit-logger/dist/
sudo rsync -av node_modules/ /opt/eracun/services/audit-logger/node_modules/
sudo rsync -av proto/ /opt/eracun/services/audit-logger/proto/
sudo rsync -av package.json /opt/eracun/services/audit-logger/

# 4. Set permissions
sudo chown -R eracun:eracun /opt/eracun/services/audit-logger
sudo chown -R eracun:eracun /run/eracun
sudo chmod 700 /etc/eracun

# 5. Create environment file
sudo cp .env.example /etc/eracun/audit-logger.env
sudo nano /etc/eracun/audit-logger.env  # Edit with production values
sudo chown root:eracun /etc/eracun/audit-logger.env
sudo chmod 640 /etc/eracun/audit-logger.env

# 6. Initialize database
psql -h <db-host> -U <db-user> -d audit_log < schema.sql

# 7. Install systemd unit
sudo cp deployment/eracun-audit-logger.service /etc/systemd/system/
sudo systemctl daemon-reload

# 8. Enable and start
sudo systemctl enable eracun-audit-logger
sudo systemctl start eracun-audit-logger

# 9. Verify
sudo systemctl status eracun-audit-logger
curl http://localhost:8080/health
curl http://localhost:8080/metrics
```

### 3.3 Rolling Update

```bash
# 1. Build new version locally
npm run build

# 2. Transfer to droplet
rsync -av dist/ user@droplet:/tmp/audit-logger-dist/

# 3. SSH into droplet
ssh user@droplet

# 4. Stop service
sudo systemctl stop eracun-audit-logger

# 5. Backup current version
sudo cp -r /opt/eracun/services/audit-logger/dist \
           /opt/eracun/services/audit-logger/dist.backup

# 6. Deploy new version
sudo rsync -av /tmp/audit-logger-dist/ \
           /opt/eracun/services/audit-logger/dist/
sudo chown -R eracun:eracun /opt/eracun/services/audit-logger/dist

# 7. Start service
sudo systemctl start eracun-audit-logger

# 8. Verify
sleep 5
sudo systemctl status eracun-audit-logger
curl http://localhost:8080/health

# 9. Monitor logs for errors
sudo journalctl -u eracun-audit-logger -f

# 10. If errors, rollback
# sudo systemctl stop eracun-audit-logger
# sudo rm -rf /opt/eracun/services/audit-logger/dist
# sudo mv /opt/eracun/services/audit-logger/dist.backup \
#          /opt/eracun/services/audit-logger/dist
# sudo systemctl start eracun-audit-logger
```

### 3.4 Configuration Changes

```bash
# 1. Edit environment file
sudo nano /etc/eracun/audit-logger.env

# 2. Reload systemd (if unit file changed)
sudo systemctl daemon-reload

# 3. Restart service
sudo systemctl restart eracun-audit-logger

# 4. Verify
sudo systemctl status eracun-audit-logger
```

---

## 4. Monitoring & Alerts

### 4.1 Health Check

**Endpoint:** `GET http://localhost:8080/health`

**Expected Response:**
```json
{
  "status": "healthy",
  "service": "audit-logger",
  "version": "1.0.0",
  "uptime_seconds": 12345,
  "checks": {
    "database": "connected",
    "kafka": "consuming",
    "grpc": "listening"
  }
}
```

**Alert:** If status != 200, page on-call immediately (P0)

### 4.2 Prometheus Metrics

**Endpoint:** `GET http://localhost:8080/metrics`

**Key Metrics:**

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|-----------------|
| `audit_events_written_total` | Counter | Total events written | N/A |
| `audit_write_duration_seconds` | Histogram | Write latency | p99 > 1s |
| `audit_db_connections` | Gauge | Active DB connections | > 45/50 |
| `audit_kafka_lag` | Gauge | Consumer lag | > 1000 messages |
| `audit_grpc_requests_total` | Counter | gRPC request count | N/A |
| `audit_integrity_errors_total` | Counter | Hash chain errors | > 0 (CRITICAL) |
| `service_up` | Gauge | Service health | == 0 (DOWN) |

### 4.3 Alerting Rules (Prometheus)

```yaml
groups:
  - name: audit-logger
    interval: 30s
    rules:
      # P0: Service Down
      - alert: AuditLoggerDown
        expr: service_up{service="audit-logger"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Audit Logger service is down"
          description: "The audit-logger service has been down for 1 minute"

      # P0: Kafka Consumer Lag High
      - alert: AuditKafkaLagHigh
        expr: audit_kafka_lag > 1000
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Kafka consumer lag is high ({{ $value }} messages)"
          description: "Audit events are not being processed in real-time"

      # P1: Write Latency High
      - alert: AuditWriteLatencyHigh
        expr: histogram_quantile(0.99, audit_write_duration_seconds) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Audit write latency is high (p99 > 1s)"
          description: "Database may be overloaded or slow"

      # P0: Integrity Errors Detected
      - alert: AuditIntegrityError
        expr: rate(audit_integrity_errors_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Hash chain integrity errors detected!"
          description: "CRITICAL: Audit log tampering or data corruption detected"

      # P1: Database Connection Pool Exhausted
      - alert: AuditDbPoolExhausted
        expr: audit_db_connections > 45
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool near limit"
          description: "Connection pool is at {{ $value }}/50 capacity"
```

### 4.4 Log Monitoring

**Location:** `journalctl -u eracun-audit-logger`

**Key Log Patterns:**

- `"Audit event written"` - Normal operation
- `"Failed to write audit event"` - **ALERT** (data loss risk)
- `"Kafka consumer error"` - **WARNING** (check Kafka connectivity)
- `"Database connection error"` - **ALERT** (check PostgreSQL)
- `"Hash chain broken"` - **CRITICAL** (integrity violation)

**Log Aggregation:** Forward to ELK stack or Loki for centralized analysis

---

## 5. Incident Response

### 5.1 Service Down (P0)

**Symptoms:**
- Health check returns 503 or times out
- `service_up` metric == 0
- systemd reports service as failed

**Diagnosis:**
```bash
# Check service status
sudo systemctl status eracun-audit-logger

# View recent logs
sudo journalctl -u eracun-audit-logger -n 100 --no-pager

# Check process
ps aux | grep node | grep audit-logger
```

**Resolution:**
```bash
# Attempt restart
sudo systemctl restart eracun-audit-logger

# If restart fails, check logs for error
sudo journalctl -u eracun-audit-logger -f

# Common issues:
# - DATABASE_URL incorrect → Fix in /etc/eracun/audit-logger.env
# - Kafka unreachable → Check KAFKA_BROKERS
# - Port conflict → Check if 8080 or 50051 already in use
# - Out of memory → Check droplet resources

# If persistent, check dependencies
pg_isready -h <db-host> -p <db-port> -U <db-user>
telnet <kafka-host> 9092
```

**Escalation:** If service doesn't recover in 5 minutes, page DBA and Infrastructure teams

### 5.2 High Kafka Consumer Lag (P0)

**Symptoms:**
- `audit_kafka_lag` > 1000 messages
- Events not appearing in database in real-time

**Diagnosis:**
```bash
# Check consumer lag
kafka-consumer-groups --bootstrap-server <kafka-host>:9092 \
  --describe --group audit-logger-group

# Check database write performance
psql -h <db-host> -U <db-user> -d audit_log -c \
  "SELECT COUNT(*) FROM audit_events WHERE created_at > NOW() - INTERVAL '1 minute';"
```

**Resolution:**
1. **If database is slow:** Scale up managed database (more CPU/RAM)
2. **If Kafka is producing too fast:** Add more audit-logger replicas
3. **If service is crashing:** Check logs for errors, fix and restart

**Prevention:** Monitor lag proactively, scale before reaching 1000 messages

### 5.3 Hash Chain Integrity Error (P0 - CRITICAL)

**Symptoms:**
- `audit_integrity_errors_total` > 0
- Log message: "Hash chain broken - integrity violation detected"

**Diagnosis:**
```bash
# Identify broken chains
sudo journalctl -u eracun-audit-logger | grep "Hash chain broken"

# Verify integrity via gRPC API
grpcurl -plaintext -d '{"start_timestamp_ms": 0, "end_timestamp_ms": 9999999999999}' \
  localhost:50051 eracun.auditlogger.AuditLogService/VerifyIntegrity
```

**Resolution:**
1. **STOP ALL WRITES:** Immediately halt invoice processing (this is a forensic incident)
2. **Notify management:** This is a potential security breach or data corruption
3. **Isolate database:** Take snapshot for forensic analysis
4. **Investigate root cause:**
   - Database corruption (disk failure, bit flip)
   - Unauthorized access (check audit logs, database logs)
   - Bug in hash calculation (review code)
5. **Restore from backup** if tampering confirmed
6. **File incident report** for Croatian authorities (if legally required)

**Escalation:** Immediately escalate to CTO and legal team

### 5.4 Database Connection Failure (P0)

**Symptoms:**
- Log message: "Database connection error"
- Health check shows `database: "disconnected"`

**Diagnosis:**
```bash
# Test database connectivity
pg_isready -h <db-host> -p <db-port> -U <db-user>

# Test credentials
psql -h <db-host> -U <db-user> -d audit_log -c "SELECT 1;"

# Check connection pool
curl http://localhost:8080/metrics | grep audit_db_connections
```

**Resolution:**
1. **If managed database is down:** Contact DigitalOcean support immediately
2. **If credentials wrong:** Update DATABASE_URL in /etc/eracun/audit-logger.env
3. **If firewall blocking:** Check droplet firewall rules, database firewall rules
4. **If connection pool exhausted:** Restart service to reset pool

**Mitigation:** Kafka will buffer events until database recovers (no data loss)

---

## 6. Maintenance

### 6.1 Database Maintenance

**Index Maintenance (Monthly):**
```sql
-- Reindex for performance
REINDEX INDEX CONCURRENTLY idx_invoice_id;
REINDEX INDEX CONCURRENTLY idx_timestamp;
REINDEX INDEX CONCURRENTLY idx_service_event;

-- Analyze for query planner
ANALYZE audit_events;
```

**Vacuum (Weekly):**
```sql
-- Free up dead tuples (append-only still accumulates bloat)
VACUUM ANALYZE audit_events;
```

**Disk Space Monitoring:**
```sql
-- Check table size
SELECT pg_size_pretty(pg_total_relation_size('audit_events'));

-- Check growth rate
SELECT created_at::date AS day, COUNT(*) AS events
FROM audit_events
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY day
ORDER BY day DESC;
```

**Archival (11-year retention):**
- Events older than 1 year: Move to cold storage (DigitalOcean Spaces)
- Retain in hot database for fast queries (1 year)
- Automate with cron job (not implemented yet - see PENDING.md)

### 6.2 Certificate Rotation

**TLS Certificates (if enabled):**
```bash
# 1. Generate new certificates (via Let's Encrypt or FINA)
# 2. Update paths in /etc/eracun/audit-logger.env
# 3. Restart service
sudo systemctl restart eracun-audit-logger
```

### 6.3 Log Rotation

**Configure logrotate:**
```bash
# /etc/logrotate.d/eracun-audit-logger
/opt/eracun/services/audit-logger/logs/*.log {
  daily
  rotate 30
  compress
  delaycompress
  notifempty
  missingok
  create 0640 eracun eracun
  postrotate
    systemctl reload eracun-audit-logger
  endscript
}
```

### 6.4 Dependency Updates

**Node.js Updates:**
```bash
# Check current version
node --version

# Update (every 6 months)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Restart service
sudo systemctl restart eracun-audit-logger
```

**npm Package Updates:**
```bash
# Check for updates
npm outdated

# Update non-breaking (patch/minor versions)
npm update

# Test locally
npm test

# Deploy to production (follow rolling update procedure)
```

---

## 7. Troubleshooting

### 7.1 Common Issues

#### Issue: Service won't start

**Symptoms:**
```
● eracun-audit-logger.service - eRacun Audit Logger Service
   Loaded: loaded (/etc/systemd/system/eracun-audit-logger.service; enabled)
   Active: failed (Result: exit-code)
```

**Diagnosis:**
```bash
sudo journalctl -u eracun-audit-logger -n 50 --no-pager
```

**Common Causes:**
- **Missing environment variables:** Check `/etc/eracun/audit-logger.env`
- **Database unreachable:** Test with `pg_isready`
- **Port conflict:** Check if 8080 or 50051 already in use
- **File permissions:** Ensure `eracun` user can read `/opt/eracun/services/audit-logger/`
- **Missing dependencies:** Run `npm ci` in service directory

#### Issue: High memory usage

**Symptoms:**
- Droplet memory usage > 80%
- Service becomes unresponsive

**Diagnosis:**
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head -n 10

# Check Node.js heap usage
curl http://localhost:8080/metrics | grep nodejs_heap
```

**Resolution:**
- Increase droplet RAM (upgrade to higher tier)
- Set `MemoryMax` in systemd unit file
- Investigate memory leaks (profiling with clinic.js)

#### Issue: Slow queries

**Symptoms:**
- `audit_grpc_requests_total{status="success"}` latency > 200ms
- Timeouts on gRPC calls

**Diagnosis:**
```sql
-- Check slow queries
SELECT query, calls, mean_exec_time, max_exec_time
FROM pg_stat_statements
WHERE query LIKE '%audit_events%'
ORDER BY mean_exec_time DESC
LIMIT 10;

-- Check missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation
FROM pg_stats
WHERE tablename = 'audit_events'
AND n_distinct > 1000;
```

**Resolution:**
- Add indexes for common query patterns
- Increase database resources (CPU/RAM)
- Partition table by timestamp (for very large datasets)

### 7.2 Debugging Commands

```bash
# Service status
sudo systemctl status eracun-audit-logger

# Live logs
sudo journalctl -u eracun-audit-logger -f

# Logs from last hour
sudo journalctl -u eracun-audit-logger --since "1 hour ago"

# Health check
curl -v http://localhost:8080/health

# Metrics
curl http://localhost:8080/metrics

# gRPC health check (requires grpcurl)
grpcurl -plaintext localhost:50051 list

# Test database connection
pg_isready -h <db-host> -p <db-port> -U <db-user>

# Test Kafka connectivity
telnet <kafka-host> 9092

# Check open files
sudo lsof -u eracun | wc -l

# Check network connections
sudo netstat -tulpn | grep -E '8080|50051'

# Check disk space
df -h /opt/eracun

# Check service user permissions
sudo -u eracun bash -c 'cd /opt/eracun/services/audit-logger && ls -la'
```

---

## 8. Disaster Recovery

### 8.1 Backup Strategy

**Database Backups:**
- **Frequency:** Continuous WAL archiving + daily snapshots
- **Retention:** 30 days hot, 11 years cold (regulatory requirement)
- **Location:** DigitalOcean Spaces (cross-region replication)
- **Tool:** DigitalOcean Managed Database automated backups

**Configuration Backups:**
- `/etc/eracun/audit-logger.env` → Git repository (encrypted with SOPS)
- `/etc/systemd/system/eracun-audit-logger.service` → Git repository

### 8.2 Recovery Procedures

#### Scenario 1: Service Failure (Non-Database)

**RTO:** 5 minutes
**RPO:** 0 (no data loss - Kafka retains events)

**Steps:**
1. Restart service: `sudo systemctl restart eracun-audit-logger`
2. Verify health: `curl http://localhost:8080/health`
3. Monitor consumer lag: `audit_kafka_lag` should decrease to 0

#### Scenario 2: Database Corruption

**RTO:** 1 hour
**RPO:** 5 minutes (from last WAL archive)

**Steps:**
1. Stop audit-logger service: `sudo systemctl stop eracun-audit-logger`
2. Contact DigitalOcean support for managed database restore
3. Restore from latest snapshot (or PITR to 5 minutes ago)
4. Verify integrity: Run `VerifyIntegrity` gRPC call
5. Restart service: `sudo systemctl start eracun-audit-logger`
6. Monitor consumer lag: Kafka will replay missed events

#### Scenario 3: Complete Droplet Failure

**RTO:** 4 hours
**RPO:** 0 (Kafka retains events for 7 days)

**Steps:**
1. Provision new DigitalOcean droplet (same configuration)
2. Install Node.js, dependencies, systemd unit
3. Restore configuration from Git
4. Update DNS (if applicable)
5. Start service
6. Kafka will replay all events since last committed offset

#### Scenario 4: Kafka Data Loss

**RTO:** Not applicable (data already in database)
**RPO:** 0 (database is source of truth after write)

**Impact:** No data loss. Audit events are persisted to PostgreSQL before Kafka offset commit. If Kafka topic is lost, query database directly via gRPC API.

### 8.3 Recovery Testing

**Quarterly Disaster Recovery Drill:**
1. Simulate droplet failure (terminate instance)
2. Restore from backup
3. Verify all data is accessible
4. Measure RTO/RPO
5. Update runbook with lessons learned

---

## Appendix A: Quick Reference

### Common Commands

```bash
# Start service
sudo systemctl start eracun-audit-logger

# Stop service
sudo systemctl stop eracun-audit-logger

# Restart service
sudo systemctl restart eracun-audit-logger

# View status
sudo systemctl status eracun-audit-logger

# View logs (live)
sudo journalctl -u eracun-audit-logger -f

# View logs (last 100 lines)
sudo journalctl -u eracun-audit-logger -n 100

# Health check
curl http://localhost:8080/health

# Metrics
curl http://localhost:8080/metrics

# Test database
pg_isready -h <db-host> -p <db-port> -U <db-user>

# Kafka consumer lag
kafka-consumer-groups --bootstrap-server <kafka-host>:9092 \
  --describe --group audit-logger-group
```

### Environment Variables

```bash
# View current config
sudo cat /etc/eracun/audit-logger.env

# Edit config
sudo nano /etc/eracun/audit-logger.env

# Test manually
sudo -u eracun bash
source /etc/eracun/audit-logger.env
node /opt/eracun/services/audit-logger/dist/index.js
```

### gRPC API Examples

```bash
# Get audit trail for invoice
grpcurl -plaintext -d '{"invoice_id": "inv-001"}' \
  localhost:50051 eracun.auditlogger.AuditLogService/GetAuditTrail

# Query events by service
grpcurl -plaintext -d '{"service_name": "xsd-validator", "limit": 10}' \
  localhost:50051 eracun.auditlogger.AuditLogService/QueryAuditEvents

# Verify integrity (last 24 hours)
START=$(date -d '24 hours ago' +%s%3N)
END=$(date +%s%3N)
grpcurl -plaintext -d "{\"start_timestamp_ms\": $START, \"end_timestamp_ms\": $END}" \
  localhost:50051 eracun.auditlogger.AuditLogService/VerifyIntegrity
```

---

## Appendix B: Change Log

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2025-11-11 | 1.0.0 | Platform Team | Initial runbook |

---

**End of Runbook**
