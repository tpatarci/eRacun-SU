# XSD Validator Service - Operations Runbook

**Service:** xsd-validator
**Owner:** eRacun Development Team
**On-Call:** See PagerDuty/Grafana OnCall rotation
**Last Updated:** 2025-11-10

---

## Quick Reference

**Health Check:** `curl http://localhost:8080/health`
**Metrics:** `curl http://localhost:8080/metrics`
**Logs:** `journalctl -u eracun-xsd-validator -f`
**Restart:** `systemctl restart eracun-xsd-validator`

**Performance Targets:**
- Latency: <100ms p50, <200ms p95
- Throughput: 100 validations/second
- Memory: <256MB
- CPU: <1 core

---

## Table of Contents

1. [Service Overview](#service-overview)
2. [Deployment](#deployment)
3. [Monitoring](#monitoring)
4. [Common Issues](#common-issues)
5. [Troubleshooting](#troubleshooting)
6. [Maintenance](#maintenance)
7. [Disaster Recovery](#disaster-recovery)
8. [Escalation](#escalation)

---

## 1. Service Overview

### Purpose
Validates invoice XML documents against UBL 2.1 XSD schemas. First validation layer in the invoice processing pipeline.

### Dependencies

**Upstream:**
- None (entry point for validation pipeline)

**Downstream:**
- schematron-validator (receives validated XML)
- invoice-state-manager (receives validation results)

**Infrastructure:**
- RabbitMQ (message queue)
- Prometheus (metrics)
- Jaeger (tracing)

### Architecture
- **Language:** TypeScript/Node.js 20
- **Framework:** None (minimal dependencies)
- **Protocol:** RabbitMQ (AMQP)
- **Observability:** Prometheus + Jaeger + Pino

---

## 2. Deployment

### Prerequisites

**System Requirements:**
- Ubuntu 22.04 LTS or Debian 12+
- Node.js 20.x
- systemd
- 256MB RAM minimum
- 1GB disk space

**External Services:**
- RabbitMQ server (localhost:5672 or remote)
- Prometheus server (for metrics scraping)
- Jaeger collector (for tracing)

### Installation

#### Step 1: Create User

```bash
sudo adduser --system --group eracun
```

#### Step 2: Deploy Code

```bash
# Create service directory
sudo mkdir -p /opt/eracun/services/xsd-validator

# Copy built code
sudo cp -r dist/ /opt/eracun/services/xsd-validator/
sudo cp -r node_modules/ /opt/eracun/services/xsd-validator/
sudo cp -r schemas/ /opt/eracun/services/xsd-validator/
sudo cp package.json /opt/eracun/services/xsd-validator/

# Set ownership
sudo chown -R eracun:eracun /opt/eracun/services/xsd-validator
```

#### Step 3: Download Official UBL Schemas (PRODUCTION ONLY)

```bash
cd /opt/eracun/services/xsd-validator/schemas
sudo -u eracun wget http://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.zip
sudo -u eracun unzip UBL-2.1.zip
sudo -u eracun rm UBL-2.1.zip
```

**⚠️ CRITICAL:** Production deployments MUST use official UBL schemas (not minimal testing schemas).

#### Step 4: Configure Environment

```bash
# Create config directory
sudo mkdir -p /etc/eracun

# Copy environment file
sudo cp .env.example /etc/eracun/xsd-validator.env

# Edit configuration
sudo nano /etc/eracun/xsd-validator.env
```

**Required Environment Variables:**
```bash
NODE_ENV=production
LOG_LEVEL=info
RABBITMQ_URL=amqp://user:pass@localhost:5672
RABBITMQ_QUEUE=eracun.xsd-validator.xml
SCHEMA_PATH=/opt/eracun/services/xsd-validator/schemas/ubl-2.1
PROMETHEUS_PORT=9100
HEALTH_PORT=8080
JAEGER_ENDPOINT=http://localhost:14268/api/traces
```

#### Step 5: Install systemd Unit

```bash
# Copy systemd unit file
sudo cp xsd-validator.service /etc/systemd/system/eracun-xsd-validator.service

# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable eracun-xsd-validator

# Start service
sudo systemctl start eracun-xsd-validator

# Check status
sudo systemctl status eracun-xsd-validator
```

#### Step 6: Verify Deployment

```bash
# Check health endpoint
curl http://localhost:8080/health
# Expected: {"status":"ok","service":"xsd-validator"}

# Check readiness
curl http://localhost:8080/ready
# Expected: {"status":"ready","schemas_loaded":2,"rabbitmq_connected":true}

# Check metrics
curl http://localhost:8080/metrics | grep xsd_validator_up
# Expected: xsd_validator_up 1

# Check logs
journalctl -u eracun-xsd-validator -n 50
# Expected: "XSD Validator Service started successfully"
```

---

## 3. Monitoring

### Health Checks

**Liveness Probe:** `GET /health`
- Always returns 200 if process running
- Used by systemd restart logic

**Readiness Probe:** `GET /ready`
- Returns 200 if schemas loaded AND RabbitMQ connected
- Returns 503 if not ready
- Used by load balancers

### Key Metrics

**Prometheus Metrics (port 9100):**

```prometheus
# Request counter
xsd_validation_total{status="valid|invalid|error"}

# Latency histogram
xsd_validation_duration_seconds{schema_type="UBL-Invoice-2.1|UBL-CreditNote-2.1"}

# Error counter
xsd_validation_errors_total{error_type="parse|schema|internal"}

# Queue depth
xsd_validation_queue_depth

# Service status
xsd_validator_up  # 1=up, 0=down

# Schemas loaded
xsd_schemas_loaded  # Should be 2 (Invoice + CreditNote)
```

**Grafana Dashboard Queries:**

```promql
# p95 latency
histogram_quantile(0.95, rate(xsd_validation_duration_seconds_bucket[5m]))

# Error rate
rate(xsd_validation_total{status="error"}[5m])

# Throughput
rate(xsd_validation_total[5m])

# Queue depth
xsd_validation_queue_depth
```

### Alerts

**Critical Alerts (Page Immediately):**
- Service down (`xsd_validator_up == 0` for >2 minutes)
- High error rate (>5% errors for >5 minutes)
- Queue backing up (depth >1000 for >10 minutes)
- Memory >90% (OOM imminent)

**Warning Alerts (Ticket):**
- Slow validation (p95 >200ms for >10 minutes)
- Schemas not loaded (`xsd_schemas_loaded < 2`)
- RabbitMQ disconnected

### Logs

**Log Location:** journalctl (systemd) or stdout (Docker)

**Structured JSON Format:**
```json
{
  "timestamp": "2025-11-10T14:32:18.123Z",
  "level": "info",
  "service": "xsd-validator",
  "request_id": "7f3a2b8c-...",
  "invoice_id": "550e8400-...",
  "message": "XSD validation completed",
  "duration_ms": 85,
  "result": "valid"
}
```

**Log Queries:**

```bash
# All logs (last hour)
journalctl -u eracun-xsd-validator --since "1 hour ago"

# Errors only
journalctl -u eracun-xsd-validator -p err --since "1 hour ago"

# Specific invoice
journalctl -u eracun-xsd-validator | grep "550e8400"

# Follow (tail -f equivalent)
journalctl -u eracun-xsd-validator -f
```

### Tracing

**Jaeger UI:** http://localhost:16686

**Trace Search:**
- Service: `xsd-validator`
- Operation: `xsd_validation`
- Tags: `invoice.id`, `validation.result`

**Sampling:** 100% (all requests traced per TODO-008)

---

## 4. Common Issues

### Issue 1: Service Won't Start

**Symptoms:**
- systemd shows "failed" status
- Logs show error during startup

**Common Causes:**
1. **Schemas not loaded**
   - Check: `ls /opt/eracun/services/xsd-validator/schemas/ubl-2.1/maindoc/`
   - Fix: Download official UBL schemas (see Step 3 above)

2. **RabbitMQ not accessible**
   - Check: `curl -u guest:guest http://localhost:15672/api/overview`
   - Fix: Start RabbitMQ: `systemctl start rabbitmq-server`

3. **Port already in use**
   - Check: `lsof -i :8080` or `lsof -i :9100`
   - Fix: Kill conflicting process or change ports

4. **Permission denied**
   - Check: `ls -la /opt/eracun/services/xsd-validator`
   - Fix: `chown -R eracun:eracun /opt/eracun/services/xsd-validator`

**Resolution:**
```bash
# Check detailed logs
journalctl -u eracun-xsd-validator -n 100 --no-pager

# Common fixes
sudo systemctl restart rabbitmq-server
sudo systemctl restart eracun-xsd-validator
```

---

### Issue 2: High Memory Usage

**Symptoms:**
- Memory >256MB (check: `systemctl status eracun-xsd-validator`)
- OOM killer terminates service

**Common Causes:**
1. **Memory leak** (bug in code)
2. **Large XML documents** (>10MB)
3. **Schema cache not working**

**Immediate Actions:**
```bash
# Restart service (frees memory)
systemctl restart eracun-xsd-validator

# Check memory before/after
systemctl status eracun-xsd-validator | grep Memory
```

**Long-term Fix:**
1. Investigate memory leak (heap snapshot)
2. Add size limits to XML input
3. Implement schema cache eviction

---

### Issue 3: Slow Validation (p95 >200ms)

**Symptoms:**
- Metrics show high latency
- Queue backing up

**Common Causes:**
1. **CPU throttling** (systemd limits)
2. **Large documents**
3. **Schemas not cached**
4. **High load** (need horizontal scaling)

**Investigation:**
```bash
# Check CPU usage
systemctl status eracun-xsd-validator | grep CPU

# Check queue depth
curl http://localhost:8080/metrics | grep queue_depth

# Check p95 latency
curl http://localhost:8080/metrics | grep duration_seconds
```

**Fixes:**
```bash
# Increase CPU quota (if throttled)
sudo systemctl edit eracun-xsd-validator
# Add: CPUQuota=200%

# Restart
sudo systemctl daemon-reload
sudo systemctl restart eracun-xsd-validator
```

---

### Issue 4: RabbitMQ Connection Lost

**Symptoms:**
- `/ready` returns 503
- Logs show "ECONNREFUSED" or "Channel closed"

**Immediate Actions:**
```bash
# Check RabbitMQ status
systemctl status rabbitmq-server

# Check RabbitMQ queues
rabbitmqctl list_queues

# Restart xsd-validator (auto-reconnects)
systemctl restart eracun-xsd-validator
```

**Prevention:**
- RabbitMQ cluster for HA
- Connection retry logic (already implemented)
- Monitor RabbitMQ health

---

## 5. Troubleshooting

### Debugging Checklist

**Step 1: Check Service Status**
```bash
systemctl status eracun-xsd-validator
```

**Step 2: Check Logs**
```bash
journalctl -u eracun-xsd-validator -n 100
```

**Step 3: Check Health Endpoints**
```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

**Step 4: Check Dependencies**
```bash
# RabbitMQ
curl -u guest:guest http://localhost:15672/api/overview

# Prometheus
curl http://localhost:9090/-/healthy

# Jaeger
curl http://localhost:14269/
```

**Step 5: Check Resources**
```bash
# Memory
systemctl status eracun-xsd-validator | grep Memory

# CPU
systemctl status eracun-xsd-validator | grep CPU

# Disk
df -h /opt/eracun
```

### Enable Debug Logging

```bash
# Edit environment
sudo nano /etc/eracun/xsd-validator.env
# Change: LOG_LEVEL=debug

# Restart
sudo systemctl restart eracun-xsd-validator

# View debug logs
journalctl -u eracun-xsd-validator -f
```

**⚠️ WARNING:** Debug logging is verbose. Revert to `info` after troubleshooting.

### Performance Profiling

```bash
# Install profiling tools
npm install -g clinic

# Profile (requires stopping systemd service temporarily)
systemctl stop eracun-xsd-validator
cd /opt/eracun/services/xsd-validator
clinic doctor -- node dist/index.js

# Analyze results
clinic doctor --open
```

---

## 6. Maintenance

### Routine Maintenance

**Weekly:**
- [ ] Review error logs
- [ ] Check metrics dashboards
- [ ] Verify disk space >20% free

**Monthly:**
- [ ] Update dependencies (`npm audit fix`)
- [ ] Review performance trends
- [ ] Test backup/restore procedures

**Quarterly:**
- [ ] Update UBL schemas (if new version released)
- [ ] Review and optimize resource limits
- [ ] Load testing (verify SLA targets)

### Schema Updates

**When to Update:**
- New UBL version released (e.g., UBL 2.2)
- Croatian CIUS specification updated
- Bug fixes in schemas

**Update Procedure:**
```bash
# Backup current schemas
cd /opt/eracun/services/xsd-validator/schemas
sudo -u eracun tar -czf ubl-2.1-backup-$(date +%Y%m%d).tar.gz ubl-2.1/

# Download new schemas
sudo -u eracun wget http://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.zip
sudo -u eracun unzip -o UBL-2.1.zip
sudo -u eracun rm UBL-2.1.zip

# Restart service (loads new schemas)
sudo systemctl restart eracun-xsd-validator

# Verify
curl http://localhost:8080/ready
```

### Scaling

**Horizontal Scaling:**

Run multiple instances behind load balancer:

```bash
# Instance 1
sudo systemctl start eracun-xsd-validator@1

# Instance 2
sudo systemctl start eracun-xsd-validator@2
```

**When to Scale:**
- Queue depth consistently >100
- CPU usage >80%
- p95 latency >200ms

**Load Balancer:** nginx or HAProxy (round-robin RabbitMQ consumers)

---

## 7. Disaster Recovery

### Backup

**What to Backup:**
- ✅ Configuration files (`/etc/eracun/xsd-validator.env`)
- ✅ UBL schemas (`/opt/eracun/services/xsd-validator/schemas/`)
- ❌ Code (in git, redeploy from CI/CD)
- ❌ Logs (ephemeral, 90-day retention)

**Backup Procedure:**
```bash
# Create backup
tar -czf xsd-validator-backup-$(date +%Y%m%d).tar.gz \
  /etc/eracun/xsd-validator.env \
  /opt/eracun/services/xsd-validator/schemas/

# Store securely
aws s3 cp xsd-validator-backup-*.tar.gz s3://eracun-backups/
```

### Restore

**Recovery Time Objective (RTO):** <1 hour
**Recovery Point Objective (RPO):** 0 (stateless service)

**Restore Procedure:**
```bash
# 1. Provision new server
# 2. Install Node.js 20
# 3. Create eracun user
# 4. Restore from backup
aws s3 cp s3://eracun-backups/xsd-validator-backup-latest.tar.gz .
tar -xzf xsd-validator-backup-latest.tar.gz -C /

# 5. Deploy code (from CI/CD or git)
# 6. Install systemd unit
# 7. Start service
systemctl start eracun-xsd-validator

# 8. Verify
curl http://localhost:8080/health
```

### Failure Scenarios

| Scenario | Impact | Recovery | RTO |
|----------|--------|----------|-----|
| Service crash | Invoices queued | systemd auto-restart | <1 min |
| Server failure | Processing stopped | Deploy to new server | <1 hour |
| RabbitMQ failure | Queue unavailable | Failover to RabbitMQ cluster | <5 min |
| Schema corruption | Validation fails | Restore from backup | <15 min |
| Data center outage | Complete outage | Failover to DR site | <2 hours |

---

## 8. Escalation

### Severity Levels

**P0 (Critical - Page Immediately):**
- Service down for >5 minutes
- All validations failing (>90% error rate)
- Memory leak causing crashes

**P1 (High - Page During Business Hours):**
- Performance degraded (p95 >500ms)
- High error rate (10-90%)
- Queue backing up

**P2 (Medium - Ticket):**
- Isolated errors (<10%)
- Non-critical warnings
- Capacity planning needed

**P3 (Low - Backlog):**
- Feature requests
- Performance optimizations
- Documentation updates

### On-Call Contacts

**Primary On-Call:** See Grafana OnCall rotation
**Escalation Path:**
1. On-call engineer (PagerDuty/Grafana OnCall)
2. Service owner (see README.md)
3. Platform lead
4. CTO

**Communication Channels:**
- **Incident:** #incident-response (Slack)
- **Status:** #eracun-status (Slack)
- **Escalation:** on-call phone number

### Incident Response

**Step 1: Acknowledge**
- Acknowledge alert in PagerDuty/Grafana OnCall
- Post in #incident-response

**Step 2: Assess**
- Check service status
- Review logs and metrics
- Determine severity

**Step 3: Mitigate**
- Restart service (if safe)
- Apply hotfix (if available)
- Scale horizontally (if capacity issue)

**Step 4: Communicate**
- Update #incident-response every 15 minutes
- Notify stakeholders if user-facing

**Step 5: Resolve**
- Verify service restored
- Close incident ticket
- Schedule post-mortem (P0/P1 only)

**Step 6: Post-Mortem**
- Root cause analysis
- Action items to prevent recurrence
- Update runbook

---

## Appendix A: Configuration Reference

**Environment Variables:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NODE_ENV` | Yes | - | `production`, `staging`, or `development` |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, `error`, `fatal` |
| `RABBITMQ_URL` | Yes | - | AMQP connection string |
| `RABBITMQ_QUEUE` | No | `eracun.xsd-validator.xml` | Queue name |
| `SCHEMA_PATH` | No | `./schemas/ubl-2.1` | Path to UBL schemas |
| `PROMETHEUS_PORT` | No | `9100` | Metrics port |
| `HEALTH_PORT` | No | `8080` | Health check port |
| `JAEGER_ENDPOINT` | No | `http://localhost:14268/api/traces` | Jaeger collector URL |
| `MAX_CONCURRENT` | No | `100` | Max concurrent validations |

---

## Appendix B: Performance Tuning

**systemd Resource Limits:**

```ini
# /etc/systemd/system/eracun-xsd-validator.service
[Service]
MemoryMax=256M       # Increase if needed
MemoryHigh=200M      # Warning threshold
CPUQuota=100%        # Increase for better throughput
```

**RabbitMQ Prefetch:**

```javascript
// src/index.ts
await rabbitmqChannel.prefetch(100);  // Increase for throughput
```

**Node.js Heap Size:**

```bash
# If memory limits increased
NODE_OPTIONS="--max-old-space-size=512" node dist/index.js
```

---

**Document Version:** 1.0
**Last Reviewed:** 2025-11-10
**Next Review:** 2025-12-10 or after major incident
