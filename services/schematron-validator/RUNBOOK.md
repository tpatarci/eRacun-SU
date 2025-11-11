# Schematron Validator Service - Operations Runbook

**Service:** schematron-validator
**Bounded Context:** Validation Layer
**Version:** 1.0.0
**Last Updated:** 2025-11-11

---

## Quick Reference

### Health Checks

```bash
# Liveness probe (is service running?)
curl http://localhost:8081/health

# Readiness probe (is service ready?)
curl http://localhost:8081/ready

# Prometheus metrics
curl http://localhost:9101/metrics
```

### Service Management

```bash
# Status
sudo systemctl status eracun-schematron-validator

# Start
sudo systemctl start eracun-schematron-validator

# Stop
sudo systemctl stop eracun-schematron-validator

# Restart
sudo systemctl restart eracun-schematron-validator

# Enable on boot
sudo systemctl enable eracun-schematron-validator
```

### Logs

```bash
# Follow logs (real-time)
journalctl -u eracun-schematron-validator -f

# Last 100 lines
journalctl -u eracun-schematron-validator -n 100

# Logs since 1 hour ago
journalctl -u eracun-schematron-validator --since "1 hour ago"

# Logs with errors only
journalctl -u eracun-schematron-validator -p err
```

### Quick Diagnostics

```bash
# Check if service is listening
ss -tulpn | grep -E '8081|9101'

# Check RabbitMQ connection
systemctl status rabbitmq-server

# Check disk space
df -h /opt/eracun

# Check memory usage
free -h
```

---

## 1. Deployment Procedures

### 1.1 Prerequisites

**System Requirements:**
- Ubuntu 22.04 LTS or Debian 12+
- Node.js 20+
- systemd
- RabbitMQ 3.12+
- Minimum 2GB RAM
- Minimum 10GB disk space

**Network Requirements:**
- Port 8081 (HTTP health endpoints)
- Port 9101 (Prometheus metrics)
- Port 5672 (RabbitMQ)

### 1.2 Initial Deployment

**Step 1: Create Service User**

```bash
sudo adduser --system --group --no-create-home eracun
```

**Step 2: Create Directory Structure**

```bash
sudo mkdir -p /opt/eracun/services/schematron-validator
sudo mkdir -p /opt/eracun/services/schematron-validator/rules
sudo mkdir -p /opt/eracun/services/schematron-validator/logs
sudo mkdir -p /etc/eracun/services
```

**Step 3: Deploy Service Code**

```bash
# From development machine
cd services/schematron-validator
npm run build

# Copy to production
rsync -avz --delete \
  dist/ \
  node_modules/ \
  package*.json \
  production:/opt/eracun/services/schematron-validator/

# On production server
cd /opt/eracun/services/schematron-validator
npm ci --only=production
```

**Step 4: Download Croatian CIUS Rules**

⚠️ **CRITICAL:** Production MUST use official Croatian CIUS rules from Porezna Uprava.

```bash
# Download official rules (URL will be published by Porezna Uprava)
# Expected availability: September 2025
wget https://cis.porezna-uprava.hr/docs/cius-hr-core-v1.0.sch \
  -O /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch

# Verify file downloaded
ls -lh /opt/eracun/services/schematron-validator/rules/

# Verify file is valid XML
xmllint --noout /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch
```

**Alternative (if official rules not yet available):**
Contact FINA Support: 01 4404 707 or Porezna Uprava for early access.

**Step 5: Configure Environment**

```bash
# Create configuration file
sudo tee /etc/eracun/services/schematron-validator.conf > /dev/null <<'EOF'
RABBITMQ_URL=amqp://eracun:PASSWORD@rabbitmq.eracun.internal:5672
SCHEMATRON_RULES_PATH=/opt/eracun/services/schematron-validator/rules
HTTP_PORT=8081
PROMETHEUS_PORT=9101
JAEGER_AGENT_HOST=jaeger.eracun.internal
JAEGER_AGENT_PORT=14268
LOG_LEVEL=info
NODE_ENV=production
VALIDATION_TIMEOUT_MS=10000
EOF

# Secure configuration file
sudo chmod 600 /etc/eracun/services/schematron-validator.conf
sudo chown root:root /etc/eracun/services/schematron-validator.conf
```

**Step 6: Install systemd Unit**

```bash
# Copy service unit
sudo cp schematron-validator.service /etc/systemd/system/eracun-schematron-validator.service

# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable eracun-schematron-validator
```

**Step 7: Set Permissions**

```bash
sudo chown -R eracun:eracun /opt/eracun/services/schematron-validator
sudo chmod -R 755 /opt/eracun/services/schematron-validator
sudo chmod 600 /etc/eracun/services/schematron-validator.conf
```

**Step 8: Start Service**

```bash
sudo systemctl start eracun-schematron-validator
```

**Step 9: Verify Deployment**

```bash
# 1. Check service status
systemctl status eracun-schematron-validator
# Should show "active (running)"

# 2. Check health endpoint
curl http://localhost:8081/health
# Should return: {"status":"healthy","service":"schematron-validator"}

# 3. Check readiness endpoint
curl http://localhost:8081/ready
# Should return: {"status":"ready","rabbitmq":true,"rules_loaded":true}

# 4. Check metrics endpoint
curl http://localhost:9101/metrics | grep schematron_rules_loaded
# Should show rules loaded gauge > 0

# 5. Check logs for errors
journalctl -u eracun-schematron-validator -n 50
# Should not show errors
```

### 1.3 Updates and Rollbacks

**Update Procedure:**

```bash
# 1. Build new version
cd services/schematron-validator
git pull
npm run build

# 2. Stop service
ssh production
sudo systemctl stop eracun-schematron-validator

# 3. Backup current version
sudo cp -r /opt/eracun/services/schematron-validator \
         /opt/eracun/services/schematron-validator.backup.$(date +%Y%m%d-%H%M%S)

# 4. Deploy new version
rsync -avz --delete dist/ production:/opt/eracun/services/schematron-validator/dist/

# 5. Restart service
sudo systemctl start eracun-schematron-validator

# 6. Verify
curl http://localhost:8081/ready
journalctl -u eracun-schematron-validator -n 50

# 7. If successful, remove backup after 24 hours
```

**Rollback Procedure:**

```bash
# 1. Stop service
sudo systemctl stop eracun-schematron-validator

# 2. List backups
ls -lh /opt/eracun/services/ | grep schematron-validator.backup

# 3. Restore previous version
sudo rm -rf /opt/eracun/services/schematron-validator
sudo cp -r /opt/eracun/services/schematron-validator.backup.20251111-143000 \
         /opt/eracun/services/schematron-validator

# 4. Restart service
sudo systemctl start eracun-schematron-validator

# 5. Verify
curl http://localhost:8081/ready
```

---

## 2. Monitoring

### 2.1 Health Checks

**Liveness Probe:** `GET http://localhost:8081/health`
- **Purpose:** Kubernetes/load balancer liveness check
- **Expected:** 200 OK
- **Interval:** Every 30 seconds
- **Failure:** Restart service

**Readiness Probe:** `GET http://localhost:8081/ready`
- **Purpose:** Is service ready to accept traffic?
- **Expected:** 200 OK
- **Checks:** RabbitMQ connected, rules loaded
- **Failure:** Remove from load balancer

### 2.2 Key Metrics (Prometheus)

**schematron_validation_total** (Counter)
- **What:** Total validations performed
- **Labels:** status (valid/invalid/error), rule_set
- **Alert:** Error rate >5%

**schematron_validation_duration_seconds** (Histogram)
- **What:** Validation processing time
- **Labels:** rule_set
- **Normal:** p50 <500ms, p95 <1s, p99 <2s
- **Warning:** p95 >2s
- **Critical:** p95 >5s
- **Alert:** P1 if p95 >2s for 5 minutes

**schematron_rules_checked_total** (Histogram)
- **What:** Number of rules checked per validation
- **Labels:** rule_set
- **Normal:** 100-150 rules for CIUS_HR_CORE
- **Alert:** Drops below 50 (rules not loading properly)

**schematron_rules_failed_total** (Histogram)
- **What:** Number of rules failed per validation
- **Labels:** rule_set
- **Normal:** 0-5 failures
- **Alert:** Average >10 failures (data quality issue)

**schematron_rules_loaded** (Gauge)
- **What:** Number of rules currently loaded in memory
- **Labels:** rule_set
- **Normal:** >100 for CIUS_HR_CORE
- **Critical:** 0 (rules not loaded, service not ready)
- **Alert:** P0 if 0 for >1 minute

**schematron_errors_by_rule** (Counter)
- **What:** Errors counted by rule ID
- **Labels:** rule_id, rule_set
- **Use:** Identify which business rules fail most often
- **Alert:** Specific rule failures spike

**schematron_warnings_by_rule** (Counter)
- **What:** Warnings counted by rule ID
- **Labels:** rule_id, rule_set
- **Use:** Track non-critical validation issues

**schematron_rule_cache_size_bytes** (Gauge)
- **What:** Size of compiled XSLT cache in bytes
- **Normal:** 1-5 MB
- **Warning:** >10 MB
- **Alert:** >50 MB (memory leak?)

**schematron_xslt_compilation_time_seconds** (Histogram)
- **What:** Time to compile Schematron rules to XSLT
- **Labels:** rule_set
- **Normal:** <1s
- **Warning:** >2s
- **Alert:** >5s (performance issue)

### 2.3 Alerting Rules (Prometheus)

```yaml
groups:
  - name: schematron-validator
    interval: 30s
    rules:
      # P0: Service Down
      - alert: SchematronValidatorDown
        expr: up{job="schematron-validator"} == 0
        for: 1m
        labels:
          severity: critical
          priority: P0
        annotations:
          summary: "Schematron Validator service is down"
          description: "Service {{ $labels.instance }} has been down for >1 minute"
          runbook: "Check systemctl status, logs, restart service"

      # P0: No Rules Loaded
      - alert: SchematronNoRulesLoaded
        expr: schematron_rules_loaded == 0
        for: 1m
        labels:
          severity: critical
          priority: P0
        annotations:
          summary: "No Schematron rules loaded"
          description: "Service cannot validate without rules"
          runbook: "Check rules file exists, verify file permissions"

      # P1: High Error Rate
      - alert: SchematronHighErrorRate
        expr: |
          sum(rate(schematron_validation_total{status="error"}[5m]))
          /
          sum(rate(schematron_validation_total[5m]))
          > 0.05
        for: 5m
        labels:
          severity: warning
          priority: P1
        annotations:
          summary: "Schematron validation error rate >5%"
          description: "Error rate: {{ $value | humanizePercentage }}"
          runbook: "Check logs for validation errors, verify rules are correct"

      # P1: High Latency
      - alert: SchematronHighLatency
        expr: |
          histogram_quantile(0.95,
            rate(schematron_validation_duration_seconds_bucket[5m])
          ) > 2
        for: 5m
        labels:
          severity: warning
          priority: P1
        annotations:
          summary: "Schematron validation p95 latency >2s"
          description: "p95: {{ $value }}s"
          runbook: "Check CPU usage, rule cache size, consider scaling"

      # P2: Memory Warning
      - alert: SchematronHighMemory
        expr: process_resident_memory_bytes{job="schematron-validator"} > 450000000
        for: 5m
        labels:
          severity: warning
          priority: P2
        annotations:
          summary: "Schematron Validator memory usage >450MB"
          description: "Memory: {{ $value | humanize }}B"
          runbook: "Check rule cache size, consider restart"
```

### 2.4 Log Patterns to Watch

**Normal Operations:**
```
{"level":"info","service":"schematron-validator","request_id":"...","status":"VALID"}
{"level":"info","service":"schematron-validator","message":"Schematron validation completed"}
```

**Warning Signs:**
```
{"level":"warn","message":"RabbitMQ connection closed, reconnecting in 5s"}
{"level":"warn","message":"Failed to pre-load rules"}
```

**Critical Errors:**
```
{"level":"error","message":"Failed to load Schematron rules"}
{"level":"error","message":"RabbitMQ connection error"}
{"level":"error","message":"Validation timeout"}
```

### 2.5 Grafana Dashboard

**Import Dashboard:** See `deployment/grafana/dashboards/schematron-validator.json`

**Key Panels:**
1. Validation Throughput (requests/sec)
2. Success Rate (gauge)
3. Latency Percentiles (p50, p95, p99)
4. Memory Usage
5. Rules Loaded (gauge)
6. Error Rate by Rule ID
7. Rule Cache Size

---

## 3. Common Issues

### Issue 1: Service Won't Start

**Symptoms:**
- `systemctl status` shows "failed" or "activating"
- Health endpoint not responding
- Logs: "Failed to load Schematron rules"

**Diagnosis:**

```bash
# 1. Check service status
systemctl status eracun-schematron-validator

# 2. Check recent logs
journalctl -u eracun-schematron-validator -n 100

# 3. Check if rules file exists
ls -lh /opt/eracun/services/schematron-validator/rules/
# Should show: cius-hr-core.sch (or other rule files)

# 4. Check file permissions
ls -l /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch
# Should be readable by eracun user

# 5. Check RabbitMQ connectivity
systemctl status rabbitmq-server
telnet rabbitmq.eracun.internal 5672
```

**Solutions:**

**A. Rules File Missing:**
```bash
# Download rules (see Deployment section 1.2 Step 4)
wget https://cis.porezna-uprava.hr/docs/cius-hr-core-v1.0.sch \
  -O /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch

sudo chown eracun:eracun /opt/eracun/services/schematron-validator/rules/*.sch
sudo systemctl restart eracun-schematron-validator
```

**B. Wrong File Permissions:**
```bash
sudo chown -R eracun:eracun /opt/eracun/services/schematron-validator
sudo chmod 644 /opt/eracun/services/schematron-validator/rules/*.sch
sudo systemctl restart eracun-schematron-validator
```

**C. RabbitMQ Not Running:**
```bash
sudo systemctl start rabbitmq-server
# Wait 10 seconds for RabbitMQ to start
sudo systemctl restart eracun-schematron-validator
```

**D. Disk Space Full:**
```bash
df -h
# If /opt partition is full:
# - Remove old log files
# - Remove old backups
# - Expand disk
```

### Issue 2: High Memory Usage

**Symptoms:**
- Memory usage >500MB
- OOM (Out of Memory) kills
- Logs: "JavaScript heap out of memory"

**Diagnosis:**

```bash
# Check current memory usage
ps aux | grep schematron-validator

# Check systemd memory limits
systemctl show eracun-schematron-validator | grep Memory

# Check rule cache size
curl http://localhost:9101/metrics | grep schematron_rule_cache_size_bytes
```

**Solutions:**

**A. Rule Cache Too Large:**
```bash
# Restart service to clear cache
sudo systemctl restart eracun-schematron-validator

# If problem persists, increase memory limit in systemd unit
sudo systemctl edit eracun-schematron-validator
# Add:
[Service]
MemoryMax=768M

sudo systemctl daemon-reload
sudo systemctl restart eracun-schematron-validator
```

**B. Memory Leak:**
```bash
# Enable debug logging
sudo systemctl set-environment LOG_LEVEL=debug
sudo systemctl restart eracun-schematron-validator

# Monitor memory over time
watch -n 5 'ps aux | grep schematron-validator'

# If memory continuously grows, collect logs and escalate
journalctl -u eracun-schematron-validator --since "1 hour ago" > memory-leak.log
```

### Issue 3: Slow Validation (<1s → >5s)

**Symptoms:**
- `schematron_validation_duration_seconds` p95 >5s
- Timeout errors in logs
- Backlog in RabbitMQ queue

**Diagnosis:**

```bash
# Check CPU usage
top -b -n 1 | grep schematron

# Check if rules are cached
curl http://localhost:9101/metrics | grep schematron_rules_loaded

# Check validation duration
curl http://localhost:9101/metrics | grep schematron_validation_duration_seconds

# Check RabbitMQ queue depth
sudo rabbitmqctl list_queues name messages
```

**Solutions:**

**A. Rules Not Cached (Loading on Every Request):**
```bash
# Verify rules are pre-loaded
curl http://localhost:8081/ready
# Should show: "rules_loaded": true

# If false, check logs for rule loading errors
journalctl -u eracun-schematron-validator -n 100 | grep -i rule
```

**B. CPU Bottleneck:**
```bash
# Check CPU quota
systemctl show eracun-schematron-validator | grep CPUQuota

# Increase CPU quota in systemd unit
sudo systemctl edit eracun-schematron-validator
# Change:
CPUQuota=200%  # Allow 2 cores

sudo systemctl daemon-reload
sudo systemctl restart eracun-schematron-validator
```

**C. Large/Complex Documents:**
```bash
# Check validation timeout setting
grep VALIDATION_TIMEOUT_MS /etc/eracun/services/schematron-validator.conf

# Increase timeout if needed (default: 10000ms)
sudo sed -i 's/VALIDATION_TIMEOUT_MS=10000/VALIDATION_TIMEOUT_MS=15000/' \
  /etc/eracun/services/schematron-validator.conf

sudo systemctl restart eracun-schematron-validator
```

**D. Scale Horizontally:**
```bash
# Deploy additional instances behind load balancer
# Each instance processes messages from shared RabbitMQ queue
```

### Issue 4: RabbitMQ Connection Lost

**Symptoms:**
- Logs: "RabbitMQ connection error" or "Connection closed"
- `/ready` endpoint returns 503
- No validations being processed

**Diagnosis:**

```bash
# Check RabbitMQ status
systemctl status rabbitmq-server

# Check network connectivity
telnet rabbitmq.eracun.internal 5672

# Check RabbitMQ logs
journalctl -u rabbitmq-server -n 100
```

**Solutions:**

**A. RabbitMQ Crashed:**
```bash
sudo systemctl restart rabbitmq-server

# Wait 30 seconds for RabbitMQ to fully start
sleep 30

# Schematron validator will auto-reconnect
# Check logs:
journalctl -u eracun-schematron-validator -f
# Should see: "Connecting to RabbitMQ" then "RabbitMQ consumer started"
```

**B. Network Issue:**
```bash
# Check network connectivity
ping rabbitmq.eracun.internal

# Check firewall rules
sudo iptables -L | grep 5672

# Check DNS resolution
nslookup rabbitmq.eracun.internal
```

**C. Authentication Failure:**
```bash
# Verify credentials in configuration
grep RABBITMQ_URL /etc/eracun/services/schematron-validator.conf

# Test credentials manually
rabbitmqadmin -H rabbitmq.eracun.internal -u eracun -p PASSWORD list queues
```

### Issue 5: Validation Errors Spiking

**Symptoms:**
- `schematron_validation_total{status="invalid"}` increasing rapidly
- Specific rule failures dominating (e.g., BR-S-01)
- Customer complaints about rejected invoices

**Diagnosis:**

```bash
# Check error distribution by rule
curl http://localhost:9101/metrics | grep schematron_errors_by_rule

# Check recent validation logs
journalctl -u eracun-schematron-validator -n 100 | grep -i invalid

# Identify most common rule failures
journalctl -u eracun-schematron-validator --since "1 hour ago" | \
  grep -oP 'BR-[A-Z]+-\d+' | sort | uniq -c | sort -rn
```

**Solutions:**

**A. Data Quality Issue (Upstream):**
```bash
# Most common: invoices from upstream system have wrong VAT rates, OIBs, etc.
# Solution: Fix upstream system (e.g., invoice generation service)
# Temporary: Document known issues, coordinate with upstream team
```

**B. Rules Updated (New Validation Requirements):**
```bash
# Check if rules were recently updated
ls -lh /opt/eracun/services/schematron-validator/rules/

# Review rule change log (if available)
# Coordinate with business team on new requirements
```

**C. Wrong Rule Set Loaded:**
```bash
# Verify correct rules are loaded
curl http://localhost:9101/metrics | grep schematron_rules_loaded

# Check which rule file is being used
grep SCHEMATRON_RULES_PATH /etc/eracun/services/schematron-validator.conf

# Ensure correct file is present
ls /opt/eracun/services/schematron-validator/rules/
```

---

## 4. Troubleshooting

### 4.1 Systematic Debugging Process

**Step 1: Check Service Status**
```bash
systemctl status eracun-schematron-validator
```
- If "inactive" → Service stopped, start it
- If "failed" → Check logs (Step 2)
- If "active" → Service running, check dependencies (Step 3)

**Step 2: Check Logs**
```bash
journalctl -u eracun-schematron-validator -n 100
```
Look for:
- "Failed to load rules" → Rules missing or permissions issue
- "RabbitMQ connection error" → RabbitMQ down or network issue
- "Validation timeout" → Performance issue or large documents

**Step 3: Check Dependencies**
```bash
# RabbitMQ
systemctl status rabbitmq-server
telnet rabbitmq.eracun.internal 5672

# Disk space
df -h

# Memory
free -h

# Network
ping rabbitmq.eracun.internal
```

**Step 4: Check Configuration**
```bash
# Verify configuration file exists
cat /etc/eracun/services/schematron-validator.conf

# Verify rules exist
ls -lh /opt/eracun/services/schematron-validator/rules/

# Verify permissions
ls -l /opt/eracun/services/schematron-validator/
```

**Step 5: Enable Debug Logging**
```bash
sudo systemctl set-environment LOG_LEVEL=debug
sudo systemctl restart eracun-schematron-validator
journalctl -u eracun-schematron-validator -f
```

**Step 6: Test Manually**
```bash
# Test health endpoint
curl -v http://localhost:8081/health

# Test ready endpoint
curl -v http://localhost:8081/ready

# Test metrics endpoint
curl -v http://localhost:9101/metrics
```

### 4.2 Performance Profiling

```bash
# Install Node.js profiler
npm install -g clinic

# Profile service (development only)
clinic doctor -- node dist/index.js

# Analyze heap memory
clinic heapprofiler -- node dist/index.js

# Check for event loop delays
clinic bubbleprof -- node dist/index.js
```

### 4.3 Network Debugging

```bash
# Check listening ports
ss -tulpn | grep -E '8081|9101|5672'

# Trace network calls
sudo tcpdump -i any port 5672 -w rabbitmq-traffic.pcap

# Check DNS resolution
dig rabbitmq.eracun.internal

# Test connectivity
nc -zv rabbitmq.eracun.internal 5672
```

---

## 5. Maintenance

### 5.1 Routine Tasks

**Daily:**
- [ ] Check Grafana dashboard for anomalies
- [ ] Review error rate metrics
- [ ] Check disk space usage

**Weekly:**
- [ ] Review logs for warnings
- [ ] Verify all alerts are configured
- [ ] Check for available updates

**Monthly:**
- [ ] Review performance trends
- [ ] Update Schematron rules (if new version released)
- [ ] Rotate logs (journalctl automatically handles this)
- [ ] Test disaster recovery procedures

**Quarterly:**
- [ ] Review and update RUNBOOK
- [ ] Audit service security
- [ ] Capacity planning review
- [ ] Update dependencies

### 5.2 Updating Schematron Rules

**When:** Croatian Tax Authority publishes new CIUS version

**Procedure:**

```bash
# 1. Download new rules to staging
wget https://cis.porezna-uprava.hr/docs/cius-hr-core-v2.0.sch \
  -O /tmp/cius-hr-core-v2.0.sch

# 2. Validate new rules (check XML syntax)
xmllint --noout /tmp/cius-hr-core-v2.0.sch

# 3. Test in staging environment
ssh staging
sudo cp /tmp/cius-hr-core-v2.0.sch \
  /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch
sudo systemctl restart eracun-schematron-validator

# 4. Run validation tests
cd /opt/eracun/services/schematron-validator
npm test

# 5. Monitor staging for 24 hours
# - Check error rates
# - Check validation success rates
# - Review logs for unexpected errors

# 6. If successful, deploy to production
ssh production
sudo cp /tmp/cius-hr-core-v2.0.sch \
  /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch
sudo systemctl restart eracun-schematron-validator

# 7. Monitor production closely for 48 hours

# 8. Document rule update in changelog
echo "$(date): Updated CIUS rules to v2.0" >> /opt/eracun/CHANGELOG.md
```

### 5.3 Log Management

**journalctl Configuration:**

```bash
# Check current retention settings
journalctl --disk-usage

# Configure retention (keep 90 days per regulatory requirements)
sudo tee /etc/systemd/journald.conf.d/eracun.conf > /dev/null <<'EOF'
[Journal]
MaxRetentionSec=90d
MaxFileSec=1day
Compress=yes
EOF

# Restart journald
sudo systemctl restart systemd-journald

# Manually vacuum old logs (if needed)
sudo journalctl --vacuum-time=90d
```

### 5.4 Scaling

**Vertical Scaling (Single Instance):**

```bash
# Increase CPU quota
sudo systemctl edit eracun-schematron-validator
[Service]
CPUQuota=200%  # 2 cores

# Increase memory limit
MemoryMax=768M

sudo systemctl daemon-reload
sudo systemctl restart eracun-schematron-validator
```

**Horizontal Scaling (Multiple Instances):**

```bash
# Deploy additional instances
# Each instance:
# - Connects to same RabbitMQ
# - Processes messages from shared queue
# - Reports metrics to same Prometheus

# Behind load balancer (nginx/HAProxy):
upstream schematron-validator {
    server schematron-validator-01:8081;
    server schematron-validator-02:8081;
    server schematron-validator-03:8081;
}

# RabbitMQ automatically distributes work across consumers
```

---

## 6. Disaster Recovery

### 6.1 RTO/RPO

- **RTO (Recovery Time Objective):** <1 hour
- **RPO (Recovery Point Objective):** 0 minutes (stateless service)

### 6.2 Backup Strategy

**What to Backup:**
- ✅ Configuration files (`/etc/eracun/services/schematron-validator.conf`)
- ✅ Schematron rule files (`/opt/eracun/services/schematron-validator/rules/`)
- ✅ systemd unit file (`/etc/systemd/system/eracun-schematron-validator.service`)
- ❌ Service code (stored in git repository)
- ❌ Runtime state (stateless service, nothing to backup)

**Backup Procedure:**

```bash
# Automated daily backup
sudo tee /etc/cron.daily/backup-schematron-validator > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/schematron-validator/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp /etc/eracun/services/schematron-validator.conf "$BACKUP_DIR/"

# Backup rules
cp -r /opt/eracun/services/schematron-validator/rules "$BACKUP_DIR/"

# Backup systemd unit
cp /etc/systemd/system/eracun-schematron-validator.service "$BACKUP_DIR/"

# Compress
tar -czf "$BACKUP_DIR.tar.gz" -C /backup/schematron-validator "$(date +%Y%m%d)"
rm -rf "$BACKUP_DIR"

# Retain 90 days
find /backup/schematron-validator -name "*.tar.gz" -mtime +90 -delete
EOF

sudo chmod +x /etc/cron.daily/backup-schematron-validator
```

### 6.3 Recovery Scenarios

#### Scenario 1: Service Failure (Pod Crash)

**Detection:** Health check fails, Prometheus alert fires

**Recovery:**

```bash
# Kubernetes automatically restarts pod
# Manual restart if needed:
sudo systemctl restart eracun-schematron-validator

# Verify recovery
curl http://localhost:8081/health
```

**Time:** <5 minutes

#### Scenario 2: Server Failure

**Detection:** Server unresponsive, all services down

**Recovery:**

```bash
# 1. Provision new server (DigitalOcean Droplet)
# 2. Install dependencies (see Deployment section)
# 3. Restore from backup
tar -xzf /backup/schematron-validator/20251111.tar.gz -C /tmp
sudo cp /tmp/20251111/schematron-validator.conf /etc/eracun/services/
sudo cp -r /tmp/20251111/rules/* /opt/eracun/services/schematron-validator/rules/
sudo cp /tmp/20251111/eracun-schematron-validator.service /etc/systemd/system/

# 4. Deploy service code from git
git clone https://github.com/eracun/platform.git
cd platform/services/schematron-validator
npm install
npm run build
sudo cp -r dist node_modules /opt/eracun/services/schematron-validator/

# 5. Start service
sudo systemctl daemon-reload
sudo systemctl start eracun-schematron-validator

# 6. Update load balancer to new server IP
```

**Time:** 30-45 minutes

#### Scenario 3: Corrupted Rules File

**Detection:** Service fails to start, logs: "Failed to load Schematron rules"

**Recovery:**

```bash
# 1. Stop service
sudo systemctl stop eracun-schematron-validator

# 2. Backup corrupted file
sudo mv /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch \
     /tmp/cius-hr-core.sch.corrupt.$(date +%Y%m%d-%H%M%S)

# 3. Restore from backup
sudo tar -xzf /backup/schematron-validator/20251111.tar.gz -C /tmp
sudo cp /tmp/20251111/rules/cius-hr-core.sch \
     /opt/eracun/services/schematron-validator/rules/

# 4. Verify file integrity
xmllint --noout /opt/eracun/services/schematron-validator/rules/cius-hr-core.sch

# 5. Restart service
sudo systemctl start eracun-schematron-validator

# 6. Verify
curl http://localhost:8081/ready
```

**Time:** 5-10 minutes

#### Scenario 4: RabbitMQ Cluster Failure

**Detection:** All validators show "not ready", RabbitMQ connection errors

**Recovery:**

```bash
# 1. Restore RabbitMQ cluster (separate runbook)
# 2. Validators will auto-reconnect within 5-30 seconds
# 3. Monitor reconnection
journalctl -u eracun-schematron-validator -f | grep -i rabbitmq

# Should see: "RabbitMQ consumer started"
```

**Time:** Depends on RabbitMQ recovery (typically 10-30 minutes)

#### Scenario 5: Total System Failure (Data Center Down)

**Detection:** All systems unresponsive

**Recovery:**

```bash
# 1. Failover to secondary data center (if configured)
# 2. Deploy all services from scratch (see Deployment section)
# 3. Restore configurations from backup
# 4. Update DNS to point to new data center
```

**Time:** 2-4 hours (depends on infrastructure automation)

### 6.4 Testing DR Procedures

**Quarterly DR Drill:**

```bash
# 1. Simulate server failure in staging
ssh staging
sudo systemctl stop eracun-schematron-validator
# Wait 5 minutes

# 2. Recover using DR procedures
# Follow "Scenario 2: Server Failure" steps

# 3. Verify recovery
curl http://staging:8081/ready
npm test

# 4. Document drill results
echo "$(date): DR drill completed successfully" >> /opt/eracun/DR-DRILLS.md

# 5. Review and update DR procedures based on lessons learned
```

---

## 7. Escalation

### 7.1 Severity Levels

**P0 (Critical) - Page Immediately**
- Service completely down (no instances running)
- No rules loaded (cannot validate)
- Data loss or corruption
- Security breach

**Action:** Call on-call engineer immediately

**P1 (High) - Page in 15 Minutes**
- Degraded performance (p95 latency >5s)
- High error rate (>10%)
- Partial outage (some instances down)
- RabbitMQ connection issues

**Action:** Page on-call engineer if not resolved in 15 minutes

**P2 (Medium) - Create Ticket**
- Warning-level metrics (memory >450MB, p95 >2s)
- Non-critical errors
- Capacity concerns

**Action:** Create JIRA ticket, resolve during business hours

**P3 (Low) - Log for Review**
- Informational alerts
- Performance optimization opportunities

**Action:** Review in weekly operations meeting

### 7.2 On-Call Contacts

**Primary On-Call:** Check PagerDuty schedule

**Escalation Path:**
1. On-call engineer (0-15 minutes)
2. Team lead (15-30 minutes)
3. Platform architect (30-60 minutes)
4. CTO (>60 minutes, P0 only)

**External Contacts:**
- **RabbitMQ Issues:** DevOps team
- **Croatian CIUS Rules:** FINA Support: 01 4404 707
- **Porezna Uprava:** Croatian Tax Authority (business hours)

### 7.3 Incident Response

**Step 1: Acknowledge**
- Acknowledge alert in PagerDuty
- Join incident Slack channel
- Post status update: "Investigating"

**Step 2: Assess**
- Check service status
- Check metrics/logs
- Determine severity
- Estimate impact

**Step 3: Mitigate**
- Follow runbook procedures
- Apply quick fix if available
- Escalate if needed

**Step 4: Resolve**
- Verify service healthy
- Monitor for 30 minutes
- Close incident

**Step 5: Postmortem** (P0/P1 only)
- Document root cause
- Document timeline
- Identify action items
- Update runbook

---

## 8. Appendix

### 8.1 Configuration Reference

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `RABBITMQ_URL` | `amqp://localhost:5672` | RabbitMQ connection URL |
| `SCHEMATRON_RULES_PATH` | `./rules` | Path to Schematron rule files |
| `HTTP_PORT` | `8081` | Health endpoints port |
| `PROMETHEUS_PORT` | `9101` | Metrics port |
| `JAEGER_AGENT_HOST` | `localhost` | Jaeger tracing host |
| `JAEGER_AGENT_PORT` | `14268` | Jaeger tracing port |
| `LOG_LEVEL` | `info` | Log level (trace/debug/info/warn/error) |
| `NODE_ENV` | `development` | Environment (development/production) |
| `VALIDATION_TIMEOUT_MS` | `10000` | Max validation time (milliseconds) |

### 8.2 Performance Tuning

**Optimize for Throughput:**
```bash
# Increase CPU quota
CPUQuota=200%

# Increase concurrency (RabbitMQ prefetch)
# Edit source code: CONFIG.rabbitmq.prefetch = 20

# Deploy multiple instances
```

**Optimize for Latency:**
```bash
# Pre-load all rule sets
# Edit source code: Pre-load all SchematronRuleSet values

# Increase memory for larger cache
MemoryMax=768M

# Use faster storage (SSD)
```

### 8.3 Security Checklist

- [ ] Service runs as non-root user (eracun)
- [ ] Configuration files secured (chmod 600)
- [ ] systemd hardening enabled (ProtectSystem=strict)
- [ ] No secrets in logs (PII masking enabled)
- [ ] HTTPS/TLS for production RabbitMQ
- [ ] Network segmentation (private VLAN)
- [ ] Regular security updates (apt update && apt upgrade)
- [ ] Audit logs enabled and monitored

### 8.4 Related Documentation

- **Service Specification:** `README.md`
- **API Contracts:** `docs/api-contracts/schematron-validator.yaml`
- **ADRs:** `docs/adr/`
- **Test Documentation:** `tests/README.md`
- **Deployment:** `deployment/systemd/README.md`

---

**Document Version:** 1.0.0
**Last Updated:** 2025-11-11
**Maintained By:** Platform Operations Team
**Review Schedule:** Monthly
