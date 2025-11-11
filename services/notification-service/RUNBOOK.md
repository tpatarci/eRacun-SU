# Notification Service - Operations Runbook

**Service:** `notification-service`
**Version:** 1.0.0
**Last Updated:** 2025-11-11

---

## 1. Service Overview

The notification-service is the single notification channel for the eRacun platform, handling all email, SMS, and webhook notifications.

**Responsibilities:**
- Send email notifications via SMTP
- Send SMS notifications via Twilio
- Send webhook notifications via HTTP POST
- Rate limiting (10 SMS/min, 100 emails/min)
- Priority-based routing (CRITICAL bypasses rate limits)
- Audit trail storage in PostgreSQL

**Critical Dependencies:**
- RabbitMQ (message queue)
- PostgreSQL (audit trail)
- SMTP server (email delivery)
- Twilio API (SMS delivery)

---

## 2. Deployment

### 2.1 Build from Source

```bash
cd services/notification-service
npm install
npm run build
```

### 2.2 systemd Deployment

```bash
# Copy service unit
sudo cp deployment/eracun-notification-service.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable eracun-notification-service

# Start service
sudo systemctl start eracun-notification-service

# Check status
sudo systemctl status eracun-notification-service
```

### 2.3 Environment Variables

Create `/etc/eracun/notification-service.env`:

```bash
# Service
SERVICE_NAME=notification-service
HTTP_PORT=8085
PROMETHEUS_PORT=9093
LOG_LEVEL=info
NODE_ENV=production

# SMTP (Email)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=noreply@eracun.hr
SMTP_PASSWORD=<sops-encrypted>
SMTP_FROM=noreply@eracun.hr

# Twilio (SMS)
TWILIO_ACCOUNT_SID=ACxxxxxx
TWILIO_AUTH_TOKEN=<sops-encrypted>
TWILIO_FROM_NUMBER=+385xxxxxxxxx

# RabbitMQ
RABBITMQ_URL=amqp://localhost:5672
NOTIFICATION_QUEUE=notifications.send
RABBITMQ_PREFETCH=10

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=eracun
POSTGRES_USER=eracun
POSTGRES_PASSWORD=<sops-encrypted>
POSTGRES_POOL_MIN=10
POSTGRES_POOL_MAX=50

# Rate Limits
EMAIL_RATE_LIMIT_PER_MINUTE=100
SMS_RATE_LIMIT_PER_MINUTE=10

# Retry
MAX_RETRY_ATTEMPTS=3
RETRY_BACKOFF_BASE_MS=1000

# Tracing
OTEL_EXPORTER_JAEGER_ENDPOINT=http://localhost:14268/api/traces
```

---

## 3. Monitoring

### 3.1 Health Checks

**Liveness:**
```bash
curl http://localhost:8085/health
# Response: {"status": "healthy", "uptime_seconds": 86400, "checks": {...}}
```

**Readiness:**
```bash
curl http://localhost:8085/ready
# Response: {"status": "ready", "dependencies": {...}}
```

### 3.2 Prometheus Metrics

**Metrics endpoint:**
```bash
curl http://localhost:9093/metrics
```

**Key metrics:**
- `notifications_sent_total` - Total notifications sent (by type, priority, status)
- `notification_send_duration_seconds` - Send latency histogram
- `notification_queue_depth` - Pending notifications in queue
- `notification_retry_attempts_total` - Total retry attempts
- `notification_failures_total` - Total failures (by type, reason)
- `service_up` - Service health status (1 = up, 0 = down)

### 3.3 Grafana Dashboard Queries

**Email send rate (per minute):**
```promql
rate(notifications_sent_total{type="email",status="success"}[5m]) * 60
```

**SMS rate limit saturation:**
```promql
rate(notifications_sent_total{type="sms"}[1m]) * 60 > 9
```

**Notification failures (last hour):**
```promql
sum(increase(notification_failures_total[1h])) by (type, reason)
```

**p95 latency (by type):**
```promql
histogram_quantile(0.95, rate(notification_send_duration_seconds_bucket[5m]))
```

---

## 4. Common Issues & Troubleshooting

### Issue 1: SMTP Connection Failed

**Symptoms:**
- Email notifications failing
- Logs: "SMTP connection verification failed"
- Metric: `notification_failures_total{type="email",reason="smtp_error"}` increasing

**Diagnosis:**
```bash
# Check SMTP configuration
cat /etc/eracun/notification-service.env | grep SMTP

# Test SMTP connection
telnet smtp.gmail.com 587

# Check service logs
journalctl -u eracun-notification-service -n 100 | grep SMTP
```

**Resolution:**
1. Verify SMTP credentials are correct
2. Check if SMTP server is reachable (firewall rules)
3. Verify SMTP port (587 for TLS, 465 for SSL)
4. Test with different SMTP provider (e.g., SendGrid)
5. Restart service: `sudo systemctl restart eracun-notification-service`

---

### Issue 2: SMS Rate Limit Exceeded

**Symptoms:**
- SMS notifications delayed or failing
- Logs: "Rate limit timeout - SMS queue backlog"
- Metric: `notification_queue_depth` increasing

**Diagnosis:**
```bash
# Check current rate limit
curl http://localhost:8085/health

# Check queue depth
curl http://localhost:9093/metrics | grep notification_queue_depth

# Check Twilio account status
# (requires Twilio API key)
```

**Resolution:**
1. Increase `SMS_RATE_LIMIT_PER_MINUTE` in config (if Twilio allows)
2. Mark non-urgent SMS as LOW priority (batched daily)
3. Switch to email for non-critical notifications
4. Add additional Twilio phone number (parallel sending)
5. Monitor Twilio account for carrier throttling

---

### Issue 3: RabbitMQ Connection Lost

**Symptoms:**
- No notifications being processed
- Logs: "Failed to start RabbitMQ consumer"
- Service stuck in "not_ready" state

**Diagnosis:**
```bash
# Check RabbitMQ status
sudo systemctl status rabbitmq-server

# Check connection
sudo rabbitmqctl list_connections

# Check queue
sudo rabbitmqctl list_queues | grep notifications.send
```

**Resolution:**
1. Restart RabbitMQ: `sudo systemctl restart rabbitmq-server`
2. Check RabbitMQ logs: `journalctl -u rabbitmq-server -n 200`
3. Verify network connectivity: `telnet localhost 5672`
4. Restart notification-service: `sudo systemctl restart eracun-notification-service`
5. Check firewall rules (port 5672 must be open)

---

### Issue 4: PostgreSQL Connection Pool Exhausted

**Symptoms:**
- Notifications delayed or timing out
- Logs: "PostgreSQL pool error" or "Connection timeout"
- High CPU usage on database server

**Diagnosis:**
```bash
# Check active connections
psql -U eracun -d eracun -c "SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE 'notification-service%';"

# Check pool configuration
cat /etc/eracun/notification-service.env | grep POSTGRES_POOL
```

**Resolution:**
1. Increase pool size: `POSTGRES_POOL_MAX=100` (default: 50)
2. Check for connection leaks (missing `client.release()`)
3. Restart service to reset pool: `sudo systemctl restart eracun-notification-service`
4. Scale database (add read replicas for audit trail queries)
5. Archive old notification_log rows (retention > 90 days)

---

### Issue 5: Twilio API Errors (SMS Failures)

**Symptoms:**
- SMS notifications failing
- Logs: "Twilio API error" or "Invalid phone number"
- Metric: `notification_failures_total{type="sms",reason="twilio_error"}` increasing

**Diagnosis:**
```bash
# Check Twilio configuration
env | grep TWILIO

# Validate phone number format
# Must be E.164 format: +385911234567
```

**Resolution:**
1. Verify Twilio account is active (check balance)
2. Validate phone numbers are in E.164 format
3. Check Twilio console for error codes
4. Verify `TWILIO_FROM_NUMBER` is correct
5. Test with Twilio CLI:
   ```bash
   twilio api:core:messages:create \
     --from "+385911234567" \
     --to "+385911234567" \
     --body "Test"
   ```

---

### Issue 6: Webhook Timeouts

**Symptoms:**
- Webhook notifications failing
- Logs: "Webhook send timeout"
- Metric: `notification_failures_total{type="webhook",reason="timeout"}` increasing

**Diagnosis:**
```bash
# Test webhook URL manually
curl -X POST https://example.com/webhook \
  -H "Content-Type: application/json" \
  -d '{"test": true}'

# Check response time
time curl -X POST https://example.com/webhook \
  -H "Content-Type: application/json" \
  -d '{"test": true}'
```

**Resolution:**
1. Verify webhook URL is reachable (not localhost/internal in production)
2. Increase timeout (default: 10 seconds)
3. Check webhook endpoint logs for errors
4. Test with `curl` manually (see diagnosis)
5. Remove webhook if permanently unreachable

---

### Issue 7: High Memory Usage

**Symptoms:**
- Service OOM (Out of Memory)
- systemd restarts service automatically
- Logs: "JavaScript heap out of memory"

**Diagnosis:**
```bash
# Check memory usage
ps aux | grep notification-service

# Check systemd memory limit
systemctl show eracun-notification-service | grep Memory

# Check for memory leaks
node --inspect dist/index.js
```

**Resolution:**
1. Increase Node.js heap size: `NODE_OPTIONS="--max-old-space-size=2048"`
2. Check for memory leaks (template cache, connection pool)
3. Restart service: `sudo systemctl restart eracun-notification-service`
4. Scale horizontally (run multiple instances)
5. Profile with Chrome DevTools (heap snapshot)

---

### Issue 8: Template Rendering Errors

**Symptoms:**
- Email/SMS content malformed or empty
- Logs: "Failed to render template"
- Notifications sent but content missing

**Diagnosis:**
```bash
# Check template files exist
ls -la services/notification-service/templates/email/
ls -la services/notification-service/templates/sms/

# Validate template syntax (Handlebars)
cat services/notification-service/templates/email/invoice_submitted.html
```

**Resolution:**
1. Verify template files exist in `templates/` directory
2. Validate Handlebars syntax (no unclosed tags)
3. Check template variables match sender calls
4. Clear template cache and restart:
   ```bash
   sudo systemctl restart eracun-notification-service
   ```
5. Test template rendering manually (unit tests)

---

## 5. Disaster Recovery

### 5.1 Service Down (Complete Outage)

**Immediate Actions:**
1. Check service status: `systemctl status eracun-notification-service`
2. Check logs: `journalctl -u eracun-notification-service -n 500`
3. Verify dependencies (RabbitMQ, PostgreSQL, SMTP)
4. Restart service: `sudo systemctl restart eracun-notification-service`

**If restart fails:**
1. Check for configuration errors in `/etc/eracun/notification-service.env`
2. Verify secrets are decrypted (SOPS)
3. Check file permissions: `ls -la /opt/eracun/services/notification-service/`
4. Run service manually to see errors:
   ```bash
   cd /opt/eracun/services/notification-service
   node dist/index.js
   ```

**Escalation:**
1. Page on-call engineer (P0 incident)
2. Fallback: Send critical alerts via backup channel (PagerDuty)
3. Rollback to previous version if recent deployment

### 5.2 Data Loss (PostgreSQL)

**Impact:** Notification audit trail lost (not critical for operations)

**Recovery:**
1. Restore PostgreSQL from backup
2. Service continues operating without audit trail
3. Notification log can be rebuilt from application logs (if needed)

### 5.3 RabbitMQ Queue Backlog

**Impact:** Notifications delayed

**Recovery:**
1. Scale up consumers (run multiple service instances)
2. Increase `RABBITMQ_PREFETCH` to process more messages concurrently
3. Prioritize CRITICAL notifications (automatic via priority queue)
4. Purge LOW priority notifications if backlog > 10,000:
   ```bash
   sudo rabbitmqctl purge_queue notifications.send
   ```

---

## 6. Capacity Planning

**Current Limits:**
- Emails: 100/minute sustained, 200/minute burst (2x)
- SMS: 10/minute sustained, 20/minute burst
- Webhooks: 100/second (6,000/minute)

**Scaling Thresholds:**
- CPU usage > 70% for 10 minutes → Scale horizontally
- Memory usage > 80% → Increase heap size or scale horizontally
- Queue depth > 1,000 → Add more service instances

**Horizontal Scaling:**
1. Run multiple service instances behind load balancer
2. Each instance consumes from same RabbitMQ queue (work distribution)
3. Rate limiters are per-instance (total rate = N * rate_per_instance)

---

## 7. Maintenance

### 7.1 Rolling Update (Zero Downtime)

```bash
# 1. Build new version
cd services/notification-service
npm run build

# 2. Deploy to staging first
# ... test in staging ...

# 3. Deploy to instance 1
sudo systemctl stop eracun-notification-service@1
sudo rsync -av dist/ /opt/eracun/services/notification-service/dist/
sudo systemctl start eracun-notification-service@1

# 4. Verify instance 1 healthy
curl http://localhost:8085/health

# 5. Repeat for instance 2, 3, etc.
```

### 7.2 Database Maintenance (Archiving Old Logs)

```sql
-- Archive notifications older than 90 days
DELETE FROM notification_log
WHERE created_at < NOW() - INTERVAL '90 days';

-- Or move to archive table
INSERT INTO notification_log_archive
SELECT * FROM notification_log
WHERE created_at < NOW() - INTERVAL '90 days';

DELETE FROM notification_log
WHERE created_at < NOW() - INTERVAL '90 days';
```

---

## 8. Security

**Secrets Management:**
- All credentials stored in SOPS-encrypted files
- Never commit `.env` files to git
- Rotate secrets quarterly (SMTP password, Twilio auth token)

**systemd Hardening:**
- `ProtectSystem=strict` - Read-only filesystem
- `NoNewPrivileges=true` - No privilege escalation
- `PrivateTmp=true` - Isolated /tmp

**PII Protection:**
- Email addresses masked in logs (`u***@example.com`)
- Phone numbers masked in logs (`+385****5678`)
- Never log message content

---

## 9. Alerting Rules

**P0 (Page Immediately):**
- Service down (systemd restart failures)
- All notifications failing (SMTP/Twilio/RabbitMQ down)
- Memory usage > 95%

**P1 (Page in 15 minutes):**
- Notification failure rate > 10% for 10 minutes
- Queue depth > 5,000 for 10 minutes
- p95 latency > 30 seconds

**P2 (Ticket Next Day):**
- Rate limit saturation (90% of limit) for 1 hour
- Retry attempts increasing
- Template rendering warnings

---

## 10. Contact Information

**On-Call Engineer:** PagerDuty rotation
**Slack Channel:** #eracun-ops
**Email:** ops@eracun.hr
**Phone (Emergencies):** +385 1 234 5678

---

**Last Updated:** 2025-11-11
**Version:** 1.0.0
**Maintained By:** eRacun DevOps Team
