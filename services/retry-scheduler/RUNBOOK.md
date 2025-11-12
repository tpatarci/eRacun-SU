# Retry Scheduler - Operations Runbook

**Service:** retry-scheduler
**Version:** 1.0.0
**Last Updated:** 2025-11-12

---

## Table of Contents

1. [Service Overview](#service-overview)
2. [Architecture](#architecture)
3. [Deployment](#deployment)
4. [Monitoring & Alerts](#monitoring--alerts)
5. [Common Issues](#common-issues)
6. [Troubleshooting](#troubleshooting)
7. [Maintenance Procedures](#maintenance-procedures)
8. [Disaster Recovery](#disaster-recovery)
9. [Performance Tuning](#performance-tuning)
10. [Security](#security)

---

## Service Overview

### Purpose

The retry-scheduler service automatically retries failed messages with exponential backoff. It consumes retry requests from RabbitMQ, persists them in PostgreSQL with calculated retry times, and republishes messages after appropriate delays.

### Key Features

- **Exponential backoff with jitter** (2s → 4s → 8s → 16s...)
- **PostgreSQL persistence** (retries survive service restarts)
- **Max retry limit** (default: 3 attempts)
- **Manual review routing** (exhausted retries → manual-review.pending)
- **Prometheus metrics** (retries scheduled, executed, exhausted, queue depth)

### Critical Dependencies

- **RabbitMQ**: Message queue (retry.scheduled → service → original queues)
- **PostgreSQL**: Persistent retry queue storage
- **Prometheus**: Metrics collection
- **Jaeger**: Distributed tracing (optional)

### SLA Targets

- **Availability:** 99.9% uptime
- **Latency:** Retry execution within 5 seconds of scheduled time
- **Throughput:** 50 retries/second sustained, 200 retries/second burst

---

## Architecture

### Data Flow

```
RabbitMQ (retry.scheduled)
  │
  ├─> Consumer (src/consumer.ts)
  │     └─> Calculate next retry time (src/backoff.ts)
  │           └─> Store in PostgreSQL (src/repository.ts)
  │
  └─> Scheduler (src/scheduler.ts)
        ├─> Poll for due retries (every 10 seconds)
        ├─> retry_count < max_retries?
        │     ├─> YES: Republish to original queue (src/publisher.ts)
        │     └─> NO: Move to manual-review.pending
        └─> Update metrics (src/observability.ts)
```

### Critical Files

- **src/index.ts**: Main entry point, graceful shutdown
- **src/consumer.ts**: RabbitMQ consumer (retry.scheduled)
- **src/repository.ts**: PostgreSQL operations (retry_queue table)
- **src/scheduler.ts**: Polling scheduler (10-second interval)
- **src/backoff.ts**: Exponential backoff calculation
- **src/publisher.ts**: Message republishing logic
- **src/observability.ts**: Metrics, logging, tracing

---

## Deployment

### Prerequisites

- Node.js 20+
- PostgreSQL 12+ (retry_queue table)
- RabbitMQ 3.8+ (retry.scheduled, manual-review.pending queues)

### Installation (systemd)

1. **Build the service:**
   ```bash
   npm install
   npm run build
   ```

2. **Deploy files:**
   ```bash
   sudo mkdir -p /opt/eracun/services/retry-scheduler
   sudo cp -r dist node_modules package.json /opt/eracun/services/retry-scheduler/
   ```

3. **Create environment file:**
   ```bash
   sudo cp .env.example /etc/eracun/retry-scheduler.env
   sudo nano /etc/eracun/retry-scheduler.env
   # Configure: POSTGRES_*, RABBITMQ_URL, etc.
   ```

4. **Install systemd unit:**
   ```bash
   sudo cp deployment/eracun-retry-scheduler.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable eracun-retry-scheduler
   sudo systemctl start eracun-retry-scheduler
   ```

5. **Verify deployment:**
   ```bash
   sudo systemctl status eracun-retry-scheduler
   curl http://localhost:8086/health
   curl http://localhost:9094/metrics
   ```

### Rolling Update (Zero-Downtime)

1. Build new version locally
2. `rsync -avz dist/ user@server:/opt/eracun/services/retry-scheduler/dist/`
3. `sudo systemctl restart eracun-retry-scheduler`
4. Monitor logs: `journalctl -u eracun-retry-scheduler -f`
5. Check health: `curl http://localhost:8086/health`

### Rollback

```bash
# Restore previous version
sudo rsync -avz /opt/eracun/services/retry-scheduler/dist.backup/ /opt/eracun/services/retry-scheduler/dist/
sudo systemctl restart eracun-retry-scheduler
```

---

## Monitoring & Alerts

### Health Endpoints

| Endpoint | Port | Purpose | Expected Response |
|----------|------|---------|-------------------|
| `GET /health` | 8086 | Overall health | `{"status":"healthy"}` (200) |
| `GET /ready` | 8086 | Readiness check | `{"status":"ready"}` (200) |
| `GET /metrics` | 9094 | Prometheus metrics | Text format (200) |

### Key Metrics

#### Counters

- **retries_scheduled_total{queue}**: Total retry requests received
- **retries_executed_total{queue,status}**: Retries executed (status: success/failed)
- **retries_exhausted_total{queue}**: Messages moved to manual review

#### Gauges

- **retry_queue_depth**: Number of pending retry tasks in PostgreSQL
- **service_up**: Service health (1 = up, 0 = down)

### Recommended Alerts

#### Critical (P0)

```prometheus
# Service down
service_up{service="retry-scheduler"} == 0
```

```prometheus
# Retry queue backlog growing unbounded
retry_queue_depth > 10000
```

```prometheus
# High failure rate
rate(retries_executed_total{status="failed"}[5m]) > 10
```

#### Warning (P1)

```prometheus
# Many retries exhausted (downstream service issues)
rate(retries_exhausted_total[5m]) > 5
```

```prometheus
# Queue depth above normal
retry_queue_depth > 1000
```

#### Info (P2)

```prometheus
# Scheduler lag (retries not executing on time)
retry_queue_depth > 100 AND rate(retries_executed_total[5m]) < 1
```

---

## Common Issues

### 1. Retry Queue Backlog Growing

**Symptom:** `retry_queue_depth` metric increasing continuously

**Causes:**
- Retry poll interval (10s) too slow for incoming rate
- PostgreSQL connection pool exhausted
- Scheduler not running (service crashed)

**Resolution:**
1. Check service status: `systemctl status eracun-retry-scheduler`
2. Check logs: `journalctl -u eracun-retry-scheduler -n 100`
3. Verify PostgreSQL connection: `SELECT COUNT(*) FROM retry_queue WHERE status = 'pending';`
4. Decrease poll interval: Set `RETRY_POLL_INTERVAL_MS=5000` in env file
5. Increase DB pool: Set `POSTGRES_POOL_MAX=100`
6. Restart service: `systemctl restart eracun-retry-scheduler`

---

### 2. RabbitMQ Connection Lost

**Symptom:** `GET /health` returns 503, logs show "Failed to connect to RabbitMQ"

**Causes:**
- RabbitMQ server down or restarting
- Network connectivity issues
- Authentication failure

**Resolution:**
1. Check RabbitMQ status: `systemctl status rabbitmq-server`
2. Verify connectivity: `telnet <rabbitmq-host> 5672`
3. Check credentials in `/etc/eracun/retry-scheduler.env`
4. Check RabbitMQ logs: `journalctl -u rabbitmq-server -n 50`
5. Service auto-reconnects with exponential backoff (wait 1-2 minutes)
6. Manual restart if needed: `systemctl restart eracun-retry-scheduler`

---

### 3. PostgreSQL Connection Issues

**Symptom:** `GET /health` returns 503, logs show "PostgreSQL health check failed"

**Causes:**
- PostgreSQL server down
- Connection pool exhausted
- Too many connections

**Resolution:**
1. Check PostgreSQL status: `systemctl status postgresql`
2. Check connection count:
   ```sql
   SELECT count(*) FROM pg_stat_activity WHERE datname = 'eracun';
   ```
3. Check pool configuration: `POSTGRES_POOL_MIN=10 POSTGRES_POOL_MAX=50`
4. Increase PostgreSQL max_connections if needed
5. Restart service: `systemctl restart eracun-retry-scheduler`

---

### 4. Max Retries Exhausted (High Manual Review Rate)

**Symptom:** `retries_exhausted_total` metric increasing rapidly

**Causes:**
- Downstream service persistently failing (not transient errors)
- Max retries too low for actual recovery time
- Dead-letter-handler miscategorizing permanent errors as transient

**Resolution:**
1. Check manual-review.pending queue:
   ```bash
   rabbitmqctl list_queues name messages | grep manual-review.pending
   ```
2. Identify failing downstream service from queue labels in metrics
3. Investigate downstream service health
4. Consider increasing `DEFAULT_MAX_RETRIES` if failures are temporary but need more time
5. Review dead-letter-handler classification logic

---

### 5. Retry Execution Lag

**Symptom:** Retries executing >10 seconds after scheduled time

**Causes:**
- Scheduler poll interval too long (default: 10s)
- PostgreSQL query slow (missing index)
- High CPU/memory usage

**Resolution:**
1. Check scheduler interval: `RETRY_POLL_INTERVAL_MS` in env file
2. Verify index exists:
   ```sql
   SELECT indexname FROM pg_indexes WHERE tablename = 'retry_queue';
   -- Should include: idx_retry_next_retry
   ```
3. Check system resources: `top`, `free -h`
4. Decrease poll interval: `RETRY_POLL_INTERVAL_MS=5000`
5. Optimize database query: `EXPLAIN ANALYZE SELECT * FROM retry_queue WHERE next_retry_at <= NOW() AND status = 'pending';`

---

## Troubleshooting

### Diagnostic Commands

#### Check Service Status
```bash
systemctl status eracun-retry-scheduler
journalctl -u eracun-retry-scheduler -f  # Follow logs
journalctl -u eracun-retry-scheduler --since "10 minutes ago"
```

#### Check Health
```bash
curl http://localhost:8086/health | jq
curl http://localhost:8086/ready | jq
curl http://localhost:9094/metrics | grep retry
```

#### Check Database
```sql
-- Pending retries
SELECT COUNT(*) FROM retry_queue WHERE status = 'pending';

-- Due retries (should be processed soon)
SELECT COUNT(*) FROM retry_queue WHERE next_retry_at <= NOW() AND status = 'pending';

-- Recent activity
SELECT status, COUNT(*) FROM retry_queue GROUP BY status;

-- Oldest pending retry
SELECT message_id, next_retry_at, retry_count FROM retry_queue WHERE status = 'pending' ORDER BY next_retry_at LIMIT 10;
```

#### Check RabbitMQ
```bash
rabbitmqctl list_queues name messages | grep retry
rabbitmqctl list_connections
```

### Log Analysis

**Common Log Patterns:**

- **Retry scheduled:** `"Retry scheduled"` with `message_id`, `next_retry_at`
- **Retry executed:** `"Retry executed successfully"` with `retry_count`
- **Max retries exceeded:** `"Max retries exceeded - moved to manual review"`
- **Database error:** `"Failed to save retry task"` or `"Failed to get due retry tasks"`
- **RabbitMQ error:** `"Failed to start RabbitMQ consumer"`

**Search logs:**
```bash
journalctl -u eracun-retry-scheduler | grep "Max retries exceeded"
journalctl -u eracun-retry-scheduler | grep ERROR
```

---

## Maintenance Procedures

### Database Maintenance

#### Clean Up Old Retries (Monthly)
```sql
-- Archive retries older than 30 days
INSERT INTO retry_queue_archive SELECT * FROM retry_queue WHERE created_at < NOW() - INTERVAL '30 days';
DELETE FROM retry_queue WHERE created_at < NOW() - INTERVAL '30 days';

-- Vacuum table
VACUUM ANALYZE retry_queue;
```

#### Rebuild Index (If Slow Queries)
```sql
REINDEX INDEX idx_retry_next_retry;
```

### Scaling Up

**Horizontal Scaling (Multiple Instances):**
- Each instance polls independently
- PostgreSQL row-level locking prevents duplicate processing
- No additional configuration needed

**Vertical Scaling (Increase Resources):**
1. Update systemd unit:
   ```ini
   MemoryMax=2G
   CPUQuota=200%
   ```
2. Reload systemd: `systemctl daemon-reload`
3. Restart service: `systemctl restart eracun-retry-scheduler`

### Configuration Changes

1. Edit environment file: `sudo nano /etc/eracun/retry-scheduler.env`
2. Restart service: `sudo systemctl restart eracun-retry-scheduler`
3. Verify changes: `curl http://localhost:8086/health`

---

## Disaster Recovery

### Scenario 1: Service Crash

**Detection:** `service_up` metric = 0, health endpoint unreachable

**Recovery:**
```bash
# Check why it crashed
journalctl -u eracun-retry-scheduler -n 200

# Restart service
sudo systemctl restart eracun-retry-scheduler

# Verify recovery
curl http://localhost:8086/health
```

**Notes:** Pending retries are persisted in PostgreSQL and will resume automatically.

---

### Scenario 2: PostgreSQL Database Lost

**Detection:** `GET /health` returns 503, logs show database connection errors

**Recovery:**
1. Restore PostgreSQL from backup
2. Restore `retry_queue` table:
   ```sql
   \i /backup/retry_queue_backup.sql
   ```
3. Recreate indexes:
   ```sql
   CREATE INDEX IF NOT EXISTS idx_retry_next_retry ON retry_queue(next_retry_at, status) WHERE status = 'pending';
   ```
4. Restart service: `systemctl restart eracun-retry-scheduler`

**Data Loss Risk:** Retries not yet persisted to database (in-flight messages)

---

### Scenario 3: RabbitMQ Queue Lost

**Detection:** Messages not being consumed, queue missing in `rabbitmqctl list_queues`

**Recovery:**
1. Recreate queue (service auto-creates on startup):
   ```bash
   systemctl restart eracun-retry-scheduler
   ```
2. Upstream services (dead-letter-handler) will continue publishing

**Data Loss Risk:** Messages published while queue was missing (use durable queues)

---

## Performance Tuning

### Optimize Throughput

1. **Decrease poll interval** (faster retry execution):
   ```bash
   RETRY_POLL_INTERVAL_MS=5000  # Default: 10000
   ```

2. **Increase database pool** (more concurrent operations):
   ```bash
   POSTGRES_POOL_MAX=100  # Default: 50
   ```

3. **Increase RabbitMQ prefetch** (batch processing):
   ```bash
   RABBITMQ_PREFETCH=20  # Default: 10
   ```

### Optimize Latency

1. **Reduce backoff delays** (faster retries, higher load):
   ```bash
   BASE_DELAY_MS=1000  # Default: 2000
   ```

2. **Increase max delay cap** (prevent retry storms):
   ```bash
   MAX_DELAY_MS=120000  # Default: 60000
   ```

### Resource Limits

**systemd:**
```ini
MemoryMax=2G       # Hard limit
MemoryHigh=1536M   # Soft limit (swap warning)
CPUQuota=200%      # 2 CPU cores
```

**PostgreSQL:**
- Connection pool: 10-50 connections (default)
- Increase if seeing "connection pool exhausted" errors

---

## Security

### Secrets Management

- **Environment file:** `/etc/eracun/retry-scheduler.env` (permissions: 600)
- **PostgreSQL password:** Use SOPS encryption (see repository root `secrets/` directory)
- **RabbitMQ credentials:** Stored in `RABBITMQ_URL` (encrypted)

### systemd Hardening

The service unit includes:
- `ProtectSystem=strict`: Read-only filesystem
- `ProtectHome=true`: No access to user directories
- `PrivateTmp=true`: Isolated /tmp
- `NoNewPrivileges=true`: Prevent privilege escalation
- `SystemCallFilter=@system-service`: Restrict system calls

### Network Security

- Health/metrics endpoints: Bind to `localhost` only (default: 0.0.0.0:8086, 0.0.0.0:9094)
- PostgreSQL: Use SSL connections in production (`POSTGRES_SSL=true`)
- RabbitMQ: Use TLS in production (`amqps://` protocol)

### Audit Trail

All retry operations are logged with:
- `message_id`: Unique identifier for tracing
- `original_queue`: Source queue
- `retry_count`: Attempt number
- `error_reason`: Why retry was needed

Logs are sent to systemd journal and can be forwarded to centralized logging (ELK, Loki).

---

## Emergency Contacts

| Role | Contact | Escalation Time |
|------|---------|-----------------|
| On-Call Engineer | See PagerDuty | Immediate |
| Database Admin | See runbook | 15 minutes |
| Platform Team | See Slack | 30 minutes |

---

## Change Log

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2025-11-12 | 1.0.0 | Initial runbook creation | eRacun Team |

---

**End of Runbook**
