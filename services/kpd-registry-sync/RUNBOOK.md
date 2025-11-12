# KPD Registry Sync Service - Operations Runbook

**Service:** kpd-registry-sync
**Port (HTTP):** 8088
**Port (gRPC):** 50052
**Port (Metrics):** 9093

---

## 1. Service Overview

The KPD Registry Sync service maintains a local cache of Croatian product classification codes (KLASUS 2025). It syncs daily from DZS (Croatian Bureau of Statistics) and provides fast lookup APIs for invoice validation.

**Critical Dependencies:**
- PostgreSQL database (kpd_codes table)
- DZS KLASUS API (external)
- RabbitMQ (optional, for event publishing)

---

## 2. Deployment

### 2.1 systemd Deployment

```bash
# Copy service files
sudo cp dist/* /opt/eracun/services/kpd-registry-sync/dist/
sudo cp proto/* /opt/eracun/services/kpd-registry-sync/proto/
sudo cp kpd-registry-sync.service /etc/systemd/system/

# Create environment file
sudo cp .env.example /etc/eracun/kpd-registry-sync.env
sudo nano /etc/eracun/kpd-registry-sync.env  # Edit configuration

# Create directories
sudo mkdir -p /var/log/eracun/kpd-registry-sync
sudo mkdir -p /var/lib/eracun/kpd-registry-sync
sudo chown -R eracun:eracun /var/log/eracun/kpd-registry-sync
sudo chown -R eracun:eracun /var/lib/eracun/kpd-registry-sync

# Reload and start
sudo systemctl daemon-reload
sudo systemctl enable kpd-registry-sync
sudo systemctl start kpd-registry-sync

# Verify
sudo systemctl status kpd-registry-sync
sudo journalctl -u kpd-registry-sync -f
```

### 2.2 Docker Deployment

```bash
# Build image
docker build -t eracun/kpd-registry-sync:latest .

# Run container
docker run -d \
  --name kpd-registry-sync \
  -p 8088:8088 \
  -p 50052:50052 \
  -p 9093:9093 \
  --env-file .env \
  --restart unless-stopped \
  eracun/kpd-registry-sync:latest

# Check logs
docker logs -f kpd-registry-sync
```

---

## 3. Monitoring

### 3.1 Health Checks

**Basic Health:**
```bash
curl http://localhost:8088/health
# Expected: {"status":"healthy","uptime_seconds":12345}
```

**Readiness Check:**
```bash
curl http://localhost:8088/ready
# Expected: {"status":"healthy","uptime_seconds":12345,"dependencies":{...}}
```

### 3.2 Prometheus Metrics

**Metrics Endpoint:**
```bash
curl http://localhost:9093/metrics
```

**Key Metrics:**
- `kpd_codes_synced_total{action="added"}` - New codes added
- `kpd_codes_synced_total{action="updated"}` - Codes updated
- `kpd_codes_synced_total{action="deleted"}` - Codes deleted
- `kpd_sync_duration_seconds` - Sync duration histogram
- `kpd_total_codes` - Total codes in cache (gauge)
- `kpd_active_codes` - Active codes in cache (gauge)
- `kpd_lookup_requests_total{status="found"}` - Successful lookups
- `kpd_lookup_duration_seconds` - Lookup latency histogram
- `kpd_sync_errors_total{error_type}` - Sync errors by type

### 3.3 Grafana Dashboard

**Recommended Panels:**
1. **Sync Status** - Last sync timestamp, codes added/updated/deleted
2. **Cache Size** - Total codes vs active codes over time
3. **Lookup Performance** - Latency p95, p99, throughput
4. **Error Rate** - Sync errors by type
5. **Resource Usage** - Memory, CPU, DB connections

---

## 4. Common Issues

### 4.1 DZS API Unavailable

**Symptoms:**
- Sync fails with network timeout error
- `kpd_sync_errors_total{error_type="network"}` increases

**Detection:**
```bash
# Check logs
sudo journalctl -u kpd-registry-sync -n 100 | grep "DZS API"

# Check metrics
curl http://localhost:9093/metrics | grep kpd_sync_errors_total
```

**Recovery:**
1. Verify DZS API status (check official DZS status page)
2. Check network connectivity:
   ```bash
   curl -v https://api.dzs.hr/klasus/v1/codes
   ```
3. Service will automatically retry on next cron job (3 AM)
4. If urgent, trigger manual sync:
   ```bash
   curl -X POST http://localhost:8088/api/v1/kpd/sync/trigger
   ```
5. If DZS down for >24 hours, alert DZS support

**Acceptable Impact:**
- Short outages (<24h): Validation uses stale data (acceptable)
- Long outages (>24h): Risk of using outdated codes

---

### 4.2 Database Connection Lost

**Symptoms:**
- Health check fails: `/health` returns 503
- Lookup requests return 500 errors
- Logs show "Database health check failed"

**Detection:**
```bash
# Check health
curl http://localhost:8088/health

# Check database connectivity
psql -U kpd_user -d eracun -c "SELECT COUNT(*) FROM kpd_codes;"
```

**Recovery:**
1. Verify PostgreSQL is running:
   ```bash
   sudo systemctl status postgresql
   ```
2. Check database credentials in `/etc/eracun/kpd-registry-sync.env`
3. Check connection pool settings (min: 10, max: 50)
4. Restart service (connection pool will reinitialize):
   ```bash
   sudo systemctl restart kpd-registry-sync
   ```
5. If persistent, check PostgreSQL logs:
   ```bash
   sudo journalctl -u postgresql -n 100
   ```

---

### 4.3 Sync Takes Too Long (>60 seconds)

**Symptoms:**
- `kpd_sync_duration_seconds` > 60
- High database CPU usage during sync
- Slow sync performance

**Detection:**
```bash
# Check sync duration
curl http://localhost:9093/metrics | grep kpd_sync_duration_seconds

# Check sync status
curl http://localhost:8088/api/v1/kpd/sync/status
```

**Recovery:**
1. Check database indexes:
   ```sql
   SELECT * FROM pg_indexes WHERE tablename = 'kpd_codes';
   -- Expected: idx_kpd_code, idx_kpd_parent, idx_kpd_active
   ```
2. Vacuum database:
   ```sql
   VACUUM ANALYZE kpd_codes;
   ```
3. Check database connection pool:
   ```bash
   curl http://localhost:9093/metrics | grep kpd_db_pool
   ```
4. If still slow, increase connection pool size:
   ```bash
   # Edit /etc/eracun/kpd-registry-sync.env
   DATABASE_POOL_MAX=100  # Increase from 50
   sudo systemctl restart kpd-registry-sync
   ```

**Performance Target:** <60 seconds for 50,000 codes

---

### 4.4 Invalid KPD Codes in DZS Response

**Symptoms:**
- Sync completes but fewer codes than expected
- `kpd_sync_errors_total{error_type="parsing"}` increases
- Logs show "Failed to parse CSV row"

**Detection:**
```bash
# Check logs for parsing errors
sudo journalctl -u kpd-registry-sync -n 500 | grep "Failed to parse"

# Check sync statistics
curl http://localhost:8088/api/v1/kpd/sync/status | jq .
```

**Recovery:**
1. Review logs to identify invalid rows
2. Contact DZS support about data quality issue
3. Sync will continue with valid codes (invalid codes skipped)
4. Manual correction may be required for specific codes

---

### 4.5 gRPC Lookup Failures

**Symptoms:**
- kpd-validator service reports lookup errors
- `kpd_lookup_requests_total{status="error"}` increases

**Detection:**
```bash
# Test gRPC endpoint (requires grpcurl)
grpcurl -plaintext -d '{"kpd_code":"010101"}' \
  localhost:50052 kpd.KPDLookupService/LookupCode
```

**Recovery:**
1. Verify gRPC server is running:
   ```bash
   netstat -tuln | grep 50052
   ```
2. Check proto file compatibility:
   ```bash
   ls -l proto/kpd-lookup.proto
   ```
3. Restart service:
   ```bash
   sudo systemctl restart kpd-registry-sync
   ```
4. If persistent, check firewall rules:
   ```bash
   sudo ufw status | grep 50052
   ```

---

### 4.6 High Memory Usage

**Symptoms:**
- Memory usage >512MB (systemd limit)
- OOMKiller terminates service
- `systemctl status` shows "Main process exited, code=killed, status=9/KILL"

**Detection:**
```bash
# Check memory usage
sudo systemctl status kpd-registry-sync | grep Memory

# Check logs for OOM
sudo journalctl -u kpd-registry-sync -n 100 | grep -i "killed\|oom"
```

**Recovery:**
1. Increase memory limit in systemd unit:
   ```bash
   # Edit /etc/systemd/system/kpd-registry-sync.service
   MemoryLimit=1G  # Increase from 512M
   sudo systemctl daemon-reload
   sudo systemctl restart kpd-registry-sync
   ```
2. Check for memory leaks in code
3. Review connection pool size (large pool = more memory)

**Memory Budget:** 512MB (normal), 1GB (max)

---

## 5. Troubleshooting Commands

### 5.1 Service Status

```bash
# Service status
sudo systemctl status kpd-registry-sync

# Recent logs (last 100 lines)
sudo journalctl -u kpd-registry-sync -n 100

# Follow logs in real-time
sudo journalctl -u kpd-registry-sync -f

# Logs for last hour
sudo journalctl -u kpd-registry-sync --since "1 hour ago"

# Restart service
sudo systemctl restart kpd-registry-sync
```

### 5.2 Database Queries

```bash
# Connect to database
psql -U kpd_user -d eracun

# Check total codes
SELECT COUNT(*) FROM kpd_codes;

# Check active codes
SELECT COUNT(*) FROM kpd_codes WHERE active = true;

# Check recent updates
SELECT kpd_code, description, updated_at
FROM kpd_codes
ORDER BY updated_at DESC
LIMIT 10;

# Search for specific code
SELECT * FROM kpd_codes WHERE kpd_code = '010101';

# Check sync statistics
SELECT
  COUNT(*) AS total,
  SUM(CASE WHEN active = true THEN 1 ELSE 0 END) AS active,
  MAX(updated_at) AS last_updated
FROM kpd_codes;
```

### 5.3 HTTP API Testing

```bash
# List codes (paginated)
curl http://localhost:8088/api/v1/kpd/codes?page=1&pageSize=10

# Get specific code
curl http://localhost:8088/api/v1/kpd/codes/010101

# Search codes
curl http://localhost:8088/api/v1/kpd/search?q=cattle&limit=10

# Trigger manual sync
curl -X POST http://localhost:8088/api/v1/kpd/sync/trigger

# Check sync status
curl http://localhost:8088/api/v1/kpd/sync/status
```

### 5.4 gRPC API Testing

```bash
# Install grpcurl
sudo apt install grpcurl  # Debian/Ubuntu
brew install grpcurl       # macOS

# Lookup code
grpcurl -plaintext -d '{"kpd_code":"010101"}' \
  localhost:50052 kpd.KPDLookupService/LookupCode

# Validate code
grpcurl -plaintext -d '{"kpd_code":"010101"}' \
  localhost:50052 kpd.KPDLookupService/ValidateCode

# Search codes
grpcurl -plaintext -d '{"query":"cattle","limit":10}' \
  localhost:50052 kpd.KPDLookupService/SearchCodes
```

---

## 6. Disaster Recovery

### 6.1 Complete Data Loss

**Scenario:** PostgreSQL database corruption, kpd_codes table lost

**Recovery:**
1. Reinitialize database schema:
   ```sql
   DROP TABLE IF EXISTS kpd_codes;
   -- Service will recreate table on next start
   ```
2. Restart service (schema will be created):
   ```bash
   sudo systemctl restart kpd-registry-sync
   ```
3. Trigger manual sync to repopulate:
   ```bash
   curl -X POST http://localhost:8088/api/v1/kpd/sync/trigger
   ```
4. Verify data populated:
   ```bash
   psql -U kpd_user -d eracun -c "SELECT COUNT(*) FROM kpd_codes;"
   ```

**RTO:** 10 minutes (assuming DZS API available)
**RPO:** 24 hours (last sync)

### 6.2 Service Won't Start

**Scenario:** Service fails to start, exits immediately

**Recovery:**
1. Check logs for errors:
   ```bash
   sudo journalctl -u kpd-registry-sync -n 50
   ```
2. Common causes:
   - Database connection failed → Fix DATABASE_URL
   - Port already in use → Check `netstat -tuln | grep 8088`
   - Missing proto file → Verify `proto/kpd-lookup.proto` exists
   - Environment file missing → Check `/etc/eracun/kpd-registry-sync.env`
3. Test configuration:
   ```bash
   cd /opt/eracun/services/kpd-registry-sync
   node dist/index.js  # Run manually to see errors
   ```

---

## 7. Performance Tuning

### 7.1 Database Optimization

```sql
-- Create missing indexes
CREATE INDEX IF NOT EXISTS idx_kpd_code ON kpd_codes(kpd_code, active);
CREATE INDEX IF NOT EXISTS idx_kpd_parent ON kpd_codes(parent_code);
CREATE INDEX IF NOT EXISTS idx_kpd_description ON kpd_codes USING GIN(to_tsvector('english', description));

-- Vacuum and analyze
VACUUM ANALYZE kpd_codes;

-- Check index usage
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE tablename = 'kpd_codes'
ORDER BY idx_scan DESC;
```

### 7.2 Connection Pool Tuning

```bash
# Edit /etc/eracun/kpd-registry-sync.env
DATABASE_POOL_MIN=10   # Minimum connections
DATABASE_POOL_MAX=50   # Maximum connections (increase if high load)
DB_QUERY_TIMEOUT_MS=10000  # Query timeout
```

### 7.3 Sync Performance

```bash
# Adjust sync timeout
SYNC_TIMEOUT_MS=120000  # 2 minutes (increase if DZS API slow)

# HTTP request timeout
HTTP_REQUEST_TIMEOUT_MS=30000  # 30 seconds
```

---

## 8. Maintenance Tasks

### 8.1 Weekly Tasks

1. **Check sync health:**
   ```bash
   curl http://localhost:8088/api/v1/kpd/sync/status | jq .
   ```

2. **Review error logs:**
   ```bash
   sudo journalctl -u kpd-registry-sync --since "7 days ago" | grep -i error
   ```

3. **Check metrics:**
   ```bash
   curl http://localhost:9093/metrics | grep -E "kpd_(sync|lookup)_"
   ```

### 8.2 Monthly Tasks

1. **Vacuum database:**
   ```sql
   VACUUM ANALYZE kpd_codes;
   ```

2. **Review performance:**
   - Sync duration trend
   - Lookup latency trend
   - Error rate trend

3. **Check disk usage:**
   ```bash
   du -sh /var/log/eracun/kpd-registry-sync
   du -sh /var/lib/eracun/kpd-registry-sync
   ```

### 8.3 Quarterly Tasks

1. **Update DZS API endpoint** (if changed)
2. **Review KPD code statistics:**
   ```sql
   SELECT level, COUNT(*) AS count
   FROM kpd_codes
   WHERE active = true
   GROUP BY level
   ORDER BY level;
   ```

---

## 9. Contact Information

**Service Owner:** eRacun Platform Team
**On-Call:** See PagerDuty rotation
**DZS Support:** 01 4806 111 (Croatian Bureau of Statistics)

---

**Last Updated:** 2025-11-11
**Document Version:** 1.0.0
