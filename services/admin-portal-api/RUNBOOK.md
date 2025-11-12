# Admin Portal API - Operations Runbook

**Service:** `admin-portal-api`
**Version:** 1.0.0
**Last Updated:** 2025-11-12

---

## 1. Service Overview

**Purpose:** Backend API for administrative web portal

**Responsibilities:**
- JWT authentication and session management
- User management (CRUD, RBAC)
- Manual error review (DLQ management)
- System health dashboard aggregation
- Reporting (monthly summaries, error statistics)
- Certificate management

**Dependencies:**
- PostgreSQL database (`admin_portal`)
- Downstream services: health-monitor, dead-letter-handler, cert-lifecycle-manager, audit-logger

**Ports:**
- HTTP API: 8089
- Prometheus metrics: 9094

---

## 2. Deployment

### 2.1 systemd Deployment

```bash
# Build the service
cd /home/tomislav/PycharmProjects/eRačun/services/admin-portal-api
npm run build

# Copy files to deployment location
sudo mkdir -p /opt/eracun/services/admin-portal-api
sudo cp -r dist package*.json /opt/eracun/services/admin-portal-api/
cd /opt/eracun/services/admin-portal-api && sudo npm ci --only=production

# Copy systemd unit file
sudo cp /home/tomislav/PycharmProjects/eRačun/services/admin-portal-api/admin-portal-api.service /etc/systemd/system/

# Create environment file
sudo cp /home/tomislav/PycharmProjects/eRačun/services/admin-portal-api/.env.example /etc/eracun/admin-portal-api.env
sudo nano /etc/eracun/admin-portal-api.env  # Edit configuration

# Create log directory
sudo mkdir -p /opt/eracun/services/admin-portal-api/logs
sudo chown -R eracun:eracun /opt/eracun/services/admin-portal-api

# Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable admin-portal-api
sudo systemctl start admin-portal-api

# Verify service is running
sudo systemctl status admin-portal-api
curl http://localhost:8089/health
```

### 2.2 Database Setup

**Create database and tables:**

```sql
-- Create database
CREATE DATABASE admin_portal;

-- Connect to database
\c admin_portal

-- Create users table
CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  last_login TIMESTAMP
);

-- Create sessions table
CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  token VARCHAR(512) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- Create initial admin user (password: ChangeMe123!)
INSERT INTO users (email, password_hash, role, active)
VALUES (
  'admin@eracun.hr',
  '$2b$12$YourHashHere',  -- Use bcrypt to generate
  'admin',
  true
);
```

### 2.3 Docker Deployment (Alternative)

```bash
# Build Docker image
docker build -t admin-portal-api:1.0.0 .

# Run container
docker run -d \
  --name admin-portal-api \
  --env-file .env \
  -p 8089:8089 \
  -p 9094:9094 \
  admin-portal-api:1.0.0
```

---

## 3. Monitoring

### 3.1 Health Endpoints

**Service Health:**
```bash
curl http://localhost:8089/health
# Expected: {"status":"healthy","uptime_seconds":...}
```

**Readiness Check:**
```bash
curl http://localhost:8089/ready
# Expected: {"status":"ready","dependencies":{"database":"ok",...}}
```

**Prometheus Metrics:**
```bash
curl http://localhost:9094/metrics
```

### 3.2 Key Metrics

**Prometheus Queries:**

```promql
# Authentication success rate
rate(admin_auth_attempts_total{status="success"}[5m])
/ rate(admin_auth_attempts_total[5m])

# API request rate
rate(admin_api_requests_total[5m])

# API latency (p95)
histogram_quantile(0.95, rate(admin_api_duration_seconds_bucket[5m]))

# Active user sessions
admin_active_sessions

# Downstream service error rate
rate(admin_downstream_calls_total{status="error"}[5m])
```

### 3.3 Logs

**View logs:**
```bash
# systemd logs
sudo journalctl -u admin-portal-api -f

# Filter by level
sudo journalctl -u admin-portal-api | grep '"level":"error"'

# Follow errors only
sudo journalctl -u admin-portal-api -f | grep ERROR
```

---

## 4. Common Issues & Troubleshooting

### 4.1 Service Won't Start

**Symptoms:** `systemctl status admin-portal-api` shows failed state

**Diagnosis:**
```bash
sudo journalctl -u admin-portal-api -n 50
```

**Common Causes:**

1. **Database connection failed**
   ```
   Error: "Failed to connect to PostgreSQL"
   ```
   - Check DATABASE_URL in `/etc/eracun/admin-portal-api.env`
   - Verify PostgreSQL is running: `sudo systemctl status postgresql`
   - Test connection: `psql $DATABASE_URL -c "SELECT 1"`

2. **JWT_SECRET not configured**
   ```
   Error: "JWT_SECRET not configured"
   ```
   - Generate secret: `openssl rand -base64 64`
   - Add to `/etc/eracun/admin-portal-api.env`: `JWT_SECRET=<generated-key>`
   - Restart: `sudo systemctl restart admin-portal-api`

3. **Port already in use**
   ```
   Error: "EADDRINUSE: address already in use :::8089"
   ```
   - Find process: `sudo lsof -i :8089`
   - Kill process or change HTTP_PORT in config

### 4.2 Authentication Failures

**Symptoms:** Login returns 401 Unauthorized

**Diagnosis:**
1. Check user exists and is active:
   ```sql
   SELECT email, active FROM users WHERE email = 'admin@eracun.hr';
   ```

2. Verify password hash:
   ```bash
   # In Node REPL
   node -e "const bcrypt = require('bcrypt'); bcrypt.compare('password', 'hash').then(console.log)"
   ```

3. Check JWT_SECRET consistency across restarts

**Resolution:**
- Reset user password:
  ```sql
  UPDATE users SET password_hash = '<new-bcrypt-hash>' WHERE email = 'admin@eracun.hr';
  ```
- Reactivate user:
  ```sql
  UPDATE users SET active = true WHERE email = 'admin@eracun.hr';
  ```

### 4.3 Rate Limiting Triggered

**Symptoms:** Client receives 429 Too Many Requests

**Diagnosis:**
```bash
# Check recent auth attempts
sudo journalctl -u admin-portal-api | grep "auth_attempts"
```

**Resolution:**
- Wait for rate limit window to expire (15 minutes for auth, 1 minute for API)
- Increase limits in config (not recommended for auth endpoints):
  ```bash
  RATE_LIMIT_MAX=10  # Increase from 5
  ```

### 4.4 Downstream Service Unavailable

**Symptoms:** Dashboard or error review returns 500 error

**Diagnosis:**
```bash
# Check downstream service health
curl http://health-monitor:8084/health
curl http://dead-letter-handler:8081/health

# Check Prometheus metrics
curl http://localhost:9094/metrics | grep downstream_calls_total
```

**Resolution:**
- Verify service URLs in config
- Check network connectivity
- Restart downstream service if crashed
- Admin portal gracefully degrades (returns partial data)

### 4.5 Database Connection Pool Exhausted

**Symptoms:** "Connection pool exhausted" errors in logs

**Diagnosis:**
```sql
SELECT COUNT(*) FROM pg_stat_activity WHERE datname = 'admin_portal';
```

**Resolution:**
1. Increase pool size:
   ```bash
   DB_POOL_MAX=100  # Increase from 50
   ```
2. Check for connection leaks (long-running queries)
3. Restart service to reset pool:
   ```bash
   sudo systemctl restart admin-portal-api
   ```

### 4.6 Expired Sessions Accumulating

**Symptoms:** High memory usage, slow session queries

**Diagnosis:**
```sql
SELECT COUNT(*) FROM sessions WHERE expires_at < NOW();
```

**Resolution:**
- Manual cleanup:
  ```sql
  DELETE FROM sessions WHERE expires_at < NOW();
  ```
- Service automatically cleans up expired sessions hourly
- Restart service to trigger cleanup immediately

### 4.7 JWT Secret Rotation

**Symptoms:** Need to rotate JWT secret for security

**Procedure:**
1. Generate new secret: `openssl rand -base64 64`
2. Update config: `/etc/eracun/admin-portal-api.env`
3. Restart service: `sudo systemctl restart admin-portal-api`
4. **⚠️ WARNING:** All existing tokens will be invalidated
5. Users must login again

### 4.8 User Locked Out

**Symptoms:** Admin user cannot login

**Emergency Access:**
```sql
-- Reset password to 'TemporaryPassword123!'
UPDATE users SET
  password_hash = '$2b$12$8oVJz1KZqYxqYxqYxqYxqYxqYxqYxqYxqYxqYxqYxqYxqYxqY',  -- Use actual bcrypt hash
  active = true
WHERE email = 'admin@eracun.hr';
```

Generate bcrypt hash:
```bash
node -e "const bcrypt = require('bcrypt'); bcrypt.hash('TemporaryPassword123!', 12).then(console.log)"
```

---

## 5. Disaster Recovery

### 5.1 Database Backup

**Backup procedure:**
```bash
# Backup database
pg_dump admin_portal > admin_portal_backup_$(date +%Y%m%d).sql

# Backup with compression
pg_dump admin_portal | gzip > admin_portal_backup_$(date +%Y%m%d).sql.gz
```

**Restore procedure:**
```bash
# Restore from backup
psql admin_portal < admin_portal_backup_20251112.sql

# Restore from compressed backup
gunzip -c admin_portal_backup_20251112.sql.gz | psql admin_portal
```

### 5.2 Service Recovery

**If service is unresponsive:**
```bash
# Stop service
sudo systemctl stop admin-portal-api

# Check for zombie processes
ps aux | grep admin-portal-api
sudo kill -9 <pid>

# Start service
sudo systemctl start admin-portal-api
sudo systemctl status admin-portal-api
```

**If service repeatedly crashes:**
1. Check logs: `sudo journalctl -u admin-portal-api -n 100`
2. Verify configuration: `/etc/eracun/admin-portal-api.env`
3. Test database connection manually
4. Redeploy from last known good version

### 5.3 Rollback Procedure

```bash
# Stop current service
sudo systemctl stop admin-portal-api

# Restore previous version
sudo cp -r /opt/eracun/services/admin-portal-api.backup/* /opt/eracun/services/admin-portal-api/

# Restart service
sudo systemctl start admin-portal-api

# Verify
curl http://localhost:8089/health
```

---

## 6. Maintenance

### 6.1 Routine Maintenance

**Daily:**
- Monitor error rates in Prometheus
- Check service health
- Review authentication logs for suspicious activity

**Weekly:**
- Review active sessions count
- Check database size
- Verify downstream service connectivity

**Monthly:**
- Rotate logs
- Clean up old sessions
- Review user accounts (deactivate unused)
- Update dependencies (security patches)

### 6.2 Updating Dependencies

```bash
cd /home/tomislav/PycharmProjects/eRačun/services/admin-portal-api

# Check for updates
npm outdated

# Update dependencies
npm update

# Run tests
npm test

# Rebuild and redeploy
npm run build
# Follow deployment procedure in Section 2.1
```

---

## 7. Performance Tuning

### 7.1 Database Optimization

```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_users_active ON users(active) WHERE active = true;
CREATE INDEX CONCURRENTLY idx_sessions_user_active ON sessions(user_id, expires_at) WHERE expires_at > NOW();

-- Vacuum database
VACUUM ANALYZE users;
VACUUM ANALYZE sessions;
```

### 7.2 Connection Pool Tuning

Adjust in `/etc/eracun/admin-portal-api.env`:
```bash
DB_POOL_MIN=20      # Increase for high traffic
DB_POOL_MAX=100     # Increase if pool exhaustion occurs
```

### 7.3 Rate Limit Tuning

```bash
# For production with high legitimate traffic
API_RATE_LIMIT_MAX=500  # Increase from 100

# Auth endpoint limits should stay strict
RATE_LIMIT_MAX=5  # Keep at 5 to prevent brute force
```

---

## 8. Security

### 8.1 Secrets Management

**JWT Secret:**
- Generate: `openssl rand -base64 64`
- Store in `/etc/eracun/admin-portal-api.env`
- Permissions: `chmod 600 /etc/eracun/admin-portal-api.env`
- Owner: `chown eracun:eracun /etc/eracun/admin-portal-api.env`

**Database Password:**
- Store in environment file
- Never commit to git
- Rotate quarterly

### 8.2 Audit Trail

**Review authentication logs:**
```bash
sudo journalctl -u admin-portal-api | grep '"operation":"login"'
```

**Review user management actions:**
```bash
sudo journalctl -u admin-portal-api | grep '"operation":"createUser\|updateUser\|deactivateUser"'
```

---

## 9. Contact Information

**On-Call Team:** DevOps Team
**Escalation:** System Architect
**Documentation:** `/docs/adr/`, `/CLAUDE.md`

---

**Last Review:** 2025-11-12
**Next Review:** 2025-12-12
