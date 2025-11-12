# Deployment Guide

## Target Environment

**Platform:** DigitalOcean Dedicated Droplets (Linux)
**Operating System:** Ubuntu 22.04 LTS or Debian 12+
**Orchestrator:** systemd (native Linux service manager)
**Architecture:** Unix-native, filesystem-based configuration
**Philosophy:** Classic Unix conventions (POSIX standards, FHS compliance)

---

## 1. Environments

### Development
- **Hostname:** `dev.eracun.internal`
- **Location:** Local or dedicated droplet
- **Purpose:** Local development and testing
- **Database:** Local PostgreSQL instance
- **Message Broker:** Local RabbitMQ

### Staging
- **Hostname:** `staging.eracun.internal`
- **Location:** DigitalOcean droplet
- **Purpose:** Integration testing with FINA test environment
- **FINA Endpoint:** `cistest.apis-it.hr:8449/FiskalizacijaServiceTest`
- **Certificates:** FINA demo certificates (free)

### Production
- **Hostname:** `production.eracun.hr`
- **Location:** DigitalOcean droplet (EU region)
- **Purpose:** Production workload
- **FINA Endpoint:** `cis.porezna-uprava.hr:8449/FiskalizacijaService`
- **Certificates:** FINA production certificates (~40 EUR)

---

## 2. Infrastructure Components

### Message Bus
- **RabbitMQ:** Self-hosted on droplet
- **Version:** 3.12+
- **Management UI:** Port 15672 (internal only)
- **AMQP Port:** 5672

### Database
- **PostgreSQL:** DigitalOcean Managed Database (recommended)
- **Version:** 15+
- **Connection Pooling:** PgBouncer
- **Backups:** Automated daily + WAL archiving

### Observability
- **Prometheus:** Self-hosted for metrics
- **Grafana:** Self-hosted for dashboards
- **Jaeger:** Self-hosted for distributed tracing
- **Loki:** Self-hosted for log aggregation

### Future Considerations
- **Temporal:** Workflow engine for complex sagas
- **Kubernetes:** If horizontal scaling exceeds single-server capacity

---

## 3. systemd Service Deployment

### File System Layout
```
/etc/systemd/system/          # Service unit files
/opt/eracun/services/         # Service code
/etc/eracun/                  # Configuration files
/var/lib/eracun/              # Service data
/var/log/eracun/              # Log files
/run/eracun/                  # Runtime secrets (tmpfs)
```

### Service Unit Template
```ini
[Unit]
Description=eRacun %i Service
After=network.target rabbitmq-server.service postgresql.service
Requires=rabbitmq-server.service

[Service]
Type=simple
User=eracun
Group=eracun
WorkingDirectory=/opt/eracun/services/%i
ExecStartPre=/usr/local/bin/sops-decrypt.sh %i
ExecStart=/usr/bin/node /opt/eracun/services/%i/dist/index.js
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=10s

# Security Hardening (see @docs/SECURITY.md)
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/eracun/%i /var/log/eracun/%i
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
InaccessiblePaths=/etc/eracun/.age-key

# Resource Limits
MemoryMax=1G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
```

---

## 4. Rolling Deployment Process

### Step 1: Build
```bash
# In CI/CD or locally
npm run build
npm test
npm run lint
```

### Step 2: Transfer Artifacts
```bash
# rsync to droplet
rsync -avz --delete \
  dist/ \
  user@staging.eracun.internal:/opt/eracun/services/invoice-gateway-api/dist/
```

### Step 3: Update Configuration (if needed)
```bash
# Update service-specific config
sudo vim /etc/eracun/services/invoice-gateway-api.conf

# Decrypt and update secrets
cd /etc/eracun/secrets
sops secrets.yaml  # Edit with SOPS
```

### Step 4: Deploy
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Restart service
sudo systemctl restart eracun-invoice-gateway-api

# Verify service started
sudo systemctl status eracun-invoice-gateway-api

# Check logs
sudo journalctl -u eracun-invoice-gateway-api -f
```

---

## 5. Zero-Downtime Deployment

### Strategy
- Run multiple service instances behind nginx/HAProxy
- Drain connections before restart
- Health checks prevent routing to restarting services

### Load Balancer Configuration (nginx)
```nginx
upstream invoice_gateway {
  least_conn;
  server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
  server 127.0.0.1:3002 max_fails=3 fail_timeout=30s;
}

server {
  listen 443 ssl http2;
  server_name api.eracun.hr;

  location /health {
    proxy_pass http://invoice_gateway;
    proxy_connect_timeout 1s;
  }

  location / {
    proxy_pass http://invoice_gateway;
    proxy_set_header X-Request-ID $request_id;
  }
}
```

### Deployment Steps
1. Stop instance 1: `systemctl stop eracun-invoice-gateway-api@1`
2. Deploy new code to instance 1
3. Start instance 1: `systemctl start eracun-invoice-gateway-api@1`
4. Wait for health check to pass
5. Repeat for instance 2
6. Verify both instances healthy

---

## 6. Rollback Procedure

### Quick Rollback (<5 minutes)
```bash
# Stop new version
sudo systemctl stop eracun-invoice-gateway-api

# Restore previous version
sudo rsync -avz \
  /opt/eracun/backups/invoice-gateway-api-prev/ \
  /opt/eracun/services/invoice-gateway-api/

# Start service
sudo systemctl start eracun-invoice-gateway-api

# Verify
sudo systemctl status eracun-invoice-gateway-api
```

### Database Rollback
```bash
# If schema changes were made
psql -U postgres -d eracun -f /opt/eracun/backups/rollback-migration.sql

# Verify data integrity
npm run test:integration
```

---

## 7. System-Level Services

### Critical Daemons
- `eracun-healthcheck.service` - System-wide health monitoring
- `eracun-deadletter.service` - Failed message reprocessing
- `eracun-audit.service` - Immutable audit log writer

### Scheduled Tasks (systemd timers)
- `eracun-daily-report.timer` - Daily reconciliation reports
- `eracun-cert-renewal.timer` - TLS certificate rotation (30 days before expiry)
- `eracun-backup-verification.timer` - Backup integrity checks

### Example Timer Unit
```ini
[Unit]
Description=eRacun Daily Report Timer

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

---

## 8. Monitoring Deployment

### Post-Deployment Checklist
- [ ] Service status: `systemctl status eracun-*`
- [ ] Logs: No errors in `journalctl -u eracun-*`
- [ ] Health endpoint: `curl https://api.eracun.hr/health`
- [ ] Metrics: Prometheus targets up
- [ ] Queue depths: RabbitMQ queues processing
- [ ] Database connections: No connection pool exhaustion

### Deployment Metrics
```promql
# Deployment success rate
sum(rate(deployment_success_total[1h])) / sum(rate(deployment_total[1h]))

# Service restart count
increase(systemd_unit_state_change_total{name=~"eracun-.*"}[1h])

# Error rate spike after deployment
rate(http_requests_total{status=~"5.."}[5m])
```

---

## 9. Troubleshooting

### Service Won't Start
```bash
# Check service status
sudo systemctl status eracun-invoice-gateway-api

# Check logs
sudo journalctl -u eracun-invoice-gateway-api -n 100

# Check configuration
sudo /opt/eracun/services/invoice-gateway-api/bin/check-config.sh

# Verify secrets decrypted
ls -la /run/eracun/
```

### Database Connection Issues
```bash
# Test connection
psql -h localhost -U eracun_user -d eracun_db

# Check connection pool
sudo systemctl status pgbouncer
psql -p 6432 -U pgbouncer -d pgbouncer -c "SHOW POOLS"
```

### RabbitMQ Issues
```bash
# Check RabbitMQ status
sudo systemctl status rabbitmq-server

# Check queues
sudo rabbitmqctl list_queues

# Check connections
sudo rabbitmqctl list_connections
```

---

## Related Documentation

- **Security Hardening:** @docs/SECURITY.md (systemd directives)
- **Configuration Management:** @docs/adr/ADR-001-configuration-strategy.md
- **Secrets Management:** @docs/adr/ADR-002-secrets-management.md
- **Operations Runbooks:** @docs/operations/ (incident response)

---

**Last Updated:** 2025-11-12
**Document Owner:** DevOps Team
**Review Cadence:** Monthly
