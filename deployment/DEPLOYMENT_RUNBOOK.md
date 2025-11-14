# eRačun Deployment Runbook

## Team 1: Core Processing Pipeline Deployment Guide

This runbook covers deployment procedures for the 4 core microservices:
- **invoice-gateway-api** (Port 3000)
- **invoice-orchestrator** (Port 3001)
- **ubl-transformer** (Port 3002)
- **validation-coordinator** (Port 3003)

---

## Prerequisites

### Server Requirements
- **OS**: Ubuntu 22.04 LTS or Debian 12+
- **Node.js**: 20.x LTS
- **User**: `eracun` (non-root with sudo privileges)
- **Disk**: 50GB minimum for services + logs
- **Memory**: 8GB minimum (16GB recommended)
- **CPU**: 4 cores minimum

### Software Dependencies
```bash
# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install SOPS for secrets management
sudo curl -Lo /usr/local/bin/sops https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64
sudo chmod +x /usr/local/bin/sops

# Install age for encryption
sudo apt-get install -y age

# Install PostgreSQL client
sudo apt-get install -y postgresql-client

# Install rsync for deployments
sudo apt-get install -y rsync
```

### Directory Structure Setup
```bash
# Create eracun user
sudo useradd -r -m -s /bin/bash eracun
sudo usermod -aG sudo eracun

# Create directory structure
sudo mkdir -p /opt/eracun/services
sudo mkdir -p /opt/eracun/backups
sudo mkdir -p /etc/eracun/services
sudo mkdir -p /etc/eracun/secrets
sudo mkdir -p /var/lib/eracun
sudo mkdir -p /var/log/eracun
sudo mkdir -p /run/eracun

# Set permissions
sudo chown -R eracun:eracun /opt/eracun
sudo chown -R eracun:eracun /var/lib/eracun
sudo chown -R eracun:eracun /var/log/eracun
sudo chown -R eracun:eracun /run/eracun
sudo chmod 700 /etc/eracun/secrets
```

---

## Initial Deployment

### Step 1: Build Services Locally

```bash
# Clone repository
git clone https://github.com/tpatarci/eRacun-development.git
cd eRacun-development

# Install dependencies
npm install

# Build all services
cd services/invoice-gateway-api && npm install && npm run build && cd ../..
cd services/invoice-orchestrator && npm install && npm run build && cd ../..
cd services/ubl-transformer && npm install && npm run build && cd ../..
cd services/validation-coordinator && npm install && npm run build && cd ../..
```

### Step 2: Deploy systemd Service Files

```bash
# Copy service files to systemd
sudo cp deployment/systemd/*.service /etc/systemd/system/

# Copy helper scripts
sudo cp deployment/scripts/sops-decrypt.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/sops-decrypt.sh

# Reload systemd
sudo systemctl daemon-reload
```

### Step 3: Configure Secrets (SOPS)

```bash
# Generate age key (one-time)
age-keygen -o /etc/eracun/.age-key
sudo chown eracun:eracun /etc/eracun/.age-key
sudo chmod 400 /etc/eracun/.age-key

# Create encrypted secrets (example for invoice-gateway-api)
cat > /tmp/invoice-gateway-api.yaml <<EOF
DATABASE_URL: "postgresql://user:pass@localhost:5432/eracun"
RABBITMQ_URL: "amqp://user:pass@localhost:5672"
JWT_SECRET: "your-secret-key-here"
EOF

# Encrypt with SOPS
export SOPS_AGE_KEY_FILE=/etc/eracun/.age-key
sops -e /tmp/invoice-gateway-api.yaml > /etc/eracun/secrets/invoice-gateway-api.enc.yaml

# Secure and cleanup
sudo chown eracun:eracun /etc/eracun/secrets/invoice-gateway-api.enc.yaml
sudo chmod 600 /etc/eracun/secrets/invoice-gateway-api.enc.yaml
rm /tmp/invoice-gateway-api.yaml
```

### Step 4: Deploy Services

```bash
# Deploy each service
./deployment/scripts/deploy-service.sh invoice-gateway-api staging
./deployment/scripts/deploy-service.sh invoice-orchestrator staging
./deployment/scripts/deploy-service.sh ubl-transformer staging
./deployment/scripts/deploy-service.sh validation-coordinator staging
```

### Step 5: Enable and Start Services

```bash
# Enable services to start on boot
sudo systemctl enable eracun-invoice-gateway-api
sudo systemctl enable eracun-invoice-orchestrator
sudo systemctl enable eracun-ubl-transformer
sudo systemctl enable eracun-validation-coordinator

# Start all services
sudo systemctl start eracun-invoice-gateway-api
sudo systemctl start eracun-invoice-orchestrator
sudo systemctl start eracun-ubl-transformer
sudo systemctl start eracun-validation-coordinator
```

---

## Verification

### Check Service Status
```bash
# Check all services
sudo systemctl status eracun-*

# Check specific service
sudo systemctl status eracun-invoice-gateway-api
```

### View Logs
```bash
# Real-time logs
sudo journalctl -u eracun-invoice-gateway-api -f

# Last 100 lines
sudo journalctl -u eracun-invoice-gateway-api -n 100

# Logs since boot
sudo journalctl -u eracun-invoice-gateway-api -b
```

### Health Checks
```bash
# Invoice Gateway API
curl http://localhost:3000/health

# Expected response:
# {"status":"UP","timestamp":"2025-11-14T...","dependencies":{...}}
```

### Resource Usage
```bash
# Check memory usage
sudo systemctl status eracun-invoice-gateway-api | grep Memory

# Check CPU usage
top -p $(pgrep -f invoice-gateway-api)
```

---

## Rollback Procedure

### Quick Rollback (< 5 minutes)

```bash
# Rollback to latest backup
./deployment/scripts/rollback-service.sh invoice-gateway-api production

# Rollback to specific backup
./deployment/scripts/rollback-service.sh invoice-gateway-api production 20251114-143022
```

### Manual Rollback

```bash
# Stop service
sudo systemctl stop eracun-invoice-gateway-api

# Restore from backup
sudo rm -rf /opt/eracun/services/invoice-gateway-api
sudo cp -r /opt/eracun/backups/invoice-gateway-api-20251114-143022 \
          /opt/eracun/services/invoice-gateway-api
sudo chown -R eracun:eracun /opt/eracun/services/invoice-gateway-api

# Start service
sudo systemctl start eracun-invoice-gateway-api

# Verify
sudo systemctl status eracun-invoice-gateway-api
```

---

## Troubleshooting

### Service Won't Start

**Check logs:**
```bash
sudo journalctl -u eracun-invoice-gateway-api -n 100 --no-pager
```

**Common issues:**

1. **Missing secrets:**
   ```bash
   # Verify secrets exist
   ls -la /etc/eracun/secrets/invoice-gateway-api.enc.yaml

   # Test decryption
   /usr/local/bin/sops-decrypt.sh invoice-gateway-api
   cat /run/eracun/invoice-gateway-api.env
   ```

2. **Port already in use:**
   ```bash
   # Find process using port
   sudo lsof -i :3000

   # Kill process if needed
   sudo kill -9 <PID>
   ```

3. **Permission errors:**
   ```bash
   # Fix ownership
   sudo chown -R eracun:eracun /opt/eracun/services/invoice-gateway-api
   sudo chown -R eracun:eracun /var/lib/eracun/invoice-gateway-api
   ```

4. **Missing dependencies:**
   ```bash
   cd /opt/eracun/services/invoice-gateway-api
   npm ci --production
   ```

### High Memory Usage

```bash
# Check memory limit
sudo systemctl show eracun-invoice-gateway-api | grep MemoryMax

# Adjust memory limit (if needed)
sudo systemctl edit eracun-invoice-gateway-api
# Add: [Service]
#      MemoryMax=2G

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart eracun-invoice-gateway-api
```

### Database Connection Issues

```bash
# Test PostgreSQL connection
psql -h localhost -U eracun_user -d eracun_db

# Check connection pool
# (from service logs)
sudo journalctl -u eracun-invoice-gateway-api | grep "connection pool"
```

---

## Monitoring

### Key Metrics to Monitor

**Invoice Gateway API:**
- Request rate (req/s)
- Response time p95 (< 200ms)
- Error rate (< 0.1%)
- Memory usage (< 768MB)

**Invoice Orchestrator:**
- Saga completion rate
- Compensation execution count
- Queue depth
- Memory usage (< 768MB)

**UBL Transformer:**
- Transformation success rate
- Processing time p95 (< 1s)
- Memory usage (< 1.5GB for large files)

**Validation Coordinator:**
- Validation success rate
- Confidence score distribution
- Layer execution times
- Memory usage (< 1.5GB)

### Prometheus Metrics

```bash
# Metrics endpoints (when implemented)
curl http://localhost:3000/metrics
```

---

## Security Audit

### Verify Security Hardening

```bash
# Check service security score
sudo systemd-analyze security eracun-invoice-gateway-api

# Expected: Score of 8.0+ out of 10
```

### Verify File Permissions

```bash
# Secrets should be 600
ls -la /etc/eracun/secrets/

# age key should be 400
ls -la /etc/eracun/.age-key

# Service directories should be owned by eracun
ls -la /opt/eracun/services/
```

---

## Disaster Recovery

### Backup Procedures

**Automated (via systemd timer - recommended):**
```bash
# Create backup timer
sudo systemctl enable eracun-backup.timer
sudo systemctl start eracun-backup.timer
```

**Manual backup:**
```bash
# Backup all services
for service in invoice-gateway-api invoice-orchestrator ubl-transformer validation-coordinator; do
  sudo tar czf /opt/eracun/backups/${service}-$(date +%Y%m%d-%H%M%S).tar.gz \
    /opt/eracun/services/${service}
done

# Backup secrets
sudo tar czf /opt/eracun/backups/secrets-$(date +%Y%m%d-%H%M%S).tar.gz \
  /etc/eracun/secrets
```

### Full System Recovery

1. Restore from backups
2. Reinstall systemd service files
3. Restore secrets
4. Start services
5. Verify functionality

---

## Production Deployment Checklist

- [ ] All tests passing locally
- [ ] Build successful
- [ ] Secrets configured and encrypted
- [ ] Backup of current version created
- [ ] Deployment window scheduled (low traffic period)
- [ ] Team notified
- [ ] Monitoring dashboard open
- [ ] Rollback plan ready
- [ ] Post-deployment smoke tests prepared

---

**Document Version:** 1.0.0
**Last Updated:** 2025-11-14
**Owner:** Team 1 - Core Processing Pipeline
**Review Cadence:** After each production deployment
