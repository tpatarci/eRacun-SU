# systemd Service Deployment

This directory contains systemd service units for the eRacun platform.

---

## Files

| File | Purpose |
|------|---------|
| `eracun-service.template` | Template for creating new service units |
| `eracun-email-worker.service` | Example service (email ingestion worker) |
| `decrypt-secrets.sh` | Script to decrypt SOPS secrets before service start |

---

## Initial Droplet Setup (One-Time)

### 1. Install Required Tools

```bash
# Update package list
sudo apt-get update

# Install age (encryption tool)
sudo apt-get install -y age

# Install SOPS (secrets management)
wget https://github.com/mozilla/sops/releases/download/v3.8.1/sops_3.8.1_amd64.deb
sudo dpkg -i sops_3.8.1_amd64.deb

# Install Node.js (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PostgreSQL client (for database access)
sudo apt-get install -y postgresql-client

# Install RabbitMQ (message bus)
sudo apt-get install -y rabbitmq-server
sudo systemctl enable rabbitmq-server
sudo systemctl start rabbitmq-server
```

### 2. Create Service User

```bash
# Create eracun system user (no login shell)
sudo useradd -r -s /bin/false eracun

# Create required directories
sudo mkdir -p /etc/eracun/{services,secrets}
sudo mkdir -p /opt/eracun/services
sudo mkdir -p /var/log/eracun
sudo mkdir -p /var/lib/eracun

# Set ownership
sudo chown -R eracun:eracun /etc/eracun /opt/eracun /var/log/eracun /var/lib/eracun

# Secure secrets directory
sudo chmod 700 /etc/eracun/secrets
```

### 3. Generate age Key Pair

```bash
# Generate production age key
sudo age-keygen -o /etc/eracun/.age-key

# Secure the private key
sudo chmod 600 /etc/eracun/.age-key
sudo chown root:root /etc/eracun/.age-key

# Get public key (add to repository secrets/.sops.yaml)
sudo age-keygen -y /etc/eracun/.age-key
# Output: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# IMPORTANT: Backup the private key to secure location
# (encrypted USB drive + password manager)
```

### 4. Install decrypt-secrets.sh Script

```bash
# Copy script from repository
sudo cp deployment/systemd/decrypt-secrets.sh /usr/local/bin/

# Make executable
sudo chmod 755 /usr/local/bin/decrypt-secrets.sh

# Test (should show usage)
/usr/local/bin/decrypt-secrets.sh
```

---

## Deploying a Service

### 1. Build Service Locally

```bash
# In service directory (e.g., services/email-worker/)
npm install
npm run build

# Test locally
npm run test
```

### 2. Deploy to Droplet

```bash
# Copy built service to droplet
rsync -avz --exclude node_modules \
  services/email-worker/ \
  deploy@droplet:/opt/eracun/services/email-worker/

# SSH to droplet
ssh deploy@droplet

# Install dependencies (production only)
cd /opt/eracun/services/email-worker
sudo npm install --omit=dev
```

### 3. Deploy Configuration

```bash
# Copy configuration from repository
sudo cp config/platform.conf.example /etc/eracun/platform.conf
sudo cp config/environment-production.conf /etc/eracun/environment.conf
sudo cp config/services/email-worker.conf.example /etc/eracun/services/email-worker.conf

# Edit with environment-specific values
sudo vim /etc/eracun/environment.conf
sudo vim /etc/eracun/services/email-worker.conf

# Set permissions
sudo chmod 644 /etc/eracun/*.conf
sudo chmod 644 /etc/eracun/services/*.conf
```

### 4. Deploy Secrets

```bash
# Copy encrypted secrets from repository
sudo cp secrets/email-worker-production.env.enc /etc/eracun/secrets/

# Set permissions
sudo chmod 600 /etc/eracun/secrets/*.enc

# Test decryption (should create /run/eracun/secrets.env)
sudo /usr/local/bin/decrypt-secrets.sh email-worker

# Verify decrypted secrets exist
sudo ls -la /run/eracun/
sudo cat /run/eracun/secrets.env  # Check (then delete from terminal history)
```

### 5. Install systemd Service

```bash
# Copy service unit
sudo cp deployment/systemd/eracun-email-worker.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable eracun-email-worker

# Start service
sudo systemctl start eracun-email-worker

# Check status
sudo systemctl status eracun-email-worker
```

### 6. Monitor Service

```bash
# View logs
sudo journalctl -u eracun-email-worker -f

# Check for errors
sudo journalctl -u eracun-email-worker -p err

# View last 100 lines
sudo journalctl -u eracun-email-worker -n 100
```

---

## Creating a New Service

### 1. Copy Template

```bash
cd deployment/systemd/
cp eracun-service.template eracun-my-service.service
```

### 2. Customize Service File

Replace placeholders:
- `{{SERVICE_NAME}}` → `my-service`
- `{{SERVICE_PORT}}` → `3002` (or actual port)
- `{{SERVICE_DESCRIPTION}}` → "eRacun My Service Description"

Adjust dependencies:
```ini
After=network-online.target postgresql.service
Wants=postgresql.service
```

Adjust resource limits:
```ini
MemoryMax=2G
CPUQuota=400%
```

### 3. Test Service

```bash
# Check syntax
systemd-analyze verify eracun-my-service.service

# Install
sudo cp eracun-my-service.service /etc/systemd/system/
sudo systemctl daemon-reload

# Start (without enabling)
sudo systemctl start eracun-my-service

# Check for errors
sudo systemctl status eracun-my-service
sudo journalctl -u eracun-my-service

# If working, enable for auto-start
sudo systemctl enable eracun-my-service
```

---

## Common Operations

### Restart Service

```bash
sudo systemctl restart eracun-email-worker
```

### Stop Service

```bash
sudo systemctl stop eracun-email-worker
```

### Disable Service (prevent auto-start on boot)

```bash
sudo systemctl disable eracun-email-worker
```

### View Service Status

```bash
sudo systemctl status eracun-email-worker
```

### Reload Configuration (without restarting)

**NOTE:** Services must implement SIGHUP handling for this to work.

```bash
sudo systemctl reload eracun-email-worker
```

### View Environment Variables

```bash
sudo systemctl show eracun-email-worker --property=Environment
```

---

## Troubleshooting

### Service Won't Start

**Check logs:**
```bash
sudo journalctl -u eracun-email-worker -n 50
```

**Common issues:**
- Missing configuration file → Check `/etc/eracun/*.conf` exist
- Secrets decryption failed → Verify age key at `/etc/eracun/.age-key`
- Permission denied → Check `/opt/eracun/services/email-worker` owned by `eracun:eracun`
- Port already in use → Check if another service using same port

### Secrets Decryption Fails

**Test manually:**
```bash
sudo /usr/local/bin/decrypt-secrets.sh email-worker
```

**Check age public key:**
```bash
sudo age-keygen -y /etc/eracun/.age-key
```

**Verify `.sops.yaml` includes this public key** (in repository `secrets/.sops.yaml`)

### Service Crashes Immediately

**Check for missing dependencies:**
```bash
cd /opt/eracun/services/email-worker
npm install --omit=dev
```

**Check Node.js version:**
```bash
node --version  # Should be 20.x or higher
```

### High Memory Usage

**Check current usage:**
```bash
systemctl status eracun-email-worker
```

**Adjust `MemoryMax` in service file:**
```ini
MemoryMax=2G
```

**Reload and restart:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart eracun-email-worker
```

---

## Security Best Practices

✅ **DO:**
- Run services as `eracun` user (not root)
- Use `ProtectSystem=strict` in service units
- Restrict file access with `ReadOnlyPaths` and `InaccessiblePaths`
- Enable `NoNewPrivileges=true`
- Use `PrivateTmp=true` for process isolation
- Monitor logs for suspicious activity

❌ **DON'T:**
- Run services as root
- Give services write access to `/etc/eracun/`
- Store plaintext secrets in `/etc/eracun/` (use SOPS encryption)
- Commit `.age-key` to git
- Share production age key with developers

---

## References

- **ADR-001:** Configuration Management Strategy
- **ADR-002:** Secrets Management with SOPS + age
- **systemd Documentation:** https://www.freedesktop.org/software/systemd/man/
- **systemd Security:** https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Sandboxing

---

**Questions?** See `docs/operations/` for detailed guides or open GitHub issue.
