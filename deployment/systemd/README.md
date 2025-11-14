# systemd Service Units - Team 3

Production-ready systemd service units with comprehensive security hardening for all Team 3 services.

## Services Included

1. **eracun-digital-signature-service.service** - XMLDSig signing and ZKI generation
2. **eracun-fina-connector.service** - FINA Tax Authority integration
3. **eracun-archive-service.service** - 11-year invoice archival (WORM storage)
4. **eracun-dead-letter-handler.service** - Failed message recovery
5. **eracun-cert-lifecycle-manager.service** - X.509 certificate management
6. **eracun-porezna-connector.service** - Porezna Uprava integration
7. **eracun-reporting-service.service** - Compliance reporting

## Security Hardening Features

All service units include comprehensive systemd security directives per @docs/SECURITY.md:

### Filesystem Protection
- `ProtectSystem=strict` - Read-only /usr, /boot, /efi
- `ProtectHome=true` - No access to /home, /root
- `PrivateTmp=true` - Isolated /tmp directory
- `ReadWritePaths` - Explicit write permissions only
- `InaccessiblePaths` - Hide encryption keys from service

### Privilege Restrictions
- `NoNewPrivileges=true` - Can't gain new privileges
- `CapabilityBoundingSet=` - Drop ALL Linux capabilities
- `User=eracun` / `Group=eracun` - Run as dedicated user

### System Call Filtering
- `SystemCallFilter=@system-service` - Whitelist system service calls
- `SystemCallFilter=~@privileged @resources @obsolete @debug @mount @swap @reboot @module @raw-io` - Block dangerous syscalls
- `SystemCallErrorNumber=EPERM` - Return permission denied on blocked calls

### Network Restrictions
- `RestrictAddressFamilies=AF_INET AF_INET6` - Only IPv4/IPv6
- `IPAddressDeny=any` - Default deny all
- `IPAddressAllow` - Whitelist localhost and RFC1918 ranges

### Kernel Protection
- `ProtectKernelTunables=true` - Can't modify /proc/sys
- `ProtectKernelModules=true` - Can't load kernel modules
- `ProtectKernelLogs=true` - Can't read kernel logs
- `ProtectControlGroups=true` - Can't modify cgroups

### Process Restrictions
- `LockPersonality=true` - Can't change execution domain
- `RestrictRealtime=true` - No real-time scheduling
- `RestrictSUIDSGID=true` - Can't change SUID/SGID bits
- `RestrictNamespaces=true` - Can't create namespaces

### Resource Limits
- `MemoryMax` - Hard memory limit (service killed if exceeded)
- `MemoryHigh` - Soft memory limit (throttled if exceeded)
- `CPUQuota` - CPU usage percentage limit
- `TasksMax` - Max number of processes/threads

## Installation

### Prerequisites
```bash
# Create eracun user and group
sudo useradd -r -s /bin/false eracun

# Create directories
sudo mkdir -p /opt/eracun/services
sudo mkdir -p /etc/eracun
sudo mkdir -p /var/lib/eracun
sudo mkdir -p /var/log/eracun

# Set permissions
sudo chown -R eracun:eracun /opt/eracun
sudo chown -R eracun:eracun /var/lib/eracun
sudo chown -R eracun:eracun /var/log/eracun
sudo chmod 700 /etc/eracun
```

### Deploy Service

```bash
# 1. Copy service code
sudo cp -r services/digital-signature-service/dist /opt/eracun/services/digital-signature-service/
sudo cp services/digital-signature-service/package.json /opt/eracun/services/digital-signature-service/
sudo chown -R eracun:eracun /opt/eracun/services/digital-signature-service

# 2. Install dependencies
cd /opt/eracun/services/digital-signature-service
sudo -u eracun npm ci --production

# 3. Copy systemd unit
sudo cp deployment/systemd/eracun-digital-signature-service.service /etc/systemd/system/

# 4. Create environment file
sudo cp services/digital-signature-service/.env.example /etc/eracun/digital-signature-service.env
sudo vim /etc/eracun/digital-signature-service.env  # Edit configuration
sudo chmod 600 /etc/eracun/digital-signature-service.env

# 5. Reload systemd
sudo systemctl daemon-reload

# 6. Enable and start service
sudo systemctl enable eracun-digital-signature-service
sudo systemctl start eracun-digital-signature-service

# 7. Verify
sudo systemctl status eracun-digital-signature-service
sudo journalctl -u eracun-digital-signature-service -f
```

## Service Management

### Start/Stop/Restart
```bash
sudo systemctl start eracun-digital-signature-service
sudo systemctl stop eracun-digital-signature-service
sudo systemctl restart eracun-digital-signature-service
sudo systemctl reload eracun-digital-signature-service  # If supported
```

### Enable/Disable
```bash
# Start on boot
sudo systemctl enable eracun-digital-signature-service

# Don't start on boot
sudo systemctl disable eracun-digital-signature-service
```

### Status and Logs
```bash
# Service status
sudo systemctl status eracun-digital-signature-service

# View logs (last 100 lines)
sudo journalctl -u eracun-digital-signature-service -n 100

# Follow logs (real-time)
sudo journalctl -u eracun-digital-signature-service -f

# Logs since boot
sudo journalctl -u eracun-digital-signature-service -b

# Logs for specific time range
sudo journalctl -u eracun-digital-signature-service --since "2025-11-14 10:00" --until "2025-11-14 11:00"
```

## Security Analysis

### Verify Hardening
```bash
# Analyze service security score (0-10, higher is better)
sudo systemd-analyze security eracun-digital-signature-service

# Target score: 8.0+/10
```

### Test Restrictions
```bash
# Try to write to /usr (should fail)
sudo systemctl start eracun-digital-signature-service
# Service should log permission denied

# Check which system calls are blocked
sudo systemctl show eracun-digital-signature-service | grep SystemCallFilter
```

## Troubleshooting

### Service Won't Start
```bash
# Check systemd status
sudo systemctl status eracun-digital-signature-service

# Check logs
sudo journalctl -u eracun-digital-signature-service -n 100

# Validate unit file syntax
sudo systemd-analyze verify eracun-digital-signature-service.service

# Check file permissions
ls -la /opt/eracun/services/digital-signature-service
ls -la /etc/eracun/digital-signature-service.env
```

### Permission Denied Errors
```bash
# Check if path is in ReadWritePaths
sudo systemctl show eracun-digital-signature-service | grep ReadWritePaths

# Add path to unit file if needed
ReadWritePaths=/var/lib/eracun/digital-signature-service /var/log/eracun
```

### High Memory Usage
```bash
# Check memory limit
sudo systemctl show eracun-digital-signature-service | grep Memory

# Adjust in unit file
MemoryMax=2G  # Increase limit
MemoryHigh=1536M
```

## Deployment Checklist

- [ ] Service code deployed to /opt/eracun/services/<service>/
- [ ] Dependencies installed (npm ci --production)
- [ ] Environment file created in /etc/eracun/<service>.env
- [ ] Environment file permissions set to 600
- [ ] systemd unit copied to /etc/systemd/system/
- [ ] systemctl daemon-reload executed
- [ ] Service enabled with systemctl enable
- [ ] Service started with systemctl start
- [ ] Service status verified (systemctl status)
- [ ] Logs checked (journalctl -u <service> -f)
- [ ] Health endpoint responding (curl http://localhost:<port>/health)
- [ ] Metrics endpoint responding (curl http://localhost:<metrics-port>/metrics)
- [ ] Prometheus scraping service metrics
- [ ] Security score verified (systemd-analyze security)

## Related Documentation

- **Security Standards:** @docs/SECURITY.md
- **Deployment Guide:** @docs/DEPLOYMENT_GUIDE.md
- **SOPS Secrets:** @docs/adr/ADR-002-secrets-management.md
- **systemd Reference:** https://www.freedesktop.org/software/systemd/man/systemd.exec.html

---

**Last Updated:** 2025-11-14
**Maintainer:** DevOps Team
