# Security Standards

## Zero Trust Architecture

**Core Principle:** Never trust, always verify.

### Security Boundaries
- No service trusts incoming data without validation
- All inter-service communication authenticated (mTLS in production)
- Input sanitization at every boundary
- Defense in depth - multiple layers of protection

---

## 1. Secrets Management

### SOPS + age Encryption

**Technology Stack:**
- **SOPS:** Mozilla's Secrets OPerationS (open source, €0 cost)
- **age:** Modern encryption tool (simple, secure)
- **Storage:** Encrypted secrets safe in git repository

### File System Layout
```
/etc/eracun/secrets/         # Encrypted secrets (600 permissions)
/run/eracun/                 # Decrypted secrets (tmpfs, cleared on reboot)
```

### systemd Integration
```ini
[Service]
ExecStartPre=/usr/local/bin/sops-decrypt.sh
User=eracun
Group=eracun
```

### Permissions
- Services run as `eracun` user (never root)
- Secret files: 600 (`-rw-------`)
- Secret directories: 700 (`drwx------`)
- Age keys: 400 (`-r--------`)

### Git Protection
**NEVER commit to git:**
- `.p12` files (PKCS#12 certificates)
- `.key` files (private keys)
- `.pem` files (certificates)
- `.env` files (environment variables)
- `*.dec.yaml` (decrypted SOPS files)

**Protected by .gitignore and pre-commit hooks**

### See Also
- ADR-001: Configuration Management Strategy
- ADR-002: Secrets Management with SOPS
- `deployment/systemd/` for implementation

---

## 2. XML Security

**Critical for e-invoice processing - XML is attack vector**

### XXE (XML External Entity) Prevention
```typescript
// ALWAYS disable external entities
const parser = new XMLParser({
  resolveExternalEntities: false,
  resolveExternalDTDs: false,
  forbidExternalEntityResolution: true
});
```

### Input Validation
1. **Schema validation BEFORE parsing**
   - XSD validation first
   - Reject invalid XML immediately
   - Never parse untrusted XML without validation

2. **Size limits enforced**
   - Max 10MB per document
   - Reject oversized payloads at API gateway
   - Prevents memory exhaustion attacks

3. **Billion Laughs Attack Protection**
   - Detect entity expansion bombs
   - Limit entity nesting depth
   - Timeout on excessive parsing time

### XML Processing Checklist
- [ ] External entities disabled
- [ ] Schema validated
- [ ] Size limit checked (<10MB)
- [ ] Entity expansion limited
- [ ] Parsing timeout configured
- [ ] Error messages don't leak structure

---

## 3. systemd Service Hardening

**Linux kernel security features via systemd**

### Mandatory Hardening Directives
```ini
[Service]
# Filesystem Protection
ProtectSystem=strict           # Read-only /usr, /boot, /efi
ProtectHome=true              # No access to /home, /root
ReadWritePaths=/var/lib/eracun  # Only explicit paths writable
PrivateTmp=true               # Isolated /tmp directory

# Privilege Restrictions
NoNewPrivileges=true          # Can't gain new privileges
CapabilityBoundingSet=        # Drop ALL Linux capabilities
User=eracun                   # Run as dedicated user
Group=eracun                  # Run as dedicated group

# System Call Filtering
SystemCallFilter=@system-service  # Only allow system-service syscalls
SystemCallErrorNumber=EPERM      # Return EPERM on blocked syscalls

# Secrets Protection
InaccessiblePaths=/etc/eracun/.age-key  # Hide encryption keys
ProtectKernelModules=true      # Can't load kernel modules
ProtectKernelLogs=true         # Can't read kernel logs
ProtectControlGroups=true      # Can't modify cgroups
```

### Security Layers Explained

**ProtectSystem=strict:**
- Entire filesystem read-only except explicit exceptions
- Prevents malware from modifying binaries
- Service code can't be tampered with at runtime

**CapabilityBoundingSet=:**
- Drops all Linux capabilities
- Service runs with minimal permissions
- Even if exploited, can't escalate privileges

**SystemCallFilter:**
- Whitelist approach to system calls
- Only allows safe system calls for services
- Blocks dangerous syscalls (ptrace, execve, etc.)

**InaccessiblePaths:**
- Hides encryption keys from service
- Keys only accessible to decrypt script
- Service never sees age private key

### Testing Hardening
```bash
# Verify service can't write to /usr
systemctl start eracun-test
systemd-analyze security eracun-test  # Should score 8.0+/10
```

---

## 4. Authentication & Authorization

### Inter-Service Authentication
- **mTLS:** Mutual TLS for service-to-service
- **Certificates:** Managed by cert-lifecycle-manager
- **Rotation:** Automated 90-day certificate rotation
- **Revocation:** CRL + OCSP stapling

### API Authentication
- **JWT tokens:** For external APIs
- **Expiry:** 1 hour for access tokens, 30 days for refresh
- **Signing:** RS256 algorithm (asymmetric)
- **Validation:** On every request, no exceptions

### RBAC (Role-Based Access Control)
```typescript
enum UserRole {
  ADMIN = 'admin',
  OPERATOR = 'operator',
  VIEWER = 'viewer'
}

// Middleware enforces permissions
requireRole(UserRole.ADMIN)
```

---

## 5. Network Security

### Firewall Rules
```bash
# Only allow necessary ports
ufw default deny incoming
ufw allow 443/tcp    # HTTPS
ufw allow 9090/tcp   # Prometheus (internal only)
ufw allow 15672/tcp  # RabbitMQ management (internal only)
ufw enable
```

### Service Isolation
- Services listen on localhost only
- Reverse proxy (nginx) handles external traffic
- Internal services not exposed to internet

### Rate Limiting
- API Gateway: 100 req/min per client
- Invoice upload: 10 req/min per client
- Prevents DDoS and abuse

---

## 6. Vulnerability Management

### Dependency Scanning
- **Snyk:** Scans npm dependencies daily
- **Trivy:** Scans Docker images
- **CI/CD:** Fails build on high/critical vulnerabilities
- **Automated:** Dependabot creates PRs for updates

### Security Audits
- **Frequency:** Quarterly external audits
- **Scope:** Penetration testing + code review
- **Compliance:** ISO 27001, GDPR requirements
- **Remediation:** 30 days for high severity, 90 for medium

### Incident Response
1. **Detection:** Monitoring alerts security team
2. **Containment:** Isolate affected services
3. **Investigation:** Root cause analysis
4. **Remediation:** Deploy fixes
5. **Post-Mortem:** Document lessons learned

---

## 7. Compliance Requirements

### GDPR
- Data minimization (collect only necessary data)
- Encryption at rest and in transit
- Right to deletion (automated process)
- Breach notification (within 72 hours)

### Croatian Data Protection
- Data stored in EU region
- Cross-border transfer restrictions
- User consent for data processing
- Privacy policy published

### PCI DSS (if handling payments)
- No credit card data stored
- Payment gateway integration only
- PCI DSS Level 1 compliance

---

## 8. Security Checklist (Pre-Deploy)

- [ ] Secrets encrypted with SOPS
- [ ] No hardcoded credentials in code
- [ ] systemd hardening directives applied
- [ ] XML parsing configured securely
- [ ] Dependencies scanned for vulnerabilities
- [ ] Rate limiting configured
- [ ] mTLS certificates deployed
- [ ] Firewall rules configured
- [ ] Monitoring alerts configured
- [ ] Incident response plan documented

---

## Related Documentation

- **Development Standards:** @docs/DEVELOPMENT_STANDARDS.md
- **Compliance Requirements:** @docs/COMPLIANCE_REQUIREMENTS.md
- **Deployment Guide:** @docs/DEPLOYMENT_GUIDE.md (systemd configuration)
- **Certificate Management:** @docs/guides/certificate-setup.md
- **Incident Response:** @docs/operations/incident-response.md

---

**Last Updated:** 2025-11-12
**Document Owner:** Security Team
**Review Cadence:** Monthly
**Security Contact:** security@eracun.hr
