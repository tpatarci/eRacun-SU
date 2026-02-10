# Security Audit Checklist

**eRačun Platform - Team 3: External Integration & Compliance**

## Overview

This checklist provides a comprehensive security audit framework for the eRačun electronic invoice processing platform. Use this checklist before production deployment and quarterly thereafter.

**Audit Frequency:** Quarterly + Pre-Production
**Last Updated:** 2025-11-14
**Compliance Standards:** ISO 27001, GDPR, Croatian Data Protection Law

---

## 1. Authentication & Authorization

### 1.1 API Authentication

- [ ] **JWT tokens** are used for external API authentication
- [ ] **Token expiry** is configured (1 hour for access tokens, 30 days for refresh)
- [ ] **Token signing** uses RS256 (asymmetric encryption)
- [ ] **Token validation** occurs on every request without exceptions
- [ ] **Token revocation** mechanism is implemented
- [ ] **Refresh token rotation** is enabled
- [ ] **Failed authentication attempts** are logged and monitored
- [ ] **Rate limiting** is applied to authentication endpoints (max 5 attempts per minute)

### 1.2 Inter-Service Authentication

- [ ] **mTLS** (mutual TLS) is configured for all service-to-service communication
- [ ] **Certificate rotation** is automated (90-day lifecycle)
- [ ] **Certificate revocation** lists (CRL) are checked
- [ ] **OCSP stapling** is enabled for certificate validation
- [ ] **Service accounts** have minimum required permissions
- [ ] **Service identity** is verified on every internal API call

### 1.3 Role-Based Access Control (RBAC)

- [ ] **User roles** are defined (ADMIN, OPERATOR, VIEWER)
- [ ] **Permission boundaries** are enforced at application level
- [ ] **Principle of least privilege** is applied to all roles
- [ ] **Role changes** are logged in audit trail
- [ ] **Default role** is lowest privilege level
- [ ] **Admin actions** require additional verification (2FA recommended)

---

## 2. Secrets Management

### 2.1 SOPS + age Encryption

- [ ] **All secrets** are encrypted with SOPS + age
- [ ] **Age private key** is stored securely (`/etc/eracun/.age-key` with 400 permissions)
- [ ] **Encrypted files** (`.enc.env`, `.enc.yaml`) are committed to git
- [ ] **Decrypted files** are NEVER committed to git (enforced by `.gitignore` and pre-commit hooks)
- [ ] **Key rotation** procedure is documented and tested
- [ ] **Backup keys** are stored in secure offline location
- [ ] **Team members** have individual age public keys for collaboration

### 2.2 Environment Variables

- [ ] **No hardcoded credentials** in source code
- [ ] **Sensitive environment variables** are encrypted at rest
- [ ] **Environment files** (`.env`) are in `.gitignore`
- [ ] **Production secrets** are different from development secrets
- [ ] **Secret rotation** is performed quarterly
- [ ] **Secrets access** is logged and monitored

### 2.3 Certificate Management

- [ ] **FINA certificates** (`.p12` files) are encrypted with SOPS
- [ ] **Certificate passwords** are stored in encrypted vault
- [ ] **Certificates** are NEVER committed to git unencrypted
- [ ] **Certificate expiry** is monitored (alerts 30 days before expiry)
- [ ] **Backup certificates** exist for disaster recovery
- [ ] **HSM integration** is prepared for production (mock HSM validated)

---

## 3. Network Security

### 3.1 Firewall Configuration

- [ ] **Default deny** policy for incoming traffic
- [ ] **Only necessary ports** are open (443 HTTPS, 5672 RabbitMQ internal, 5432 PostgreSQL internal)
- [ ] **Management interfaces** (RabbitMQ 15672, Prometheus 9090) are internal-only
- [ ] **SSH access** is restricted to known IP addresses
- [ ] **Firewall rules** are documented and version-controlled
- [ ] **Egress filtering** is configured (whitelist FINA, Porezna endpoints only)

### 3.2 Service Isolation

- [ ] **Services listen** on localhost only (reverse proxy handles external traffic)
- [ ] **Internal services** are not exposed to internet
- [ ] **Network segmentation** separates production from development
- [ ] **Container networking** uses isolated networks
- [ ] **Database access** is restricted to application services only

### 3.3 TLS/SSL Configuration

- [ ] **TLS 1.3** is enforced (TLS 1.2 minimum)
- [ ] **Strong cipher suites** are configured (no weak ciphers)
- [ ] **Perfect forward secrecy** is enabled
- [ ] **HSTS headers** are set (Strict-Transport-Security: max-age=31536000)
- [ ] **Certificate pinning** is implemented for critical connections
- [ ] **SSL Labs grade** is A or A+ (test: https://www.ssllabs.com/ssltest/)

---

## 4. systemd Hardening

### 4.1 Filesystem Protection

- [ ] **ProtectSystem=strict** - Entire filesystem read-only except explicit paths
- [ ] **ProtectHome=true** - No access to /home or /root
- [ ] **ReadWritePaths** are explicitly whitelisted (e.g., `/var/lib/eracun/`)
- [ ] **PrivateTmp=true** - Isolated /tmp directory per service
- [ ] **InaccessiblePaths** hides sensitive files (e.g., `/etc/eracun/.age-key`)

### 4.2 Privilege Restrictions

- [ ] **NoNewPrivileges=true** - Cannot gain new privileges
- [ ] **CapabilityBoundingSet=** - All Linux capabilities dropped
- [ ] **User=eracun** - Service runs as dedicated non-root user
- [ ] **Group=eracun** - Service runs in dedicated group
- [ ] **UMask=0077** - Files created with restrictive permissions

### 4.3 System Call Filtering

- [ ] **SystemCallFilter=@system-service** - Only safe system calls allowed
- [ ] **SystemCallFilter=~@privileged** - Dangerous syscalls blocked
- [ ] **SystemCallErrorNumber=EPERM** - Blocked syscalls return permission denied
- [ ] **RestrictAddressFamilies=AF_INET AF_INET6** - Only IPv4/IPv6 allowed

### 4.4 Network Restrictions

- [ ] **IPAddressDeny=any** - Default deny all IP addresses
- [ ] **IPAddressAllow** explicitly whitelists required endpoints
- [ ] **RestrictRealtime=true** - No realtime scheduling
- [ ] **ProtectKernelTunables=true** - Cannot modify kernel parameters
- [ ] **ProtectKernelModules=true** - Cannot load kernel modules
- [ ] **LockPersonality=true** - Cannot change execution domain

### 4.5 Resource Limits

- [ ] **MemoryMax=1G** - Maximum memory limit set
- [ ] **CPUQuota=200%** - Maximum CPU usage limited
- [ ] **TasksMax=512** - Maximum number of tasks limited
- [ ] **LimitNOFILE=8192** - File descriptor limit set

### 4.6 Security Score

- [ ] **systemd-analyze security** score is 8.0+/10 for all services
- [ ] All security warnings are investigated and documented
- [ ] Security improvements are tracked and implemented

---

## 5. XML Security (Critical for e-Invoice Processing)

### 5.1 XXE Attack Prevention

- [ ] **External entities disabled** - `resolveExternalEntities: false`
- [ ] **External DTDs disabled** - `resolveExternalDTDs: false`
- [ ] **Entity resolution forbidden** - `forbidExternalEntityResolution: true`
- [ ] **All XML parsers** enforce these settings
- [ ] **No exceptions** for "trusted" XML sources

### 5.2 Input Validation

- [ ] **Schema validation** (XSD) occurs BEFORE parsing
- [ ] **Invalid XML** is rejected immediately (no partial processing)
- [ ] **Size limits** enforced (max 10MB per document)
- [ ] **Timeout limits** configured (max 30 seconds per parse)
- [ ] **Entity nesting depth** limited (max 5 levels)

### 5.3 Billion Laughs Attack Protection

- [ ] **Entity expansion** detection implemented
- [ ] **Recursive entities** are blocked
- [ ] **Memory limits** enforced during parsing
- [ ] **Parser timeout** prevents infinite loops

---

## 6. Input Validation & Sanitization

### 6.1 API Input Validation

- [ ] **All inputs** validated against schemas (JSON Schema, XSD)
- [ ] **Type checking** enforced (no implicit type coercion)
- [ ] **Range validation** for numeric inputs
- [ ] **Length limits** enforced for string inputs
- [ ] **Whitelist validation** for enums and constants
- [ ] **No unsafe characters** accepted (SQL injection, XSS prevention)

### 6.2 OIB Validation

- [ ] **OIB format** validated (11 digits)
- [ ] **OIB checksum** calculated and verified
- [ ] **Invalid OIBs** rejected with clear error messages
- [ ] **Test OIBs** (12345678901, etc.) only accepted in development

### 6.3 File Upload Security

- [ ] **File type** validated (only XML, PDF allowed)
- [ ] **MIME type** checked (not just file extension)
- [ ] **File size** limited (max 10MB per upload)
- [ ] **Virus scanning** performed on all uploads (ClamAV recommended)
- [ ] **Uploaded files** stored outside web root
- [ ] **File permissions** restrictive (600 for sensitive documents)

---

## 7. Data Protection & Privacy (GDPR Compliance)

### 7.1 Data Minimization

- [ ] **Only necessary data** is collected
- [ ] **Personal data** fields are justified
- [ ] **Data retention** policy is enforced (11 years for invoices, 1 year for logs)
- [ ] **Unused data** is automatically purged

### 7.2 Encryption

- [ ] **Data at rest** encrypted (AES-256 minimum)
- [ ] **Data in transit** encrypted (TLS 1.3)
- [ ] **Database encryption** enabled (PostgreSQL TDE or LUKS)
- [ ] **Backup encryption** enabled
- [ ] **Encryption keys** rotated annually

### 7.3 Data Access Controls

- [ ] **Audit trail** logs all data access
- [ ] **Data export** requires explicit permission
- [ ] **Right to deletion** (GDPR) implemented
- [ ] **Data anonymization** available for analytics
- [ ] **Cross-border transfer** restrictions enforced (EU-only storage)

### 7.4 Privacy Policy

- [ ] **Privacy policy** published and accessible
- [ ] **User consent** obtained for data processing
- [ ] **Cookie consent** implemented (if applicable)
- [ ] **Data breach notification** procedures documented (72-hour GDPR requirement)

---

## 8. Logging & Monitoring

### 8.1 Security Logging

- [ ] **Authentication attempts** logged (success and failure)
- [ ] **Authorization failures** logged with context
- [ ] **Administrative actions** logged
- [ ] **Configuration changes** logged
- [ ] **Certificate operations** logged (generation, renewal, revocation)
- [ ] **Sensitive data** excluded from logs (passwords, tokens, credit cards)

### 8.2 Log Protection

- [ ] **Logs are immutable** (append-only storage)
- [ ] **Log integrity** verified (cryptographic signatures)
- [ ] **Log retention** policy enforced (minimum 1 year)
- [ ] **Log access** restricted (audit team only)
- [ ] **Log forwarding** to SIEM system (future consideration)

### 8.3 Intrusion Detection

- [ ] **Failed login** monitoring (alert on 5+ failures)
- [ ] **Anomaly detection** for API usage patterns
- [ ] **File integrity monitoring** (AIDE or similar)
- [ ] **Network intrusion detection** (Suricata or Snort)
- [ ] **Security alerts** routed to on-call team

---

## 9. Dependency Security

### 9.1 Dependency Scanning

- [ ] **Snyk** scans npm dependencies daily
- [ ] **Trivy** scans Docker images
- [ ] **CI/CD fails** on high/critical vulnerabilities
- [ ] **Dependabot** creates automated PRs for updates
- [ ] **Dependency review** occurs before merging updates

### 9.2 Supply Chain Security

- [ ] **Package lock files** committed (package-lock.json)
- [ ] **npm audit** runs on every build
- [ ] **Subresource integrity** (SRI) for CDN resources
- [ ] **Verified publishers** preferred for critical dependencies
- [ ] **Private registry** considered for sensitive packages

---

## 10. Incident Response

### 10.1 Incident Detection

- [ ] **Security monitoring** covers all critical services
- [ ] **Alert thresholds** configured and tuned
- [ ] **On-call rotation** schedule defined
- [ ] **Escalation procedures** documented

### 10.2 Incident Response Plan

- [ ] **Detection** procedures documented
- [ ] **Containment** procedures documented (isolate affected services)
- [ ] **Investigation** procedures documented (root cause analysis)
- [ ] **Remediation** procedures documented (deploy fixes)
- [ ] **Post-mortem** template exists
- [ ] **Communication plan** defined (stakeholder notifications)

### 10.3 Disaster Recovery

- [ ] **Backup restoration** tested quarterly
- [ ] **RTO (Recovery Time Objective)** is 1 hour
- [ ] **RPO (Recovery Point Objective)** is 5 minutes
- [ ] **Failover procedures** documented
- [ ] **Disaster recovery drills** conducted annually

---

## 11. Compliance & Regulatory

### 11.1 Croatian Fiskalizacija 2.0

- [ ] **Digital signatures** use FINA X.509 certificates
- [ ] **Qualified timestamps** obtained from eIDAS-compliant TSA
- [ ] **11-year retention** enforced for all invoices
- [ ] **WORM storage** implemented (Write Once Read Many)
- [ ] **Signature validation** performed monthly
- [ ] **Audit trail** preserved for 11 years

### 11.2 Certificate Compliance

- [ ] **FINA certificates** acquired and valid
- [ ] **Certificate renewal** automated (30 days before expiry)
- [ ] **Certificate backup** stored securely
- [ ] **Certificate revocation** monitoring active
- [ ] **Test certificates** used in non-production environments only

### 11.3 Data Retention

- [ ] **Invoices** retained for 11 years (NOT 7 years)
- [ ] **Submission confirmations** (JIR, UUID) retained
- [ ] **Digital signatures** preserved and valid
- [ ] **Qualified timestamps** preserved
- [ ] **Archive integrity** verified monthly

---

## 12. Code Security

### 12.1 Secure Coding Practices

- [ ] **No SQL injection** vulnerabilities (parameterized queries only)
- [ ] **No XSS vulnerabilities** (input sanitization, output encoding)
- [ ] **No command injection** (avoid shell execution, use libraries)
- [ ] **No path traversal** (validate file paths, use path.join)
- [ ] **No SSRF** (server-side request forgery) vulnerabilities
- [ ] **Error messages** don't leak sensitive information

### 12.2 Code Review

- [ ] **Security review** for all code changes
- [ ] **Pre-commit hooks** block secrets from being committed
- [ ] **Static analysis** (ESLint security plugin) runs on every build
- [ ] **SAST** (Static Application Security Testing) integrated in CI/CD

### 12.3 Third-Party Code

- [ ] **Open-source licenses** are reviewed and approved
- [ ] **Unmaintained dependencies** are replaced
- [ ] **Vendored code** is audited
- [ ] **Code provenance** is verified (checksums, signatures)

---

## 13. Pre-Production Checklist

### 13.1 Security Testing

- [ ] **Penetration testing** completed (external vendor)
- [ ] **Vulnerability scanning** completed (Nessus, OpenVAS)
- [ ] **OWASP Top 10** vulnerabilities tested
- [ ] **Security code review** completed
- [ ] **Threat modeling** completed

### 13.2 Configuration Review

- [ ] **All default credentials** changed
- [ ] **Debug mode** disabled in production
- [ ] **Verbose error messages** disabled
- [ ] **Administrative interfaces** disabled or secured
- [ ] **Sample data** removed

### 13.3 Team Readiness

- [ ] **Security training** completed for team
- [ ] **Incident response** drills conducted
- [ ] **On-call procedures** documented and tested
- [ ] **Escalation contacts** verified
- [ ] **Communication plan** tested

---

## Audit Summary

**Audit Date:** ________________
**Auditor Name:** ________________
**Auditor Signature:** ________________

**Total Items:** 200+
**Items Passed:** ______
**Items Failed:** ______
**Items N/A:** ______

**Overall Security Score:** ______/100

**Critical Issues Found:** ______
**High Issues Found:** ______
**Medium Issues Found:** ______
**Low Issues Found:** ______

**Remediation Deadline:** ________________

---

## Related Documentation

- **Security Standards:** @docs/SECURITY.md
- **Compliance Requirements:** @docs/COMPLIANCE_REQUIREMENTS.md
- **Deployment Guide:** @docs/DEPLOYMENT_GUIDE.md
- **systemd Hardening:** @deployment/systemd/README.md
- **SOPS Secrets:** @docs/SOPS_SECRETS_MANAGEMENT.md
- **Incident Response:** @docs/guides/disaster-recovery-procedures.md (to be created)

---

**Last Updated:** 2025-11-14
**Next Review:** 2026-02-14 (Quarterly)
**Document Owner:** Security Team
