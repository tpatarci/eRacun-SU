# TASK 3: Security Hardening Verification

## Task Priority
**CRITICAL** - Financial data protection and regulatory compliance

## Objective
Verify that all security hardening measures are properly implemented across the system, protecting against data breaches, XML attacks, and unauthorized access that could result in legal penalties and business damage.

## Scope
Complete security audit covering:
- systemd service hardening
- XML security (XXE, billion laughs)
- Secrets management (SOPS + age)
- Network security and firewall rules
- Authentication and authorization
- Zero Trust implementation

## Detailed Approach

### 1. systemd Service Hardening Audit (Day 1)
**Verify each service has proper security directives:**
```bash
# Analyze security score for all services
for service in eracun-*; do
  echo "=== Security Analysis: ${service} ==="
  systemd-analyze security "${service}"
done

# Target score: 8.0+ out of 10
```

**Required hardening directives checklist:**
- [ ] `ProtectSystem=strict` - Filesystem read-only
- [ ] `ProtectHome=true` - No home directory access
- [ ] `PrivateTmp=true` - Isolated temp directory
- [ ] `NoNewPrivileges=true` - Privilege escalation blocked
- [ ] `CapabilityBoundingSet=` - ALL capabilities dropped
- [ ] `SystemCallFilter=@system-service` - Syscall whitelist
- [ ] `User=eracun` - Non-root user
- [ ] `Group=eracun` - Dedicated group
- [ ] `ReadWritePaths=` - Explicit write permissions
- [ ] `InaccessiblePaths=/etc/eracun/.age-key` - Key protection

### 2. XML Security Testing (Day 1-2)
**Test XXE attack prevention:**
```javascript
// Test malicious XML with external entity
const maliciousXML = `<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<invoice>&xxe;</invoice>`;

// Should be rejected before parsing
```

**Security validation checklist:**
- [ ] External entities disabled in all parsers
- [ ] DTD processing disabled
- [ ] Entity expansion limits configured
- [ ] Maximum document size enforced (10MB)
- [ ] Parsing timeout configured
- [ ] Schema validation before parsing
- [ ] Error messages sanitized

### 3. Secrets Management Verification (Day 2)
**SOPS + age implementation audit:**
```bash
# Check encrypted secrets
ls -la /etc/eracun/secrets/*.yaml
# All should be encrypted (sops format)

# Verify decryption service
systemctl status sops-decrypt.service

# Check runtime secrets (should be tmpfs)
mount | grep /run/eracun
```

**File permission verification:**
- [ ] Secret files: 600 (`-rw-------`)
- [ ] Secret directories: 700 (`drwx------`)
- [ ] Age keys: 400 (`-r--------`)
- [ ] No `.env` files in repository
- [ ] No `.p12`, `.key`, `.pem` files committed

### 4. Network Security Audit (Day 2-3)
**Firewall rules verification:**
```bash
# Check UFW rules
sudo ufw status verbose

# Verify only required ports open
netstat -tulpn | grep LISTEN
```

**Required configuration:**
- [ ] Default deny incoming traffic
- [ ] Only ports 443 (HTTPS) exposed externally
- [ ] Internal services on localhost only
- [ ] Management ports (RabbitMQ, Prometheus) internal only
- [ ] No unnecessary services running

### 5. Authentication/Authorization Testing (Day 3)
**mTLS verification for inter-service:**
```bash
# Test service-to-service without cert (should fail)
curl https://internal-service:8080/health

# Test with valid cert (should succeed)
curl --cert service.crt --key service.key \
  https://internal-service:8080/health
```

**JWT validation for APIs:**
- [ ] Token expiry enforced (1 hour)
- [ ] Signature verification on every request
- [ ] RS256 algorithm (no HS256)
- [ ] Refresh token rotation
- [ ] RBAC permissions enforced

### 6. Zero Trust Validation (Day 3-4)
**Input validation at boundaries:**
- [ ] All service inputs validated
- [ ] No trust between services
- [ ] Request signing/verification
- [ ] Rate limiting active
- [ ] Circuit breakers configured

## Required Tools
- systemd-analyze for security scoring
- XML security testing tools
- SOPS CLI for secrets verification
- Network scanning tools (nmap, netstat)
- Certificate verification tools
- Penetration testing framework

## Pass/Fail Criteria

### MUST PASS (Security requirements)
- ✅ All services score 8.0+ on systemd-analyze
- ✅ XXE attacks blocked at all entry points
- ✅ No plaintext secrets in repository
- ✅ mTLS enforced for internal communication
- ✅ All inputs validated and sanitized

### RED FLAGS (Security vulnerabilities)
- ❌ Services running as root
- ❌ Capabilities not dropped
- ❌ External entities enabled in XML
- ❌ Secrets stored unencrypted
- ❌ Open ports without justification
- ❌ Missing authentication on endpoints

## Deliverables
1. **Security Scorecard** - systemd-analyze results for all services
2. **Vulnerability Report** - Any identified security issues
3. **Penetration Test Results** - Attack simulation outcomes
4. **Remediation Plan** - Timeline to fix vulnerabilities
5. **Compliance Matrix** - Security standards adherence

## Time Estimate
- **Duration:** 4 days
- **Effort:** 1 senior security engineer
- **Prerequisites:** Production-like environment

## Risk Factors
- **Critical Risk:** XML injection vulnerabilities
- **Critical Risk:** Exposed secrets or certificates
- **High Risk:** Insufficient service isolation
- **Medium Risk:** Missing rate limiting
- **Low Risk:** Verbose error messages

## Escalation Path
For critical security vulnerabilities:
1. Immediate service isolation
2. Security team emergency response
3. Patch development and testing
4. Coordinated deployment with validation
5. Post-mortem and process improvement

## Security Breach Impact
- **Data Breach:** GDPR fines up to 4% annual revenue
- **Financial Loss:** Invoice manipulation, VAT fraud
- **Legal Liability:** Criminal prosecution possible
- **Reputation:** Loss of customer trust
- **Operational:** System shutdown by authorities

## Related Documentation
- @docs/SECURITY.md
- @docs/adr/ADR-002-secrets-management.md
- deployment/systemd/*.service files
- OWASP XML Security Cheat Sheet
- CIS Benchmarks for Linux

## Security Checklist
- [ ] Dependency vulnerability scan (Snyk/Trivy)
- [ ] Container image scanning
- [ ] OWASP Top 10 coverage
- [ ] SQL injection prevention verified
- [ ] CSRF tokens implemented
- [ ] XSS protection headers set
- [ ] Content Security Policy configured
- [ ] HSTS enabled
- [ ] Certificate pinning for critical APIs
- [ ] Security headers audit (securityheaders.com)

## Notes
Security hardening is non-negotiable for a system handling legally binding financial documents. Any security vulnerability could lead to invoice fraud, VAT evasion, or data breaches with severe legal and financial consequences.