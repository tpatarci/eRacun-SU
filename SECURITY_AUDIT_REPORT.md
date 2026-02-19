# Security Audit Report
**Generated:** 2025-01-19
**Project:** eRačun MVP
**Audit Tool:** npm audit

## Executive Summary

The security audit identified **34 vulnerabilities** across the project dependencies:
- **Critical:** 0
- **High:** 32
- **Moderate:** 1
- **Low:** 1

**Total Dependencies Analyzed:** 659
- Production: 218
- Development: 428
- Optional: 38
- Peer: 11

## Critical Vulnerabilities

### 1. fast-xml-parser - HIGH SEVERITY ⚠️

**Package:** `fast-xml-parser` (Direct Dependency)
**Version Range:** 4.1.3 - 5.3.5
**Current Version:** ^4.5.0
**Severity:** High (CVSS: 7.5)
**CWE:** CWE-776 (Improper Restriction of Recursive Entity References in DTDs)

**Description:**
The package is affected by a Denial of Service (DoS) vulnerability through entity expansion in DOCTYPE without expansion limits. An attacker can craft malicious XML with nested entity expansions that consume excessive memory and CPU.

**Advisory:** https://github.com/advisories/GHSA-jmr7-xgp7-cmfj

**Impact:**
- This is a **production dependency** used for XML parsing
- XML parsing is a core feature for e-invoice processing
- Attackers could send malicious XML invoices to cause DoS

**Fix Available:** Yes - Upgrade to version 5.3.6 or later (breaking change)

**Recommendation:** **URGENT** - This is a critical security issue for an e-invoice system. The fast-xml-parser library is used for parsing XML invoices, making this vulnerability directly exploitable.

---

## High Severity Vulnerabilities

### 2. minimatch - ReDoS Vulnerability

**Package:** `minimatch` (Indirect Dependency)
**Version Range:** < 10.2.1
**Severity:** High
**CWE:** CWE-1333 (Inefficient Regular Expression Complexity)

**Description:**
minimatch has a ReDoS (Regular Expression Denial of Service) vulnerability via repeated wildcards with non-matching literal in pattern.

**Advisory:** https://github.com/advisories/GHSA-3ppc-4f35-3m26

**Affected Packages (via dependency chain):**
- @eslint/eslintrc
- @humanwhocodes/config-array
- @typescript-eslint/typescript-estree
- eslint
- glob
- test-exclude

**Fix Available:** Yes - Upgrade eslint to 10.0.0 (major version bump)

---

### 3. ESLint and TypeScript-ESLint Dependencies

**Packages Affected:**
- `eslint` (Direct - DevDependency)
- `@typescript-eslint/eslint-plugin` (Direct - DevDependency)
- `@typescript-eslint/parser` (Direct - DevDependency)

**Severity:** High

**Issues:**
- Multiple dependencies on vulnerable versions of minimatch
- ReDoS vulnerabilities in dependency chain

**Fix Available:**
- eslint: Upgrade to 10.0.0 (major version bump)
- @typescript-eslint/eslint-plugin: Upgrade to 8.56.0
- @typescript-eslint/parser: Upgrade to 8.56.0

**Risk Assessment:** Lower priority - These are development dependencies not used in production runtime.

---

### 4. Jest Testing Framework

**Package:** `jest` (Direct - DevDependency)
**Severity:** High

**Affected Packages (via dependency chain):**
- @jest/core
- @jest/expect
- @jest/globals
- @jest/reporters
- @jest/transform
- jest-circus
- jest-cli
- jest-config
- jest-resolve-dependencies
- jest-runner
- jest-runtime
- jest-snapshot
- babel-jest
- babel-plugin-istanbul
- ts-jest

**Root Causes:**
- Glob vulnerability (via minimatch)
- test-exclude vulnerability (via glob and minimatch)

**Fix Available:**
- jest: Upgrade to 25.0.0 (major version bump)
- ts-jest: Upgrade to 29.1.2 (major version bump)

**Risk Assessment:** Lower priority - These are development dependencies not used in production runtime.

---

### 5. ajv - ReDoS Vulnerability

**Package:** `ajv` (Indirect Dependency)
**Version Range:** < 8.18.0
**Severity:** Moderate
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

**Description:**
ajv has a ReDoS when using the `$data` option.

**Advisory:** https://github.com/advisories/GHSA-2g4f-4pwh-qvx6

**Affected Packages:**
- @eslint/eslintrc
- eslint

**Fix Available:** Yes - Upgrade eslint to 10.0.0

---

### 6. qs - ArrayLimit Bypass

**Package:** `qs` (Indirect Dependency)
**Version Range:** 6.7.0 - 6.14.1
**Severity:** Low
**CWE:** CWE-20 (Improper Input Validation)

**Description:**
qs's arrayLimit bypass in comma parsing allows denial of service.

**Advisory:** https://github.com/advisories/GHSA-w7fw-mjwx-w883

**CVSS Score:** 3.7

**Fix Available:** Yes - Patch available

---

## Vulnerability Breakdown by Category

### Production Dependencies (HIGH RISK)
1. **fast-xml-parser** - DoS via entity expansion (CRITICAL for e-invoice system)

### Development Dependencies (LOWER RISK)
2. **eslint** - Chain of vulnerabilities via minimatch
3. **@typescript-eslint/eslint-plugin** - Via eslint dependency
4. **@typescript-eslint/parser** - Via eslint dependency
5. **jest** - Chain of vulnerabilities via glob/minimatch
6. **ts-jest** - Via jest dependency

---

## Recommended Actions

### Priority 1 - URGENT (Production Security)

1. **Upgrade fast-xml-parser to 5.3.6+**
   ```bash
   npm install fast-xml-parser@^5.3.6
   ```
   - This is a breaking change
   - Requires testing XML parsing functionality
   - Critical for e-invoice security

### Priority 2 - HIGH (Development Security)

2. **Upgrade ESLint to v10**
   ```bash
   npm install eslint@^10.0.0 --save-dev
   ```
   - Major version bump
   - May require ESLint configuration updates
   - Fixes minimatch and ajv vulnerabilities

3. **Upgrade TypeScript-ESLint packages**
   ```bash
   npm install @typescript-eslint/eslint-plugin@^8.56.0 --save-dev
   npm install @typescript-eslint/parser@^8.56.0 --save-dev
   ```

### Priority 3 - MEDIUM (Testing Framework)

4. **Upgrade Jest to v25**
   ```bash
   npm install jest@^25.0.0 --save-dev
   ```
   - Major version bump
   - May require test updates
   - ts-jest will also need upgrade to 29.1.2

### Priority 4 - LOW

5. **Update qs** (indirect dependency)
   - Will be resolved by updating dependent packages

---

## Testing Requirements

Before deploying any updates:

1. **fast-xml-parser upgrade:**
   - Test all XML parsing functionality
   - Verify e-invoice XML processing
   - Check for breaking API changes

2. **ESLint upgrade:**
   - Run linting on all source files
   - Update ESLint configuration if needed
   - Verify CI/CD pipeline compatibility

3. **Jest upgrade:**
   - Run full test suite
   - Update test configurations if needed
   - Verify code coverage metrics

---

## Automated Fix Command

To automatically fix vulnerabilities where possible:

```bash
# Safe automatic fixes (no breaking changes)
npm audit fix

# Force fixes (includes breaking changes - requires testing)
npm audit fix --force
```

**WARNING:** The `--force` flag will install major version bumps that may break functionality.

---

## Security Best Practices

1. **Regular Audits:** Run `npm audit` weekly and before every release
2. **Automated Scanning:** Integrate security scanning into CI/CD pipeline
3. **Dependency Pinning:** Consider using package-lock.json strictly
4. **Monitor Advisories:** Subscribe to npm security advisories
5. **XML Processing:** Implement XML parsing limits and validation regardless of library version

---

## Conclusion

The most critical finding is the **fast-xml-parser vulnerability (GHSA-jmr7-xgp7-cmfj)** because:
- It's a production dependency
- XML parsing is core to e-invoice functionality
- It's directly exploitable via malicious invoice submissions
- Has a high CVSS score of 7.5

**Immediate action required:** Upgrade fast-xml-parser before processing any untrusted XML documents.

The remaining vulnerabilities are primarily in development dependencies (ESLint, Jest) and pose less immediate risk to production systems but should still be addressed to maintain secure development practices.

---

**Report Generated by:** npm audit
**Next Review Date:** 2025-01-26 (1 week)
