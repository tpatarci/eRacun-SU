# Certificate Lifecycle Manager - Setup Report

**Date:** 2025-11-11
**Service:** `cert-lifecycle-manager`
**Status:** ⚠️ Foundational Setup Complete - Implementation Required

---

## Executive Summary

Established foundational setup for the **cert-lifecycle-manager** service. This service is critical for FINA certificate lifecycle management but requires significant implementation effort (estimated 4-5 days, ~2,200 LOC, HIGH complexity).

**Completed:** Configuration and project setup
**Remaining:** Full implementation of 8 core modules

---

## What Was Delivered

### Configuration Files (5 files)

1. **package.json** - Dependencies configured
   - node-forge (X.509 parsing)
   - pg, express, axios, node-cron, multer
   - prom-client, pino, opentelemetry
   - TypeScript 5.3+ with strict mode

2. **tsconfig.json** - TypeScript strict mode configuration

3. **jest.config.js** - Test configuration with 85%+ coverage threshold

4. **gitignore** - Prevents committing real certificates (*.p12, *.pfx, *.key)

5. **.env.example** - All 20 environment variables documented

---

## Architecture Established

**Core Modules Required (8 modules, ~2,200 LOC):**

1. **observability.ts** (~200 LOC)
   - TODO-008 compliance
   - 4+ Prometheus metrics (certificates_expiring_count, certificate_expiration_alerts_total, certificate_renewals_total, certificates_active)
   - Structured logging, distributed tracing

2. **cert-parser.ts** (~300 LOC)
   - X.509 .p12 certificate parsing with node-forge
   - Extract: subject DN, serial number, issuer, validity dates
   - Handle encrypted .p12 files (password protection)

3. **cert-validator.ts** (~200 LOC)
   - Validation rules:
     - Not yet valid (not_before > now)
     - Already expired (not_after < now)
     - Not issued by FINA (`issuer !== 'Fina RDC 2015 CA'`)
     - Invalid serial number format

4. **repository.ts** (~400 LOC)
   - PostgreSQL certificate inventory
   - Schema: certificates table with expiration tracking
   - CRUD operations + expiration queries

5. **expiration-monitor.ts** (~300 LOC)
   - Daily cron job (9 AM)
   - Multi-level alerts: 30/14/7/1 days before expiry
   - Status updates: active → expiring_soon → expired

6. **alerting.ts** (~200 LOC)
   - Integration with notification-service
   - Email templates for expiration alerts
   - Severity levels: INFO/WARNING/CRITICAL/URGENT

7. **api.ts** (~400 LOC)
   - HTTP REST API (port 8087)
   - 6 endpoints:
     - GET /api/v1/certificates
     - POST /api/v1/certificates/upload
     - GET /api/v1/certificates/:id
     - DELETE /api/v1/certificates/:id/revoke
     - POST /api/v1/certificates/:id/deploy
     - GET /api/v1/certificates/expiring

8. **index.ts** (~200 LOC)
   - Main entry point
   - HTTP API server
   - Cron job initialization
   - Health endpoints, metrics endpoint
   - Graceful shutdown

---

## Critical Requirements

**Security (NON-NEGOTIABLE):**
- ❌ NEVER log certificate passwords
- ❌ NEVER commit real .p12 files to git
- ✅ Encrypt all .p12 files with SOPS + age
- ✅ File permissions: 600 (owner-only read)
- ✅ Store passwords encrypted in PostgreSQL

**Croatian Compliance:**
- FINA certificates expire every 5 years (production)
- Demo certificates expire after 1 year
- Certificate expiration blocks ALL invoice submission
- Manual renewal process via FINA CMS (cms.fina.hr)
- Renewal takes 5-10 business days

---

## Implementation Roadmap

### Phase 1: Core Parsing (Day 1-2)
1. Implement observability.ts (TODO-008)
2. Implement cert-parser.ts (node-forge integration)
3. Implement cert-validator.ts (validation rules)
4. Implement repository.ts (PostgreSQL operations)
5. Unit tests for parsing and validation

### Phase 2: Monitoring & Alerting (Day 2-3)
1. Implement expiration-monitor.ts (cron job)
2. Implement alerting.ts (notification-service integration)
3. Integration tests for monitoring

### Phase 3: API & Deployment (Day 3-4)
1. Implement api.ts (HTTP REST API)
2. Implement index.ts (main entry point)
3. Integration tests for API

### Phase 4: Documentation & Testing (Day 4-5)
1. Dockerfile (multi-stage build)
2. systemd unit (security hardening)
3. RUNBOOK.md (10 operational scenarios including FINA renewal process)
4. Achieve 85%+ test coverage
5. Completion report

---

## Next Steps

**Immediate:**
1. Allocate dedicated 4-5 day implementation sprint
2. Obtain FINA demo certificate for testing
3. Set up PostgreSQL certificates table
4. Review FINA CMS renewal process documentation

**Before Production:**
1. Security audit (certificate handling, password encryption)
2. Load testing (certificate parsing performance)
3. Integration testing with notification-service
4. Staging deployment with demo certificates
5. Document manual renewal workflow in RUNBOOK

---

## Risk Assessment

**CRITICAL RISKS:**
- ⚠️ Certificate expiration blocks ALL invoice submission
- ⚠️ FINA renewal takes 5-10 business days (plan ahead!)
- ⚠️ Improper certificate handling creates security vulnerabilities
- ⚠️ Missing expiration alerts can cause business disruption

**MITIGATION:**
- Implement monitoring FIRST before other features
- Test alert system thoroughly (all 4 levels: 30/14/7/1 days)
- Document FINA renewal process in detail
- Set up redundant alerting (email + SMS + on-call page)

---

## Status

**Setup:** ✅ Complete (5 configuration files)
**Implementation:** ⚠️ Required (8 core modules, ~2,200 LOC)
**Testing:** ⚠️ Required (85%+ coverage)
**Documentation:** ⚠️ Required (RUNBOOK, completion report)

**Estimated Remaining Effort:** 4-5 days (HIGH complexity)

---

**Report Generated:** 2025-11-11
**Setup By:** Claude (AI Assistant)
**Version:** 1.0.0 - Setup Phase
