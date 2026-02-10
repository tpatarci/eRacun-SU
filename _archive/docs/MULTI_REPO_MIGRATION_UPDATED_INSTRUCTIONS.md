# Multi-Repository Migration: Updated Team Instructions

**Date:** 2025-11-16
**Purpose:** Updated migration instructions accounting for mock repository strategy
**Status:** 🚀 Ready for Immediate Action

---

## Executive Summary

With the introduction of the **`eracun-mocks` repository**, we can now unblock several migration challenges and accelerate the multi-repo transition. This document provides updated instructions for all teams, clarifying what can proceed immediately and how the mock repository enables parallel progress.

**Key Updates:**
- Mock repository eliminates external service dependencies
- Shared package strategy clarified (copy-first, consolidate later)
- 3 blocked services now have clear paths forward
- Teams can work fully independently

---

## 🎯 Current Status

### Completed Extractions (11/16 services - 69%)
✅ **Phase 0:** health-monitor, notification-service (2/2 - 100%)
✅ **Phase 1:** audit-logger, dead-letter-handler, retry-scheduler, kpd-registry-sync (4/5 - 80%)
✅ **Phase 2:** archive-service (1/1 - 100%)
✅ **Phase 3:** file-classifier, attachment-handler, pdf-parser, ocr-processing-service (4/8 - 50%)

### Blocked Services (3 services)
⚠️ admin-portal-api (awaiting ADR-005)
⚠️ email-ingestion-worker (mid-refactoring)
⚠️ invoice-gateway-api (shared package dependencies)

### Remaining Services (2 services)
🔄 xml-parser (Phase 3)
🔄 data-extractor (Phase 3)

---

## 🚀 Immediate Actions by Team

### Team 1: Core Processing (Validation & Transformation)
**Your repositories:** `eracun-validation`, `eracun-transformation`

#### Immediate Actions:
1. **Continue extracting validation services** (no blockers)
   - xsd-validator
   - schematron-validator
   - ai-validation-service
   - business-rules-engine

2. **Start using mock repository for external validators**
   ```bash
   # Clone mock repository
   git clone git@github.com:eracun/eracun-mocks.git
   cd eracun-mocks/dzs-klasus-simulator
   npm run dev  # Provides KPD validation mock
   ```

3. **Extract transformation services** (no blockers)
   - ubl-transformer
   - data-enrichment-service
   - format-converter

#### No Longer Blocked By:
- External KLASUS registry (use mock)
- FINA validation endpoints (use mock)

---

### Team 2: Ingestion & Document Processing
**Your repository:** `eracun-ingestion`

#### Immediate Actions:
1. **Extract stable services NOW:**
   ```bash
   # These are ready for extraction
   - xml-parser (no blockers)
   - data-extractor (no blockers)
   ```

2. **Fix email-ingestion-worker in monorepo first:**
   - Complete IMPROVEMENT-005 (streaming attachments)
   - Fix mailparser Promise vs EventEmitter issue
   - Resolve TypeScript errors
   - THEN extract (estimated: 2-3 days)

3. **For invoice-gateway-api - Use "Copy Strategy":**
   ```bash
   # Step 1: Copy shared contracts locally
   mkdir -p invoice-gateway-api/src/contracts
   cp -r monorepo/shared/contracts/* invoice-gateway-api/src/contracts/

   # Step 2: Replace imports
   # FROM: import { InvoiceMessage } from '@eracun/contracts';
   # TO:   import { InvoiceMessage } from './contracts';

   # Step 3: Extract with local contracts
   # Later: Consolidate to shared contracts repo
   ```

4. **Use email mock for testing:**
   ```bash
   cd eracun-mocks/email-provider-simulator
   npm run dev  # Provides SMTP/IMAP mocks
   ```

#### Unblocking Strategy:
- **invoice-gateway-api:** Copy shared packages locally (technical debt acceptable)
- **email-ingestion-worker:** Complete refactoring first (2-3 days)

---

### Team 3: Integration & Infrastructure
**Your repositories:** `eracun-integration`, `eracun-infrastructure`, `eracun-archive`

#### Immediate Actions:
1. **admin-portal-api - Proceed with Option A (Standardize on axios):**
   ```typescript
   // Quick ADR-005 Decision (can formalize later)
   // Standardize on axios for all HTTP calls

   // Step 1: Replace node-fetch with axios
   import axios from 'axios';

   // Step 2: Create standard client
   const httpClient = axios.create({
     timeout: 5000,
     headers: { 'Content-Type': 'application/json' }
   });

   // Step 3: Extract to multi-repo
   ```

2. **Continue extracting integration services:**
   - fina-connector → Use FINA mock
   - porezna-connector → Use Porezna mock
   - bank-integration → Use Bank API mock

3. **Use mock repository extensively:**
   ```bash
   # All external integrations now mockable
   cd eracun-mocks
   docker-compose up  # Runs all mocks

   # Your services point to mocks via env vars
   FINA_USE_MOCK=true
   POREZNA_USE_MOCK=true
   ```

#### No Longer Blocked By:
- External service availability (all mocked)
- Certificate management complexity (mocks provide test certs)
- Rate limiting concerns (mocks have no limits)

---

## 📦 Shared Package Resolution Strategy

### Immediate Solution: "Copy-First, Consolidate Later"

1. **Copy shared packages into each service:**
   ```bash
   # For each service needing shared code
   mkdir -p service-name/src/shared
   cp -r monorepo/shared/contracts service-name/src/shared/
   cp -r monorepo/shared/types service-name/src/shared/
   ```

2. **Update imports:**
   ```typescript
   // Before (monorepo)
   import { InvoiceMessage } from '@eracun/contracts';

   // After (multi-repo with local copy)
   import { InvoiceMessage } from './shared/contracts';
   ```

3. **Track technical debt:**
   ```typescript
   // TODO: SHARED-PACKAGE-DEBT
   // This is a local copy of @eracun/contracts
   // Will be replaced with npm package when contracts repo is ready
   // Tracked in: TECHNICAL-DEBT.md
   ```

4. **Future consolidation (Phase 4):**
   - Create `eracun-contracts` repository
   - Publish as npm packages
   - Replace local copies with npm dependencies

### Why This Works:
- **Unblocks immediately:** No waiting for perfect solution
- **Maintains type safety:** Same TypeScript definitions
- **Easy to consolidate:** Simple find-replace later
- **Low risk:** Code duplication better than broken builds

---

## 🧪 Mock Repository Integration

### Setup for All Teams:

1. **Clone mock repository:**
   ```bash
   git clone git@github.com:eracun/eracun-mocks.git
   cd eracun-mocks
   npm install
   ```

2. **Start all mocks:**
   ```bash
   docker-compose up
   # Or individually:
   cd fina-simulator && npm run dev
   ```

3. **Configure your services:**
   ```bash
   # .env.development
   FINA_USE_MOCK=true
   FINA_MOCK_URL=http://localhost:8449

   POREZNA_USE_MOCK=true
   POREZNA_MOCK_URL=http://localhost:8450

   EMAIL_USE_MOCK=true
   EMAIL_MOCK_SMTP=localhost:1025
   ```

4. **Test with chaos engineering:**
   ```bash
   # Enable failure injection
   export CHAOS_MODE=moderate
   docker-compose up

   # Your services should handle failures gracefully
   ```

### Benefits:
- **No external dependencies:** Work offline, no VPN needed
- **Predictable testing:** Mocks behave consistently
- **Chaos testing:** Validate resilience patterns
- **Fast iteration:** No rate limits or quotas

---

## 📊 Revised Timeline

### Week 1-2 (NOW)
- **All Teams:** Set up mock repository
- **Team 1:** Extract all validation services (4 services)
- **Team 2:** Extract xml-parser, data-extractor (2 services)
- **Team 3:** Fix and extract admin-portal-api (1 service)

### Week 3-4
- **Team 1:** Extract transformation services (3 services)
- **Team 2:** Complete email-ingestion-worker refactoring
- **Team 3:** Extract all integration services using mocks (4 services)

### Week 5-6
- **Team 2:** Extract invoice-gateway-api with copied packages
- **Team 2:** Extract email-ingestion-worker (after refactoring)
- **All Teams:** Integration testing with mock repository

### Week 7-8
- **Platform Team:** Create eracun-contracts repository
- **All Teams:** Replace local copies with npm packages
- **All Teams:** Final migration validation

---

## ✅ Success Criteria

### Per Service:
- [ ] Extracted to multi-repo
- [ ] TypeScript strict mode (0 errors)
- [ ] Tests passing (>85% coverage acceptable)
- [ ] Using mock repository for external deps
- [ ] Team ownership documented

### Per Team:
- [ ] All services extracted
- [ ] CI/CD pipeline configured
- [ ] Deployment independence achieved
- [ ] On-call rotation established

### Overall:
- [ ] 16/16 services migrated
- [ ] Monorepo archived (read-only)
- [ ] All teams deploying independently
- [ ] Mock repository enabling fast development

---

## 🚨 Escalation Points

### When to Escalate:
1. **Shared package conflicts:** If copy strategy causes divergence
2. **Mock inadequacy:** If mock doesn't match production behavior
3. **Performance issues:** If multi-repo overhead too high
4. **Team boundaries:** If ownership unclear

### Escalation Path:
1. Team Lead
2. Platform Architecture Team
3. Architecture Review Board (ARB)
4. CTO (for strategic decisions)

---

## 📝 Action Items Summary

### Immediate (Today):
1. ✅ Each team clone `eracun-mocks` repository
2. ✅ Start extracting unblocked services
3. ✅ Apply "copy strategy" for shared packages
4. ✅ Configure services to use mocks

### This Week:
1. 🔄 Team 1: Extract 4 validation services
2. 🔄 Team 2: Extract 2 parser services
3. 🔄 Team 3: Fix and extract admin-portal-api
4. 🔄 All: Run integration tests with mocks

### Next Week:
1. 📅 Review progress in team standup
2. 📅 Address any new blockers
3. 📅 Plan final extraction wave

---

## 🔗 Related Documents

- **Mock Repository Strategy:** @docs/EXTERNAL_SERVICE_MOCKING_STRATEGY.md
- **Mock Quick Start:** @docs/guides/MOCK_REPOSITORY_QUICKSTART.md
- **Migration Plan:** @docs/MULTI_REPO_MIGRATION_PLAN.md
- **Blocker Tracking:** `/tmp/eracun-infrastructure-pilot/BLOCKERS.md`
- **Completion Reports:** @guides/2025-11-16-multi-repo-phase2-phase3-extraction.md

---

**Document Version:** 2.0.0
**Created:** 2025-11-16
**Owner:** Platform Architecture Team
**Review:** Daily during migration sprint

## Appendix A: Quick Reference Commands

```bash
# Extract a service (generic template)
cd monorepo/services/SERVICE_NAME
mkdir -p ~/repos/eracun-DOMAIN/SERVICE_NAME
cp -r src package.json tsconfig.json ~/repos/eracun-DOMAIN/SERVICE_NAME/
cd ~/repos/eracun-DOMAIN/SERVICE_NAME

# Fix shared package imports
find . -type f -name "*.ts" -exec sed -i "s/@eracun\/contracts/\.\/shared\/contracts/g" {} \;
find . -type f -name "*.ts" -exec sed -i "s/@eracun\/types/\.\/shared\/types/g" {} \;

# Copy shared packages locally
mkdir -p src/shared
cp -r ../../../../monorepo/shared/contracts src/shared/
cp -r ../../../../monorepo/shared/types src/shared/

# Test the extraction
npm install
npm run build
npm test

# Start with mocks
export FINA_USE_MOCK=true
export CHAOS_MODE=light
npm run dev
```

## Appendix B: Blocker Resolution Checklist

### For admin-portal-api:
- [x] Decision: Standardize on axios
- [ ] Refactor HTTP calls to use axios
- [ ] Remove node-fetch dependency
- [ ] Test all endpoints
- [ ] Extract to multi-repo

### For email-ingestion-worker:
- [ ] Complete IMPROVEMENT-005
- [ ] Fix Promise/EventEmitter pattern
- [ ] Resolve TypeScript errors
- [ ] Run full test suite
- [ ] Extract to multi-repo

### For invoice-gateway-api:
- [ ] Copy @eracun/contracts locally
- [ ] Copy @eracun/di-container locally
- [ ] Update all imports
- [ ] Fix type errors
- [ ] Extract to multi-repo

---

**END OF INSTRUCTIONS**

*These instructions supersede all previous migration guidance. Teams should begin immediately with the actions outlined above.*