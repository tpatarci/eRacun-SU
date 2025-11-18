# Multi-Repository Migration - Sequential Task List

**Purpose:** Step-by-step migration tasks for single team execution
**Approach:** Sequential completion, check off as you go
**Timeline:** 4-6 weeks estimated
**Created:** 2025-11-16

---

## 📋 Prerequisites & Setup (Day 1)

### Mock Repository Setup
- [ ] Clone mock repository: `git clone git@github.com:eracun/eracun-mocks.git`
- [ ] Navigate to mock repo: `cd ~/PycharmProjects/eracun-mocks`
- [ ] Install dependencies: `npm install`
- [ ] Start all mock services: `docker-compose up -d`
- [ ] Verify FINA mock: `curl http://localhost:8449/FiskalizacijaService/status`
- [ ] Verify Porezna mock: `curl http://localhost:8450/api/status`
- [ ] Verify KLASUS mock: `curl http://localhost:8451/api/klasus/status`
- [ ] Document mock endpoints in team wiki

### Environment Preparation
- [ ] Create extraction script at `~/scripts/extract-service.sh`
- [ ] Create target directories: `mkdir -p ~/repos/{eracun-validation,eracun-ingestion,eracun-integration,eracun-infrastructure,eracun-transformation,eracun-archive}`
- [ ] Set up environment variables for mocks in `~/.bashrc`
- [ ] Create `TECHNICAL-DEBT.md` for tracking temporary solutions

---

## 🟢 Phase 1: Easy Extractions - No Dependencies (Day 1-2)

### Already Completed Services (Reference Only)
- [x] ~~health-monitor~~ (Phase 0)
- [x] ~~notification-service~~ (Phase 0)
- [x] ~~audit-logger~~ (Phase 1)
- [x] ~~dead-letter-handler~~ (Phase 1)
- [x] ~~retry-scheduler~~ (Phase 1)
- [x] ~~kpd-registry-sync~~ (Phase 1)
- [x] ~~archive-service~~ (Phase 2)
- [x] ~~file-classifier~~ (Phase 3)
- [x] ~~attachment-handler~~ (Phase 3)
- [x] ~~pdf-parser~~ (Phase 3)
- [x] ~~ocr-processing-service~~ (Phase 3)
- [x] ~~xml-parser~~ (Phase 3)

### Extract data-extractor (30 min)
- [ ] Navigate to service: `cd services/data-extractor`
- [ ] Check for recent changes: `git log -5 --oneline .`
- [ ] Extract to ingestion repo: `cp -r . ~/repos/eracun-ingestion/data-extractor`
- [ ] Install dependencies: `cd ~/repos/eracun-ingestion/data-extractor && npm install`
- [ ] Run tests: `npm test`
- [ ] Fix any test failures (document if >85% passing)
- [ ] Commit: `git add . && git commit -m "feat: extract data-extractor from monorepo"`
- [ ] Update extraction status in this file

### Extract sftp-ingestion-worker (30 min) - IF EXISTS
- [ ] Check if service exists: `ls services/ | grep sftp`
- [ ] If exists, navigate: `cd services/sftp-ingestion-worker`
- [ ] Check stability: `git log -5 --oneline .`
- [ ] If stable (no recent changes), extract: `cp -r . ~/repos/eracun-ingestion/sftp-ingestion-worker`
- [ ] Install and test: `cd ~/repos/eracun-ingestion/sftp-ingestion-worker && npm install && npm test`
- [ ] Commit if successful
- [ ] Skip if service doesn't exist or is unstable

---

## 🟡 Phase 2: Simple Validation Services (Day 2-3)

### Extract oib-validator (45 min)
- [ ] Navigate: `cd services/oib-validator`
- [ ] Extract: `cp -r . ~/repos/eracun-validation/oib-validator`
- [ ] Install: `cd ~/repos/eracun-validation/oib-validator && npm install`
- [ ] Run tests: `npm test`
- [ ] Ensure OIB validation logic works
- [ ] Commit: `git commit -m "feat: extract oib-validator"`

### Extract business-rules-engine (1 hour)
- [ ] Navigate: `cd services/business-rules-engine`
- [ ] Check for shared dependencies: `grep -r "@eracun/" . --include="*.ts"`
- [ ] Extract: `cp -r . ~/repos/eracun-validation/business-rules-engine`
- [ ] If has shared deps, apply copy strategy (see Phase 4)
- [ ] Install and test: `npm install && npm test`
- [ ] Document any business rule configurations needed
- [ ] Commit: `git commit -m "feat: extract business-rules-engine"`

### Extract xsd-validator (45 min)
- [ ] Navigate: `cd services/xsd-validator`
- [ ] Extract: `cp -r . ~/repos/eracun-validation/xsd-validator`
- [ ] Copy XSD schemas if referenced locally
- [ ] Install: `npm install`
- [ ] Test with sample XML: `npm test`
- [ ] Commit: `git commit -m "feat: extract xsd-validator"`

### Extract schematron-validator (45 min)
- [ ] Navigate: `cd services/schematron-validator`
- [ ] Extract: `cp -r . ~/repos/eracun-validation/schematron-validator`
- [ ] Copy Schematron rules if referenced
- [ ] Install and test: `npm install && npm test`
- [ ] Commit: `git commit -m "feat: extract schematron-validator"`

---

## 🔵 Phase 3: Services Requiring Mocks (Day 3-4)

### Extract kpd-validator (1 hour)
- [ ] Ensure KLASUS mock is running: `curl http://localhost:8451/api/klasus/status`
- [ ] Navigate: `cd services/kpd-validator`
- [ ] Extract: `cp -r . ~/repos/eracun-validation/kpd-validator`
- [ ] Configure mock: `echo "KLASUS_API_URL=http://localhost:8451" >> .env`
- [ ] Install: `npm install`
- [ ] Test with mock: `npm test`
- [ ] Verify KPD code validation works
- [ ] Commit: `git commit -m "feat: extract kpd-validator with mock support"`

### Extract ai-validation-service (1 hour)
- [ ] Navigate: `cd services/ai-validation-service`
- [ ] Check AI provider dependencies
- [ ] Extract: `cp -r . ~/repos/eracun-validation/ai-validation-service`
- [ ] Configure mock AI responses if needed
- [ ] Install: `npm install`
- [ ] Run tests with mocked AI: `npm test`
- [ ] Document AI provider requirements
- [ ] Commit: `git commit -m "feat: extract ai-validation-service"`

---

## 🟣 Phase 4: Transformation Services (Day 4-5)

### Extract ubl-transformer (1 hour)
- [ ] Navigate: `cd services/ubl-transformer`
- [ ] Check for shared deps: `grep -r "@eracun/" . --include="*.ts"`
- [ ] Extract: `cp -r . ~/repos/eracun-transformation/ubl-transformer`
- [ ] Apply copy strategy if needed (see instructions below)
- [ ] Install: `npm install`
- [ ] Test UBL generation: `npm test`
- [ ] Verify sample invoice transforms correctly
- [ ] Commit: `git commit -m "feat: extract ubl-transformer"`

### Extract data-enrichment-service (45 min)
- [ ] Navigate: `cd services/data-enrichment-service`
- [ ] Extract: `cp -r . ~/repos/eracun-transformation/data-enrichment-service`
- [ ] Check enrichment data sources
- [ ] Install and test: `npm install && npm test`
- [ ] Commit: `git commit -m "feat: extract data-enrichment-service"`

### Extract format-converter (45 min)
- [ ] Navigate: `cd services/format-converter`
- [ ] Extract: `cp -r . ~/repos/eracun-transformation/format-converter`
- [ ] Verify conversion mappings
- [ ] Install and test: `npm install && npm test`
- [ ] Commit: `git commit -m "feat: extract format-converter"`

---

## 🔴 Phase 5: Integration Services with Mocks (Day 5-6)

### Extract fina-connector (1.5 hours)
- [ ] Verify FINA mock running: `curl http://localhost:8449/FiskalizacijaService/status`
- [ ] Navigate: `cd services/fina-connector`
- [ ] Extract: `cp -r . ~/repos/eracun-integration/fina-connector`
- [ ] Configure for mock: `echo "FINA_USE_MOCK=true" >> .env`
- [ ] Add mock URL: `echo "FINA_MOCK_URL=http://localhost:8449" >> .env`
- [ ] Install: `npm install`
- [ ] Test fiscalization with mock: `npm test`
- [ ] Verify JIR generation works
- [ ] Document production FINA requirements
- [ ] Commit: `git commit -m "feat: extract fina-connector with mock support"`

### Extract porezna-connector (1.5 hours)
- [ ] Verify Porezna mock running: `curl http://localhost:8450/api/status`
- [ ] Navigate: `cd services/porezna-connector`
- [ ] Extract: `cp -r . ~/repos/eracun-integration/porezna-connector`
- [ ] Configure for mock: `echo "POREZNA_USE_MOCK=true" >> .env`
- [ ] Add mock URL: `echo "POREZNA_MOCK_URL=http://localhost:8450" >> .env`
- [ ] Install: `npm install`
- [ ] Test with mock: `npm test`
- [ ] Commit: `git commit -m "feat: extract porezna-connector with mock support"`

### Extract bank-integration (1 hour)
- [ ] Check if bank mock exists in mock repo
- [ ] If not, create simple mock endpoint
- [ ] Navigate: `cd services/bank-integration`
- [ ] Extract: `cp -r . ~/repos/eracun-integration/bank-integration`
- [ ] Configure mock endpoints
- [ ] Install and test: `npm install && npm test`
- [ ] Commit: `git commit -m "feat: extract bank-integration"`

### Extract certificate-lifecycle-manager (1 hour)
- [ ] Navigate: `cd services/certificate-lifecycle-manager`
- [ ] Extract: `cp -r . ~/repos/eracun-integration/certificate-lifecycle-manager`
- [ ] Configure to use mock certificates
- [ ] Install: `npm install`
- [ ] Test certificate operations: `npm test`
- [ ] Document real certificate requirements
- [ ] Commit: `git commit -m "feat: extract certificate-lifecycle-manager"`

---

## ⚠️ Phase 6: Services with Shared Package Dependencies (Day 6-7)

### Copy Strategy Instructions (Use for Each Service Below)
```bash
# For each service with @eracun/* imports:
# 1. Create shared directory
mkdir -p src/shared

# 2. Copy required packages
cp -r ~/PycharmProjects/eRačun/shared/contracts src/shared/
cp -r ~/PycharmProjects/eRačun/shared/types src/shared/
cp -r ~/PycharmProjects/eRačun/shared/di-container src/shared/

# 3. Update imports
find . -type f -name "*.ts" -exec sed -i 's/@eracun\//\.\/shared\//g' {} \;

# 4. Add tech debt marker
echo "// TODO: SHARED-PACKAGE-DEBT - Replace with npm package" >> src/index.ts
```

### Extract invoice-gateway-api with copy strategy (2 hours)
- [ ] Navigate: `cd services/invoice-gateway-api`
- [ ] List shared deps: `grep -r "@eracun/" . --include="*.ts" | cut -d: -f2 | sort -u`
- [ ] Extract: `cp -r . ~/repos/eracun-ingestion/invoice-gateway-api`
- [ ] Navigate to extracted: `cd ~/repos/eracun-ingestion/invoice-gateway-api`
- [ ] Apply copy strategy (see above)
- [ ] Fix import paths if needed
- [ ] Install: `npm install`
- [ ] Attempt build: `npm run build`
- [ ] If TypeScript errors, document in TECHNICAL-DEBT.md
- [ ] Run tests if build succeeds: `npm test`
- [ ] Commit even if not perfect: `git commit -m "feat: extract invoice-gateway-api with copy strategy"`
- [ ] Add to TECHNICAL-DEBT.md: "invoice-gateway-api: Needs shared package consolidation"

---

## 🔧 Phase 7: Currently Blocked Services (Day 8-10)

### Fix and extract admin-portal-api (4 hours)
- [ ] Navigate: `cd services/admin-portal-api`
- [ ] List HTTP client usage: `grep -r "axios\|node-fetch\|http\." . --include="*.ts"`
- [ ] Create HttpClient interface in `src/http/client.ts`
- [ ] Create AxiosAdapter implementing interface
- [ ] Replace all HTTP calls with adapter pattern
- [ ] Test refactored code in monorepo: `npm test`
- [ ] Once tests pass, extract: `cp -r . ~/repos/eracun-infrastructure/admin-portal-api`
- [ ] Apply copy strategy if has shared deps
- [ ] Install and test: `npm install && npm test`
- [ ] Commit: `git commit -m "feat: extract admin-portal-api after HTTP client standardization"`
- [ ] Document ADR-005 decision retroactively

### Complete and extract email-ingestion-worker (6 hours)
- [ ] Navigate: `cd services/email-ingestion-worker`
- [ ] Check IMPROVEMENT-005 status: `git log -5 --oneline . | grep IMPROVEMENT`
- [ ] If not complete, finish streaming implementation:
  - [ ] Fix mailparser Promise vs EventEmitter issue
  - [ ] Resolve TypeScript strict mode errors
  - [ ] Update tests for streaming
- [ ] Run full test suite: `npm test`
- [ ] Once all tests pass (>85%), extract: `cp -r . ~/repos/eracun-ingestion/email-ingestion-worker`
- [ ] Configure email mock: `echo "EMAIL_USE_MOCK=true" >> .env`
- [ ] Install and test: `npm install && npm test`
- [ ] Commit: `git commit -m "feat: extract email-ingestion-worker after IMPROVEMENT-005"`

---

## 🎯 Phase 8: Final Verification (Day 11)

### Repository Structure Verification
- [ ] Verify eracun-validation has all validation services
- [ ] Verify eracun-transformation has all transformation services
- [ ] Verify eracun-integration has all integration services
- [ ] Verify eracun-ingestion has all ingestion services
- [ ] Verify eracun-infrastructure has infrastructure services
- [ ] Verify eracun-archive has archive service

### Integration Testing
- [ ] Start all mock services
- [ ] Run integration tests across repos
- [ ] Verify service-to-service communication works
- [ ] Test with chaos mode enabled: `CHAOS_MODE=moderate`
- [ ] Document any integration issues

### Documentation Updates
- [ ] Update main README with new repo structure
- [ ] Create migration completion report
- [ ] Update TECHNICAL-DEBT.md with all copy-strategy items
- [ ] Archive monorepo services directory (make read-only)

---

## 📊 Progress Tracking

### Daily Checkpoint Template
```markdown
Date: YYYY-MM-DD
Services Extracted Today: X
Total Extracted: XX/31
Blockers Encountered:
Time Spent: X hours
Tomorrow's Target:
```

### Velocity Metrics
- **Target:** 2-3 services per day
- **Expected Completion:** 15-20 working days
- **Actual Start Date:** ___________
- **Actual End Date:** ___________

---

## 🚨 Escalation Triggers

If any of these occur, escalate immediately:

- [ ] Service extraction takes >4 hours
- [ ] Test coverage drops below 50%
- [ ] TypeScript compilation has >20 errors
- [ ] Circular dependency discovered
- [ ] Mock service inadequate for testing
- [ ] Shared package strategy causes breaking changes

---

## ✅ Definition of Done

A service is considered "extracted" when:

1. [ ] Code copied to target repository
2. [ ] Dependencies installed successfully
3. [ ] Tests pass (>85% passing acceptable)
4. [ ] TypeScript compilation succeeds (warnings OK)
5. [ ] Service runs with mock dependencies
6. [ ] Committed to new repository
7. [ ] Technical debt documented if applicable
8. [ ] This checklist item marked complete

---

## 📝 Notes Section

Use this space to track issues, decisions, and observations:

```
Date:
Note:

Date:
Note:

Date:
Note:
```

---

## 🏁 Final Checklist

When all services are extracted:

- [ ] All 31 services migrated to new repos
- [ ] Monorepo services/ directory archived
- [ ] All teams trained on new structure
- [ ] CI/CD configured for each repo
- [ ] Mock repository documented
- [ ] Shared package consolidation plan created
- [ ] Production deployment plan ready
- [ ] Celebration scheduled! 🎉

---

**Remember:**
- Don't aim for perfection, aim for "good enough"
- Document debt, don't fix it during extraction
- Use mocks aggressively
- Commit progress daily
- Ask for help when blocked

**Current Status:** 12/31 services complete (39%)
**Next Service:** data-extractor
**Estimated Completion:** ____________