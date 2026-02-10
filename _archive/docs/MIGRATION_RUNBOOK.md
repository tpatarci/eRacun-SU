# Multi-Repository Migration Runbook

**Document Type:** Operational Procedure
**Status:** ✅ Active (Phase 0 in progress)
**Created:** 2025-11-15
**Owner:** Platform Architecture Team
**Compliance:** Based on `MULTI_REPO_MIGRATION_PLAN.md`

---

## Purpose

This runbook provides step-by-step instructions for migrating services from the eRačun monorepo to individual domain repositories. Follow these procedures for each migration phase.

---

## Prerequisites

### Required Tools
- [x] Git 2.30+
- [x] Node.js 20+
- [x] GitHub CLI (`gh`)
- [x] Docker 24+
- [x] PostgreSQL 15+ (local or remote)
- [x] RabbitMQ 3.12+ (local or remote)

### Required Access
- [x] GitHub repository creation permissions
- [x] NPM package publishing rights (`@eracun` scope)
- [x] DigitalOcean deployment access
- [x] Slack #eracun-migration channel access

### Required Knowledge
- [x] Multi-repo migration plan (`docs/MULTI_REPO_MIGRATION_PLAN.md`)
- [x] Migration criteria (`docs/MULTI_REPO_MIGRATION_CRITERIA.md`)
- [x] Service architecture (`docs/adr/ADR-003-system-decomposition-integration-architecture.md`)

---

## Phase Template

Each phase follows this template:

1. **Preparation** (Day 1-2)
2. **Repository Setup** (Day 3-5)
3. **Service Migration** (Week 2)
4. **CI/CD Configuration** (Week 2)
5. **Testing** (Week 3)
6. **Staging Deployment** (Week 3)
7. **Production Migration** (Week 4)
8. **Monitoring & Cleanup** (Week 4+)

---

## Step-by-Step Procedures

### **STEP 1: Preparation** (2 days)

#### 1.1 Create Working Directory

```bash
# Create temporary workspace
mkdir -p ~/eracun-migration/phase-{N}
cd ~/eracun-migration/phase-{N}

# Clone monorepo (read-only)
git clone https://github.com/tpatarci/eRacun-development.git monorepo
cd monorepo
```

#### 1.2 Identify Services to Migrate

```bash
# List services for this phase (from migration plan)
# Example for Phase 0:
SERVICES=(
  "health-monitor"
  "notification-service"
)

# Verify services exist
for service in "${SERVICES[@]}"; do
  if [ -d "services/$service" ]; then
    echo "✓ Found: services/$service"
  else
    echo "✗ Missing: services/$service"
    exit 1
  fi
done
```

#### 1.3 Review Migration Checklist

**Technical Checklist:**
- [ ] Services can be built independently?
- [ ] Services can be deployed independently?
- [ ] Services can be tested independently?
- [ ] Clear API boundaries defined?
- [ ] No shared database access?
- [ ] Protocol Buffers contracts defined?

**Organizational Checklist:**
- [ ] Team ownership assigned?
- [ ] CODEOWNERS file prepared?
- [ ] ARB approval obtained?
- [ ] Stakeholders notified?

#### 1.4 Announce Migration

```bash
# Post to Slack
# #eracun-migration channel
echo "🚀 Starting Phase {N} Migration

**Services:** ${SERVICES[@]}
**Owner:** Team {N}
**Timeline:** Weeks {X}-{Y}
**Status:** Preparation phase"
```

---

### **STEP 2: Repository Setup** (3 days)

#### 2.1 Create New Repository

```bash
# Create repository from template
gh repo create tpatarci/eracun-{domain} \
  --template tpatarci/eracun-service-template \
  --private \
  --description "{Bounded context description}"

# Clone new repository
cd ~/eracun-migration/phase-{N}
git clone https://github.com/tpatarci/eracun-{domain}.git
cd eracun-{domain}
```

#### 2.2 Initialize Repository Structure

```bash
# Create directory structure
mkdir -p services
mkdir -p .github/workflows
mkdir -p docs

# Create package.json
cat > package.json <<'EOF'
{
  "name": "@eracun/{domain}",
  "version": "0.1.0",
  "description": "eRačun {domain} services",
  "private": true,
  "workspaces": [
    "services/*"
  ],
  "scripts": {
    "dev": "npm run dev --workspaces --if-present",
    "build": "npm run build --workspaces --if-present",
    "test": "NODE_OPTIONS=--experimental-vm-modules jest",
    "test:coverage": "NODE_OPTIONS=--experimental-vm-modules jest --coverage",
    "lint": "eslint . --ext .ts,.tsx --max-warnings 0",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@eracun/contracts": "^1.0.0"
  },
  "devDependencies": {
    "@types/jest": "^29.5.11",
    "@types/node": "^20.10.6",
    "eslint": "^8.56.0",
    "jest": "^29.7.0",
    "typescript": "^5.3.3"
  }
}
EOF
```

#### 2.3 Copy CI/CD Workflows

**See `/tmp/eracun-pilot-repo/.github/workflows/ci.yml` for complete workflow**

Key sections:
- Lint & Type Check (parallel)
- Unit Tests (parallel by service)
- Integration Tests (with PostgreSQL, RabbitMQ)
- Docker Build (multi-arch)
- Security Scan (Snyk)

#### 2.4 Create CODEOWNERS

```bash
cat > CODEOWNERS <<EOF
# Default owners
* @tpatarci/team-{N}

# Service-specific
/services/* @tpatarci/team-{N} @{lead-developer}

# Infrastructure
/.github/ @devops-lead
/scripts/ @devops-lead
EOF
```

#### 2.5 Create README.md

**See `/tmp/eracun-pilot-repo/README.md` for template**

Required sections:
- Purpose & Bounded Context
- Quick Start
- Repository Structure
- Development Workflow
- Service Documentation
- CI/CD Pipeline
- Team Ownership

---

### **STEP 3: Service Migration** (1 week)

#### 3.1 Copy Services from Monorepo

```bash
# Copy each service with full directory structure
for service in "${SERVICES[@]}"; do
  echo "Migrating: $service"

  # Copy service directory
  cp -r ../monorepo/services/$service ./services/

  # Remove monorepo-specific files
  rm -f ./services/$service/CLAUDE.md.backup*

  echo "✓ Copied: $service"
done
```

#### 3.2 Update Dependencies

```bash
# For each service
for service in "${SERVICES[@]}"; do
  cd services/$service

  # Update package.json
  # Change relative imports to @eracun/contracts
  sed -i 's|../../../shared/|@eracun/contracts|g' package.json

  # Install dependencies
  npm install

  cd ../..
done
```

#### 3.3 Update Import Statements

```bash
# Update all TypeScript files
find services -name "*.ts" -type f -exec sed -i \
  's|from.*"\.\./\.\./\.\./shared/|from "@eracun/contracts|g' {} \;

# Verify no cross-service imports
if grep -r "from.*'\.\./\.\./.*services/" services/*/src; then
  echo "❌ ERROR: Cross-service imports detected"
  exit 1
fi
```

#### 3.4 Commit Initial Migration

```bash
git add -A
git commit -m "feat: migrate services from monorepo

Migrated services:
$(for service in "${SERVICES[@]}"; do echo "- $service"; done)

Changes:
- Updated imports to use @eracun/contracts
- Removed monorepo-specific files
- Configured workspaces

Source: eRacun-development monorepo
Commit: $(cd ../monorepo && git rev-parse HEAD)"

git push origin main
```

---

### **STEP 4: CI/CD Configuration** (3 days)

#### 4.1 Test CI Pipeline Locally

```bash
# Install dependencies
npm ci

# Run linting
npm run lint

# Run type checking
npm run typecheck

# Run tests
npm test

# Check coverage
npm run test:coverage
```

#### 4.2 Push and Verify GitHub Actions

```bash
# Create test branch
git checkout -b test/ci-pipeline

# Make trivial change
echo "# CI Test" >> README.md

# Commit and push
git commit -am "test: verify CI pipeline"
git push origin test/ci-pipeline

# Create PR
gh pr create --title "Test: CI Pipeline" --body "Testing CI/CD workflows"

# Wait for CI to complete
gh pr checks

# Expected: All checks passing in ~14 minutes
```

#### 4.3 Configure Deployment Workflows

**Staging Deployment:**
```yaml
# .github/workflows/cd-staging.yml
name: Deploy to Staging
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to staging
        env:
          DO_TOKEN: ${{ secrets.DO_TOKEN }}
        run: ./scripts/deploy-staging.sh
```

**Production Deployment:**
```yaml
# .github/workflows/cd-prod.yml
name: Deploy to Production
on:
  release:
    types: [published]
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://production.eracun.hr
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to production
        env:
          DO_TOKEN: ${{ secrets.DO_TOKEN }}
        run: ./scripts/deploy-production.sh
```

---

### **STEP 5: Testing** (1 week)

#### 5.1 Unit Testing

```bash
# Run all unit tests
npm test

# Check coverage
npm run test:coverage

# Expected: >85% coverage
```

#### 5.2 Integration Testing

```bash
# Start dependencies
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
npm run test:integration

# Cleanup
docker-compose -f docker-compose.test.yml down
```

#### 5.3 Contract Testing

```bash
# Verify Protocol Buffer contracts
npm install -g @bufbuild/buf

# Check for breaking changes
buf breaking --against '.git#tag=v1.0.0'

# Expected: No breaking changes
```

#### 5.4 Smoke Testing

```bash
# Build services
npm run build

# Run smoke tests
npm run test:smoke

# Expected: All services healthy
```

---

### **STEP 6: Staging Deployment** (1 week)

#### 6.1 Deploy to Staging

```bash
# Set environment
export ENV=staging
export DO_TOKEN={token}

# Deploy services
./scripts/deploy-staging.sh

# Expected output:
# ✓ health-monitor deployed
# ✓ notification-service deployed
# ✓ All health checks passing
```

#### 6.2 Configure Feature Flags

```bash
# Enable feature flag for new repo (0% traffic initially)
kubectl set env deployment/health-monitor \
  FEATURE_FLAG_NEW_REPO=false \
  FEATURE_FLAG_NEW_REPO_PERCENTAGE=0

# Verify monorepo still handling 100% traffic
curl https://staging.eracun.hr/health | jq .source
# Expected: "monorepo"
```

#### 6.3 Run Staging Tests

```bash
# Run E2E tests against staging
npm run test:e2e -- --env=staging

# Monitor for errors
kubectl logs -f deployment/health-monitor

# Check metrics
open https://grafana.eracun.hr/d/health-monitor-staging
```

#### 6.4 Parallel Run (Canary Deployment)

**Week 3.1: 0% Traffic**
```bash
# Deploy to staging, no production traffic
kubectl set env deployment/health-monitor \
  FEATURE_FLAG_NEW_REPO_PERCENTAGE=0

# Monitor for 48 hours
```

**Week 3.2: 10% Traffic**
```bash
# Gradual traffic shift
kubectl set env deployment/health-monitor \
  FEATURE_FLAG_NEW_REPO_PERCENTAGE=10

# Monitor error rates
# Expected: <0.1% error rate increase
```

**Week 3.3: 50% Traffic**
```bash
# Half traffic
kubectl set env deployment/health-monitor \
  FEATURE_FLAG_NEW_REPO_PERCENTAGE=50

# Compare metrics: old vs new
# - Latency (p95, p99)
# - Error rates
# - Throughput
```

**Week 3.4: 100% Traffic**
```bash
# Full cutover
kubectl set env deployment/health-monitor \
  FEATURE_FLAG_NEW_REPO_PERCENTAGE=100

# Monitor for 2 weeks
# Expected: No incidents
```

---

### **STEP 7: Production Migration** (Rule 5.3 Completion Criteria)

#### 7.1 Pre-Production Checklist

- [ ] All staging tests passing (2 weeks stable)
- [ ] No incidents in staging
- [ ] Team trained on new repository
- [ ] Rollback plan documented and tested
- [ ] Stakeholders notified (48 hours advance notice)
- [ ] On-call engineers briefed
- [ ] Monitoring dashboards configured

#### 7.2 Production Deployment

```bash
# Set environment
export ENV=production
export DO_TOKEN={production-token}

# Deploy services
./scripts/deploy-production.sh

# Verify deployment
kubectl get pods -l app=health-monitor -n production

# Expected: All pods Running
```

#### 7.3 Traffic Shift (Same Canary Process)

```bash
# Day 1: 0% traffic (deploy only)
kubectl set env deployment/health-monitor \
  -n production \
  FEATURE_FLAG_NEW_REPO_PERCENTAGE=0

# Day 2: 10% traffic
FEATURE_FLAG_NEW_REPO_PERCENTAGE=10

# Day 5: 50% traffic
FEATURE_FLAG_NEW_REPO_PERCENTAGE=50

# Day 7: 100% traffic (full cutover)
FEATURE_FLAG_NEW_REPO_PERCENTAGE=100
```

#### 7.4 Monitor Production

**Critical Metrics:**
- Error rate: <0.1% increase
- Latency p95: Same or better
- Latency p99: Same or better
- Throughput: Same or better
- Health check status: 100% passing

**Monitoring Duration:**
- 2 weeks required for completion (Rule 5.3)
- Daily review of metrics
- Weekly retrospectives

---

### **STEP 8: Cleanup & Completion** (Rule 5.3)

#### 8.1 Remove Monorepo Version

```bash
# After 2 weeks stable in production
cd ~/eracun-migration/monorepo

# Delete migrated services
for service in "${SERVICES[@]}"; do
  git rm -r services/$service
done

# Commit deletion
git commit -m "chore: remove migrated services

Services migrated to eracun-{domain}:
$(for service in "${SERVICES[@]}"; do echo "- $service"; done)

New repository: https://github.com/tpatarci/eracun-{domain}
Migration phase: Phase {N}
Completion date: $(date +%Y-%m-%d)"

# Push to monorepo
git push origin main
```

#### 8.2 Update Documentation

```bash
# Update service registry
echo "## Migrated Services

| Service | New Repository | Migration Date |
|---------|---------------|----------------|
$(for service in "${SERVICES[@]}"; do
  echo "| $service | eracun-{domain} | $(date +%Y-%m-%d) |"
done)" >> docs/MIGRATED_SERVICES.md

# Update CLAUDE.md references
sed -i 's|services/{service}|https://github.com/tpatarci/eracun-{domain}|g' CLAUDE.md

# Commit documentation
git commit -am "docs: update service registry for Phase {N} migration"
git push
```

#### 8.3 Phase Completion Checklist (Rule 5.3)

**Required for Completion:**
- [x] All traffic routed to new repo (100%)
- [x] Monorepo version deleted
- [x] CI/CD pipeline fully operational (<20 min)
- [x] Monitoring/alerting configured
- [x] Team trained on new workflow
- [x] 2 weeks stable in production

**Success Metrics:**
- Deployment frequency increased: {X}%
- Build time decreased: {Y} minutes
- Error rate: {Z}% (should be <0.1% increase)
- Developer satisfaction: {Survey Score}/10

#### 8.4 Phase Retrospective

**Schedule retrospective meeting:**
- When: End of Week 4
- Who: Team {N}, DevOps, ARB members
- Agenda:
  1. What went well?
  2. What went poorly?
  3. Lessons learned
  4. Process improvements for next phase

**Document in:** `docs/reports/2025-{MM}-{DD}-phase-{N}-retrospective.md`

---

## Rollback Procedures

### **EMERGENCY ROLLBACK** (If Production Issues)

#### Step 1: Stop Traffic to New Repo (Immediate)

```bash
# Set feature flag to 0% (monorepo handles all traffic)
kubectl set env deployment/{service} \
  -n production \
  FEATURE_FLAG_NEW_REPO_PERCENTAGE=0

# Verify traffic redirected
curl https://production.eracun.hr/health | jq .source
# Expected: "monorepo"
```

#### Step 2: Verify Monorepo Services

```bash
# Check monorepo pods healthy
kubectl get pods -l source=monorepo -n production

# Run smoke tests
npm run test:smoke -- --against=monorepo

# Expected: All tests passing
```

#### Step 3: Investigate & Fix

```bash
# Review logs
kubectl logs -f deployment/{service} -n production

# Check metrics
open https://grafana.eracun.hr/d/{service}-production

# Identify root cause
# Fix in new repo
# Retest in staging
```

#### Step 4: Communicate

```bash
# Post to Slack #eracun-migration
echo "🚨 ROLLBACK: Phase {N} Migration

**Reason:** {root cause}
**Impact:** {description}
**Status:** Traffic redirected to monorepo
**Next Steps:** Investigating and fixing in new repo"
```

#### Step 5: Retry

```bash
# After fix deployed to staging
# Test for 1 week in staging
# Retry production migration
```

---

## Success Criteria Summary

**Per-Phase Success:**
- ✅ CI/CD < 20 minutes
- ✅ All tests passing (>85% coverage)
- ✅ 0 production incidents (2 weeks)
- ✅ Error rate <0.1% increase
- ✅ Latency same or better
- ✅ Team trained and confident

**Overall Migration Success:**
- ✅ All 40+ services migrated
- ✅ Monorepo archived
- ✅ CI/CD improved by 70%
- ✅ Developer satisfaction >4.0/5
- ✅ Deployment frequency increased >50%
- ✅ No compliance violations

---

## Reference Documents

- **Migration Plan:** `docs/MULTI_REPO_MIGRATION_PLAN.md`
- **Migration Criteria:** `docs/MULTI_REPO_MIGRATION_CRITERIA.md`
- **ADR-003:** System Decomposition
- **ADR-005:** Bounded Context Isolation

---

**Document Status:** ✅ **Active**
**Last Updated:** 2025-11-15
**Owner:** Platform Architecture Team
**Review:** After each phase completion
