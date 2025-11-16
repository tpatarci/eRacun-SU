# Shared Package Migration Strategy

**Date:** 2025-11-16
**Purpose:** Resolve shared package dependencies blocking multi-repo migration
**Priority:** 🔴 CRITICAL - Blocks invoice-gateway-api extraction

---

## Executive Summary

The monorepo contains shared packages (@eracun/contracts, @eracun/types, @eracun/di-container) that multiple services depend on. This document defines a pragmatic "Copy-First, Consolidate Later" strategy to unblock immediate migration while maintaining a path to proper package management.

**Strategy:** Accept temporary code duplication to achieve migration velocity.

---

## 🎯 Current Shared Package Analysis

### Identified Shared Packages

| Package | Usage Count | Services Affected | Size | Criticality |
|---------|-------------|-------------------|------|-------------|
| @eracun/contracts | 12 services | invoice-gateway-api, fina-connector, validators | ~500 LOC | 🔴 HIGH |
| @eracun/types | 8 services | All processing services | ~300 LOC | 🟡 MEDIUM |
| @eracun/di-container | 3 services | invoice-gateway-api, admin-portal | ~200 LOC | 🟢 LOW |
| @eracun/utils | 6 services | Various helpers | ~400 LOC | 🟢 LOW |
| @eracun/observability | 10 services | Logging, tracing | ~250 LOC | 🟡 MEDIUM |

### Dependency Graph
```
invoice-gateway-api
├── @eracun/contracts      (Protocol Buffers)
├── @eracun/di-container   (Inversify setup)
└── @eracun/types          (Domain models)

fina-connector
├── @eracun/contracts      (Messages)
└── @eracun/observability  (Logging)

validators/*
├── @eracun/types          (ValidationResult)
└── @eracun/utils          (Helpers)
```

---

## 📋 Migration Strategy: Three Phases

### Phase 1: Copy-First (Week 1-2) ✅ IMMEDIATE

**Approach:** Copy shared code directly into each service.

```bash
# For each service needing shared packages
SERVICE_NAME="invoice-gateway-api"
cd services/$SERVICE_NAME

# Create local shared directory
mkdir -p src/shared

# Copy required packages
cp -r ../../shared/contracts src/shared/
cp -r ../../shared/types src/shared/
cp -r ../../shared/di-container src/shared/

# Update imports via script
find . -type f -name "*.ts" -exec sed -i \
  -e "s|@eracun/contracts|./shared/contracts|g" \
  -e "s|@eracun/types|./shared/types|g" \
  -e "s|@eracun/di-container|./shared/di-container|g" {} \;
```

**Benefits:**
- ✅ Unblocks immediately
- ✅ No external dependencies
- ✅ Same TypeScript types
- ✅ Easy to track (grep for "./shared")

**Drawbacks:**
- ❌ Code duplication
- ❌ Manual sync needed
- ❌ Increases repo size

**Mitigation:**
```typescript
// Add header to all copied files
/**
 * SHARED-PACKAGE-COPY
 * This is a temporary copy from @eracun/contracts
 * Original: monorepo/shared/contracts/invoice.proto
 * TODO: Replace with npm package from eracun-contracts repo
 * Tracking: TECHNICAL-DEBT.md#shared-packages
 */
```

---

### Phase 2: Extract Contracts Repository (Week 3-4)

**Create dedicated contracts repository:**

```
eracun-contracts/
├── packages/
│   ├── contracts/          # Protocol Buffers
│   │   ├── src/
│   │   ├── package.json
│   │   └── tsconfig.json
│   ├── types/              # TypeScript types
│   │   ├── src/
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── utils/              # Shared utilities
│       ├── src/
│       ├── package.json
│       └── tsconfig.json
├── lerna.json              # Monorepo management
├── package.json
└── README.md
```

**Package Publishing:**
```json
// packages/contracts/package.json
{
  "name": "@eracun/contracts",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "publishConfig": {
    "registry": "https://npm.pkg.github.com"
  }
}
```

**Automated Publishing:**
```yaml
# .github/workflows/publish.yml
on:
  push:
    tags:
      - 'v*'
jobs:
  publish:
    steps:
      - uses: actions/checkout@v3
      - run: npm ci
      - run: npm run build
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

### Phase 3: Consolidate (Week 5-6)

**Replace local copies with npm packages:**

```bash
# For each service
cd services/invoice-gateway-api

# Remove local copies
rm -rf src/shared

# Install from npm
npm install @eracun/contracts@^1.0.0
npm install @eracun/types@^1.0.0

# Update imports back
find . -type f -name "*.ts" -exec sed -i \
  -e "s|./shared/contracts|@eracun/contracts|g" \
  -e "s|./shared/types|@eracun/types|g" {} \;
```

**Version Management:**
```json
// package.json
{
  "dependencies": {
    "@eracun/contracts": "^1.0.0",  // Protocol buffers
    "@eracun/types": "^1.0.0"       // Domain types
  }
}
```

---

## 🛠️ Implementation Guide

### Step 1: Identify Dependencies (Per Service)

```bash
# Find all shared package imports
grep -r "@eracun/" --include="*.ts" . | \
  sed 's/.*@eracun\/\([^"'\'']*\).*/\1/' | \
  sort | uniq

# Output example:
# contracts
# types
# di-container
```

### Step 2: Copy Required Packages

```bash
#!/bin/bash
# copy-shared-packages.sh

SERVICE=$1
PACKAGES=$2  # comma-separated

IFS=',' read -ra PKG_ARRAY <<< "$PACKAGES"
for pkg in "${PKG_ARRAY[@]}"; do
  echo "Copying $pkg to $SERVICE/src/shared/"
  mkdir -p "$SERVICE/src/shared"
  cp -r "shared/$pkg" "$SERVICE/src/shared/"
done

# Usage:
./copy-shared-packages.sh invoice-gateway-api "contracts,types,di-container"
```

### Step 3: Update Imports

```typescript
// Before
import { InvoiceMessage } from '@eracun/contracts';
import { ValidationResult } from '@eracun/types';
import { Container } from '@eracun/di-container';

// After
import { InvoiceMessage } from './shared/contracts';
import { ValidationResult } from './shared/types';
import { Container } from './shared/di-container';
```

### Step 4: Track Technical Debt

```markdown
<!-- TECHNICAL-DEBT.md -->
## Shared Package Copies

| Service | Copied Packages | Date | Owner | Target Removal |
|---------|----------------|------|-------|----------------|
| invoice-gateway-api | contracts, types, di-container | 2025-11-16 | Team 2 | Week 5 |
| fina-connector | contracts, observability | 2025-11-16 | Team 3 | Week 5 |
| admin-portal-api | di-container, utils | 2025-11-17 | Team 3 | Week 6 |
```

---

## 📊 Decision Matrix

### Why Copy-First?

| Approach | Speed | Risk | Complexity | Maintenance | **Score** |
|----------|-------|------|------------|-------------|-----------|
| **Copy-First** | ⚡ Immediate | 🟡 Medium | 🟢 Low | 🔴 High | **7/10** |
| Wait for Contracts Repo | 🔴 2 weeks | 🟢 Low | 🟡 Medium | 🟢 Low | **5/10** |
| Symlinks | ⚡ Immediate | 🔴 High | 🔴 High | 🔴 High | **3/10** |
| Git Submodules | 🟡 1 week | 🟡 Medium | 🔴 High | 🟡 Medium | **4/10** |

**Winner:** Copy-First provides fastest unblocking with acceptable risk.

---

## 🚨 Risk Mitigation

### Risk 1: Divergence
**Mitigation:** Freeze shared packages during migration
```bash
# Add to monorepo shared packages
echo "FROZEN FOR MIGRATION - DO NOT MODIFY" > shared/FREEZE.md
```

### Risk 2: Breaking Changes
**Mitigation:** Version lock all copies
```typescript
// Add version comment
// @version 1.0.0-migration-snapshot
export interface InvoiceMessage { ... }
```

### Risk 3: Forgotten Updates
**Mitigation:** Automated tracking
```bash
# Weekly check for divergence
diff -r service1/src/shared/contracts service2/src/shared/contracts
```

---

## ✅ Success Criteria

### Phase 1 Complete When:
- [ ] All blocked services have local shared copies
- [ ] All services compile successfully
- [ ] Technical debt tracked in TECHNICAL-DEBT.md
- [ ] No imports from @eracun/* remain

### Phase 2 Complete When:
- [ ] eracun-contracts repo created
- [ ] All packages published to npm
- [ ] Semantic versioning established
- [ ] CI/CD publishes on tag

### Phase 3 Complete When:
- [ ] All local copies removed
- [ ] All services use npm packages
- [ ] Version management via package.json
- [ ] Zero code duplication

---

## 📝 Immediate Actions

### For invoice-gateway-api (TODAY):

```bash
# 1. Navigate to service
cd services/invoice-gateway-api

# 2. Copy shared packages
mkdir -p src/shared
cp -r ../../shared/contracts src/shared/
cp -r ../../shared/types src/shared/
cp -r ../../shared/di-container src/shared/

# 3. Update imports
find . -type f -name "*.ts" -exec sed -i \
  "s|@eracun/|./shared/|g" {} \;

# 4. Build and test
npm run build
npm test

# 5. Extract to multi-repo
# (Now unblocked!)
```

---

## 🔗 Related Documents

- Updated Instructions: @docs/MULTI_REPO_MIGRATION_UPDATED_INSTRUCTIONS.md
- Blocker Analysis: @docs/BLOCKERS_RESOLUTION_WITH_MOCKS.md
- Technical Debt: TECHNICAL-DEBT.md

---

**Document Version:** 1.0.0
**Created:** 2025-11-16
**Strategy:** Copy-First, Consolidate Later
**Timeline:** 6 weeks total (2 weeks copy, 4 weeks consolidate)