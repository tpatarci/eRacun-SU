# TypeScript Harmonization Guide

## Executive Summary
This guide establishes TypeScript as the **mandatory standard** for all configuration, tooling, and scripts across the eRačun codebase. JavaScript files are considered technical debt and must be systematically migrated.

**Current State:** Mixed JavaScript/TypeScript (29% migrated)
**Target State:** 100% TypeScript with strict mode
**Deadline:** All new code in TypeScript immediately, migration complete by Q1 2025

---

## 1. Harmonization Principles

### Core Mandate
**ALL configuration and tooling files MUST be TypeScript.**

This includes:
- Jest configurations (`jest.config.ts`)
- ESLint configurations (`.eslintrc.ts`)
- Prettier configurations (`.prettierrc.ts`)
- Build scripts (all scripts in TypeScript)
- Webpack/Rollup configs (if added)
- Any custom tooling

### Why TypeScript Everywhere

1. **Type Safety**: Catch configuration errors at compile time
2. **IDE Support**: IntelliSense for configuration options
3. **Consistency**: Single language across entire codebase
4. **Refactoring**: Safe refactoring with type checking
5. **Documentation**: Types serve as inline documentation

---

## 2. Current State Audit

### Migration Status (as of 2024-11-15)

| Category | JavaScript | TypeScript | Migration % |
|----------|------------|------------|-------------|
| Jest Configs | 21 | 8 | 28% |
| Service Code | 0 | ~100% | 100% |
| Scripts | 2 | 0 | 0% |
| Shared Configs | 2 | 0 | 0% |

### Services Requiring Migration

**Already Migrated (✅):**
- digital-signature-service
- fina-connector
- pdf-parser
- xml-parser
- xsd-validator
- oib-validator
- kpd-validator
- schematron-validator

**Pending Migration (⏳):**
- reporting-service
- file-classifier
- sftp-ingestion-worker
- invoice-orchestrator
- porezna-connector
- email-ingestion-worker
- audit-logger
- notification-service
- archive-service
- cert-lifecycle-manager
- ubl-transformer
- attachment-handler
- retry-scheduler
- ai-validation-service
- invoice-gateway-api
- kpd-registry-sync
- dead-letter-handler
- ocr-processing-service
- document-classifier
- health-monitor
- admin-portal-api

---

## 3. Migration Patterns

### Pattern A: Jest Config Migration

**FROM (jest.config.js):**
```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  collectCoverageFrom: ['src/**/*.ts'],
};
```

**TO (jest.config.ts):**
```typescript
import type { Config } from 'jest';
import baseConfig from '../../shared/jest-config/base.config.js';

const config: Config = {
  ...baseConfig,
  displayName: 'service-name',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  collectCoverageFrom: [
    ...baseConfig.collectCoverageFrom || [],
    '!src/index.ts', // Service-specific exclusions
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};

export default config;
```

### Pattern B: ESLint Config Migration

**FROM (.eslintrc.js):**
```javascript
module.exports = {
  extends: ['airbnb-base'],
  rules: {
    'no-console': 'error',
  },
};
```

**TO (.eslintrc.ts):**
```typescript
import type { Linter } from 'eslint';

const config: Linter.Config = {
  extends: ['airbnb-base', 'airbnb-typescript/base'],
  parserOptions: {
    project: './tsconfig.json',
  },
  rules: {
    'no-console': 'error',
    '@typescript-eslint/explicit-function-return-type': 'error',
  },
};

export default config;
```

### Pattern C: Script Migration

**FROM (scripts/check-something.js):**
```javascript
#!/usr/bin/env node
const fs = require('fs');

function checkSomething(path) {
  const content = fs.readFileSync(path, 'utf8');
  return content.includes('pattern');
}
```

**TO (scripts/check-something.ts):**
```typescript
#!/usr/bin/env tsx
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function checkSomething(path: string): boolean {
  const absolutePath = resolve(path);
  const content = readFileSync(absolutePath, 'utf8');
  return content.includes('pattern');
}

// Type-safe CLI argument parsing
const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: check-something.ts <path>');
  process.exit(1);
}

const result = checkSomething(args[0]);
process.exit(result ? 0 : 1);
```

### Pattern D: Package.json Updates

**Update for TypeScript configs:**
```json
{
  "scripts": {
    "test": "NODE_OPTIONS='--experimental-vm-modules --import tsx' jest --config jest.config.ts",
    "test:watch": "NODE_OPTIONS='--experimental-vm-modules --import tsx' jest --config jest.config.ts --watch",
    "test:coverage": "NODE_OPTIONS='--experimental-vm-modules --import tsx' jest --config jest.config.ts --coverage"
  }
}
```

**Note:** Use `--import tsx` (NOT `--loader tsx`) for Node.js v20+

---

## 4. Step-by-Step Migration Process

### Phase 1: Shared Infrastructure (Week 1)

1. **Migrate shared/jest-config/base.config.js**
   ```bash
   mv shared/jest-config/base.config.js shared/jest-config/base.config.ts
   ```
   - Add TypeScript types
   - Export as ES module
   - Update all imports

2. **Create shared TypeScript config base**
   ```typescript
   // shared/configs/tsconfig.base.json
   {
     "compilerOptions": {
       "strict": true,
       "esModuleInterop": true,
       "skipLibCheck": true,
       "forceConsistentCasingInFileNames": true
     }
   }
   ```

3. **Migrate scripts directory**
   - Convert architecture-checker.js → .ts
   - Update shebang to use tsx
   - Add type annotations

### Phase 2: Service Migration (Week 2-3)

**For each service:**

1. **Install TypeScript dependencies**
   ```bash
   npm install --save-dev @types/jest @types/node typescript tsx
   ```

2. **Create tsconfig.jest.json**
   ```json
   {
     "extends": "./tsconfig.json",
     "compilerOptions": {
       "module": "ESNext"
     }
   }
   ```

3. **Migrate jest.config.js → jest.config.ts**
   - Use Pattern A above
   - Update package.json scripts
   - Test migration: `npm test`

4. **Migrate other configs if present**
   - .eslintrc.js → .eslintrc.ts
   - .prettierrc.js → .prettierrc.ts

5. **Verify and commit**
   ```bash
   npm test
   npm run lint
   git commit -m "chore(service-name): migrate configs to TypeScript"
   ```

### Phase 3: Validation (Week 4)

1. **Run full test suite**
   ```bash
   npm test # From monorepo root
   ```

2. **Check for JavaScript stragglers**
   ```bash
   find . -name "*.config.js" -o -name ".*.js" | grep -v node_modules
   ```

3. **Update CI/CD pipelines**
   - Ensure tsx is available
   - Update Node.js version requirements

---

## 5. Enforcement Mechanisms

### Pre-commit Hook

Add to `.husky/pre-commit`:
```bash
#!/bin/sh
# Prevent new JavaScript config files
if git diff --cached --name-only | grep -E '\.(config|rc)\.js$'; then
  echo "❌ JavaScript config files are not allowed. Use TypeScript."
  echo "See: docs/TYPESCRIPT_HARMONIZATION_GUIDE.md"
  exit 1
fi
```

### CI Check

Add to GitHub Actions:
```yaml
- name: Check TypeScript Compliance
  run: |
    JS_CONFIGS=$(find . -type f \( -name "*.config.js" -o -name ".*.js" \) \
      -not -path "*/node_modules/*" -not -path "*/dist/*" | wc -l)
    if [ "$JS_CONFIGS" -gt 0 ]; then
      echo "Found $JS_CONFIGS JavaScript config files"
      echo "All configs must be TypeScript"
      exit 1
    fi
```

### Architecture Validation Script

Create `scripts/validate-typescript-compliance.ts`:
```typescript
#!/usr/bin/env tsx
import { globSync } from 'glob';
import { readFileSync } from 'node:fs';

interface ComplianceReport {
  compliant: string[];
  nonCompliant: string[];
  score: number;
}

function validateCompliance(): ComplianceReport {
  const jsConfigs = globSync('**/*.config.js', {
    ignore: ['**/node_modules/**', '**/dist/**'],
  });

  const tsConfigs = globSync('**/*.config.ts', {
    ignore: ['**/node_modules/**', '**/dist/**'],
  });

  const score = (tsConfigs.length / (jsConfigs.length + tsConfigs.length)) * 100;

  return {
    compliant: tsConfigs,
    nonCompliant: jsConfigs,
    score: Math.round(score),
  };
}

const report = validateCompliance();
console.log(`TypeScript Compliance: ${report.score}%`);
if (report.nonCompliant.length > 0) {
  console.log('\n❌ Non-compliant files:');
  report.nonCompliant.forEach(file => console.log(`  - ${file}`));
}

process.exit(report.score === 100 ? 0 : 1);
```

---

## 6. Governance

### New Code Rule
**ABSOLUTE RULE:** No new JavaScript configuration files allowed.

- PR reviewers MUST reject any PR introducing `.js` config files
- Only TypeScript configs accepted for new services
- Exceptions require Architecture Board approval

### Migration Tracking

**Weekly Status Report:**
```markdown
## TypeScript Migration Status - Week of [DATE]

**Progress:** XX% complete (YY of ZZ files migrated)

**Completed This Week:**
- [ ] service-name-1
- [ ] service-name-2

**Blockers:**
- None / List any

**Next Week Target:**
- [ ] service-name-3
- [ ] service-name-4
```

### Success Criteria

Migration is complete when:
- [ ] 100% of config files are TypeScript
- [ ] All scripts use TypeScript
- [ ] Pre-commit hooks active
- [ ] CI validates compliance
- [ ] Documentation updated
- [ ] Team trained on patterns

---

## 7. Benefits Realized

### Immediate Benefits
- **Type safety** in configurations
- **IDE autocomplete** for all config options
- **Compile-time error detection**
- **Consistent codebase** (one language)

### Long-term Benefits
- **Easier refactoring** with type safety
- **Better documentation** through types
- **Reduced bugs** in build/test configs
- **Faster onboarding** for new developers
- **Modern toolchain** alignment

---

## 8. Common Issues and Solutions

### Issue 1: Module Resolution
**Problem:** `Cannot find module` errors
**Solution:** Ensure `tsconfig.json` has proper module resolution:
```json
{
  "compilerOptions": {
    "moduleResolution": "node",
    "allowSyntheticDefaultImports": true
  }
}
```

### Issue 2: Node.js Compatibility
**Problem:** `--loader` deprecated warning
**Solution:** Use `--import tsx` for Node.js v20+

### Issue 3: Type Definitions
**Problem:** Missing types for packages
**Solution:** Install `@types/*` packages or declare modules:
```typescript
declare module 'some-untyped-package' {
  export function someFunction(): void;
}
```

---

## 9. Timeline and Accountability

### Timeline
- **Week 1 (Nov 18-22):** Shared infrastructure
- **Week 2-3 (Nov 25-Dec 6):** Service migrations
- **Week 4 (Dec 9-13):** Validation and enforcement
- **Week 5 (Dec 16-20):** Documentation and training

### Accountability
- **Owner:** Platform Architecture Team
- **Reviewers:** Team leads for each service
- **Deadline:** December 31, 2024
- **Escalation:** CTO if blocked

---

## 10. Rollout Communication

### Message to Teams

> **Subject: Mandatory TypeScript Migration for All Configurations**
>
> Team,
>
> We are standardizing on TypeScript for ALL configuration and tooling files. This is not optional.
>
> **What's Changing:**
> - All `.js` config files must migrate to `.ts`
> - New configs must be TypeScript from day one
> - CI/CD will enforce this starting December 1st
>
> **Why:**
> - Type safety prevents configuration errors
> - Consistency across our codebase
> - Better IDE support and documentation
>
> **Action Required:**
> - Review the migration guide
> - Migrate your service configs by deadline
> - Ask for help if blocked
>
> This is a priority initiative for Q4 2024.

---

**Document Version:** 1.0.0
**Last Updated:** 2024-11-15
**Review Cycle:** Weekly during migration
**Owner:** Platform Architecture Team
**Slack Channel:** #typescript-migration