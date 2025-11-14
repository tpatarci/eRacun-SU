# Pre-Commit Hooks Guide

## Overview

Pre-commit hooks automatically check code quality before each commit, ensuring consistent code style and catching errors early. The eRačun platform uses Husky + lint-staged to run automated checks on staged files.

## What Gets Checked

### 1. ESLint (TypeScript/JavaScript)
- **Purpose**: Catch bugs, enforce best practices
- **Files**: `*.ts`, `*.tsx`
- **Rules**:
  - No `any` types (error)
  - Explicit function return types (warning)
  - No unused variables (error)
  - No console.log (warning)
  - No debugger statements (error)
  - Prefer const over let (error)
  - No var (error)

### 2. Prettier (Code Formatting)
- **Purpose**: Consistent code formatting
- **Files**: `*.ts`, `*.tsx`, `*.json`, `*.md`, `*.yml`, `*.yaml`
- **Style**:
  - Single quotes
  - Semicolons required
  - 100 character line width
  - 2 space indentation
  - Trailing commas (ES5)
  - LF line endings

### 3. Architecture Compliance
- **Purpose**: Enforce architectural standards
- **Checks**:
  - No direct HTTP calls between services
  - Must use message bus (@eracun/messaging)
  - Dependency boundaries respected
  - Service size limits (max 2,500 LOC)

## Installation

Pre-commit hooks are automatically installed when you run:

```bash
npm install
```

This triggers the `prepare` script which runs `husky install`.

## Usage

### Automatic (Recommended)

Simply commit as usual. The hooks run automatically:

```bash
git add services/cert-lifecycle-manager/src/index.ts
git commit -m "feat: add certificate renewal"

# Output:
# 🔍 Running pre-commit checks...
#
# 📝 Checking staged files with ESLint and Prettier...
# ✔ Linting and formatting complete
#
# 🏗️  Checking architecture compliance...
# ✔ Architecture compliance passed
#
# ✅ Pre-commit checks passed!
```

### Manual Commands

Run checks manually before committing:

```bash
# Check all files with ESLint
npm run lint

# Auto-fix ESLint issues
npm run lint:fix

# Check formatting with Prettier
npm run format:check

# Auto-format files with Prettier
npm run format

# Type-check all services
npm run typecheck

# Check architecture compliance
npm run check:architecture

# Run all checks at once
npm run check:all
```

## Skipping Hooks (Emergency Only)

**⚠️ WARNING**: Only skip hooks in emergencies (broken main branch, critical hotfix)

```bash
# Skip pre-commit hooks
git commit --no-verify -m "fix: critical production issue"

# Skip for specific files
git commit --no-verify -m "wip: work in progress"
```

**DO NOT** skip hooks regularly. Fix the issues instead.

## Common Issues and Fixes

### Issue 1: ESLint Errors

**Error**:
```
Error: 'any' types are not allowed (@typescript-eslint/no-explicit-any)
```

**Fix**:
```typescript
// ❌ Bad
function processData(data: any) {
  return data.value;
}

// ✅ Good
interface DataType {
  value: string;
}

function processData(data: DataType): string {
  return data.value;
}
```

### Issue 2: Unused Variables

**Error**:
```
Error: 'unusedVar' is defined but never used (@typescript-eslint/no-unused-vars)
```

**Fix**:
```typescript
// ❌ Bad
const unusedVar = 10;
const result = calculateTotal(items);

// ✅ Good - Remove unused
const result = calculateTotal(items);

// ✅ Good - Prefix with underscore if intentionally unused
const _unusedVar = 10; // Ignored by ESLint
```

### Issue 3: Missing Return Types

**Warning**:
```
Warning: Missing return type on function (@typescript-eslint/explicit-function-return-type)
```

**Fix**:
```typescript
// ❌ Bad
function calculateTotal(items) {
  return items.reduce((sum, item) => sum + item.price, 0);
}

// ✅ Good
function calculateTotal(items: Item[]): number {
  return items.reduce((sum, item) => sum + item.price, 0);
}
```

### Issue 4: Prettier Formatting

**Error**:
```
Error: Code style issues found. Run 'npm run format' to fix.
```

**Fix**:
```bash
# Auto-fix all formatting issues
npm run format

# Then commit
git add .
git commit -m "fix: apply prettier formatting"
```

### Issue 5: Architecture Violations

**Error**:
```
Error: Direct HTTP call detected in fina-connector/src/client.ts
Services must use @eracun/messaging for inter-service communication
```

**Fix**:
```typescript
// ❌ Bad - Direct HTTP call
import axios from 'axios';

async function callService() {
  const response = await axios.post('http://other-service/api/endpoint', data);
  return response.data;
}

// ✅ Good - Use message bus
import { getMessageBus } from '@eracun/messaging';

async function callService() {
  const bus = getMessageBus();
  const response = await bus.request('other-service.endpoint', data);
  return response;
}
```

## Disabling Specific Rules

### Disable ESLint for a Line

```typescript
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const data: any = parseUnknownData();
```

### Disable ESLint for a File

```typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
// Entire file ignores 'no-explicit-any' rule
```

**⚠️ Use sparingly**: Document why the rule is disabled

### Ignore Files

Add to `.eslintignore` or `.prettierignore`:

```
# .eslintignore
dist/
build/
*.test.ts
legacy/
```

## CI/CD Integration

Pre-commit hooks also run in CI/CD:

```yaml
# .github/workflows/ci.yml
- name: Run linting
  run: npm run lint

- name: Check formatting
  run: npm run format:check

- name: Type check
  run: npm run typecheck

- name: Architecture compliance
  run: npm run check:architecture
```

## Performance Tips

### Speed Up lint-staged

lint-staged only checks **staged files**, not the entire codebase:

```bash
# Fast (only staged files)
git add services/cert-lifecycle-manager/src/index.ts
git commit -m "fix: update certificate validation"
# Checks only 1 file

# Slow (all files)
npm run lint
# Checks entire codebase
```

### Parallel Execution

lint-staged runs checks in parallel when possible:

```json
{
  "*.ts": [
    "eslint --fix",      // Step 1
    "prettier --write"   // Step 2 (runs after ESLint)
  ]
}
```

## Troubleshooting

### Hooks Not Running

**Problem**: Commits succeed without running hooks

**Solution**:
```bash
# Reinstall husky
rm -rf .husky
npm run prepare

# Verify hooks are installed
ls -la .git/hooks/
# Should see: pre-commit -> ../.husky/pre-commit
```

### npx Command Not Found

**Problem**: `npx lint-staged` fails

**Solution**:
```bash
# Ensure Node.js 20+ and npm 10+ installed
node --version  # Should be >= 20.0.0
npm --version   # Should be >= 10.0.0

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install
```

### Permission Denied

**Problem**: `.husky/pre-commit: Permission denied`

**Solution**:
```bash
# Make hook executable
chmod +x .husky/pre-commit

# Verify
ls -la .husky/pre-commit
# Should show: -rwxr-xr-x
```

## Best Practices

### 1. Commit Often, Small Changes

```bash
# ✅ Good - Small, focused commits
git add services/cert-lifecycle-manager/src/validator.ts
git commit -m "fix: improve certificate validation logic"

git add services/cert-lifecycle-manager/tests/validator.test.ts
git commit -m "test: add edge cases for validator"

# ❌ Bad - Large, unfocused commits
git add .
git commit -m "fix: various updates"
```

**Why**: Smaller commits = faster pre-commit checks

### 2. Fix Issues Immediately

```bash
# ❌ Bad - Skip and defer
git commit --no-verify -m "wip: will fix lint later"

# ✅ Good - Fix immediately
npm run lint:fix
git add .
git commit -m "fix: resolve linting issues"
```

### 3. Use Editor Integration

Install ESLint and Prettier extensions in your editor:

- **VS Code**: ESLint + Prettier extensions
- **IntelliJ/WebStorm**: Built-in support
- **Vim**: ALE or coc.nvim

Configure auto-fix on save:

```json
// .vscode/settings.json
{
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

### 4. Run Checks Before Push

```bash
# Before pushing, run full checks
npm run check:all

# If passing, push
git push origin feature-branch
```

## Configuration Files

### ESLint Configuration

**Location**: `.eslintrc.json`

```json
{
  "root": true,
  "parser": "@typescript-eslint/parser",
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended"
  ],
  "rules": {
    "@typescript-eslint/no-explicit-any": "error",
    "no-console": "warn"
  }
}
```

### Prettier Configuration

**Location**: `.prettierrc`

```json
{
  "semi": true,
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2
}
```

### lint-staged Configuration

**Location**: `.lintstagedrc.json`

```json
{
  "*.{ts,tsx}": [
    "eslint --fix --max-warnings=0",
    "prettier --write"
  ],
  "*.{json,md,yml,yaml}": [
    "prettier --write"
  ]
}
```

## Related Documentation

- **Development Standards**: @docs/DEVELOPMENT_STANDARDS.md - Code style guidelines
- **Architecture**: @docs/ARCHITECTURE.md - Service boundaries and patterns
- **Testing Requirements**: @docs/DEVELOPMENT_STANDARDS.md - Test coverage standards
- **CI/CD Pipeline**: @.github/workflows/ - Automated checks

## Support

**Common Issues**: Check troubleshooting section above
**Configuration Changes**: Consult team lead before modifying
**Questions**: Ask in #engineering Slack channel

---

**Version**: 1.0.0
**Last Updated**: 2025-11-14
**Owner**: Team 3 - External Integration & Compliance
