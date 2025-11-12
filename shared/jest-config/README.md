# Shared Jest Configuration

**Purpose:** Enforce 100% test coverage across all eRacun services

---

## Why 100% Coverage?

This system handles legally binding financial documents where failures result in:
- **66,360 EUR penalties** for non-compliance
- **Loss of VAT deduction rights** (retroactive tax liability)
- **11-year audit liability** (criminal prosecution for data destruction)
- **Zero error tolerance** (Croatian Tax Authority rejects invalid invoices)

Basic tests prove code isn't broken. **100% coverage is the bare minimum** for proof of correctness.

---

## Usage

### 1. In Your Service's `jest.config.js`

```javascript
const baseConfig = require('../../shared/jest-config/base.config.js');

module.exports = {
  ...baseConfig,
  // Service-specific overrides (if needed)
  displayName: 'oib-validator',
};
```

### 2. In Your Service's `package.json`

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:ci": "jest --coverage --ci --maxWorkers=2"
  },
  "devDependencies": {
    "@types/jest": "^29.5.11",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.1"
  }
}
```

### 3. Create `tests/setup.ts` (Optional)

If you need global test setup (e.g., environment variables):

```typescript
// tests/setup.ts
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent'; // Suppress logs in tests
```

---

## Coverage Enforcement

The configuration enforces 100% coverage on:
- ✅ **Branches:** All if/else, switch, ternary paths
- ✅ **Functions:** Every function called at least once
- ✅ **Lines:** Every line executed
- ✅ **Statements:** Every statement executed

### Excluded from Coverage:
- Type definition files (`.d.ts`)
- Entry point files (`index.ts`) - often just wiring
- Interface files (`.interface.ts`)
- Type files (`.type.ts`)

If you need to exclude additional files, add to `collectCoverageFrom` in your service's config.

---

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run tests with 100% coverage
  run: npm run test:ci

- name: Verify coverage threshold
  run: |
    COVERAGE=$(cat coverage/coverage-summary.json | jq '.total.lines.pct')
    if [ "$COVERAGE" != "100" ]; then
      echo "Coverage is $COVERAGE%, expected 100%"
      exit 1
    fi
```

### GitLab CI Example

```yaml
test:
  script:
    - npm install
    - npm run test:ci
  coverage: '/Lines\s*:\s*(\d+\.?\d*)%/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml
```

---

## Writing Tests to Reach 100%

### 1. Test All Branches

```typescript
// src/validator.ts
export function validateOIB(oib: string): boolean {
  if (!oib) return false;        // Test: empty string
  if (oib.length !== 11) return false;  // Test: wrong length
  if (!/^\d+$/.test(oib)) return false; // Test: non-numeric
  return checksum(oib);          // Test: valid + invalid checksum
}

// tests/validator.test.ts
describe('validateOIB', () => {
  it('rejects empty string', () => {
    expect(validateOIB('')).toBe(false);
  });

  it('rejects wrong length', () => {
    expect(validateOIB('123')).toBe(false);
  });

  it('rejects non-numeric', () => {
    expect(validateOIB('1234567890A')).toBe(false);
  });

  it('rejects invalid checksum', () => {
    expect(validateOIB('12345678901')).toBe(false);
  });

  it('accepts valid OIB', () => {
    expect(validateOIB('12345678903')).toBe(true);
  });
});
```

### 2. Test Error Paths

```typescript
// Test both success and failure
it('handles database connection failure', async () => {
  mockDb.connect.mockRejectedValue(new Error('Connection refused'));
  await expect(service.start()).rejects.toThrow('Connection refused');
});

it('handles successful database connection', async () => {
  mockDb.connect.mockResolvedValue(true);
  await expect(service.start()).resolves.not.toThrow();
});
```

### 3. Test All Function Parameters

```typescript
// Test boundary conditions
it('handles minimum value', () => {
  expect(calculate(0)).toBe(0);
});

it('handles maximum value', () => {
  expect(calculate(Number.MAX_SAFE_INTEGER)).toBeLessThan(Infinity);
});

it('handles negative values', () => {
  expect(calculate(-1)).toBe(0);
});
```

---

## Property-Based Testing (Recommended)

For validators and transformers, use `fast-check` for exhaustive testing:

```typescript
import fc from 'fast-check';

describe('validateOIB property-based tests', () => {
  it('always rejects OIBs with wrong length', () => {
    fc.assert(
      fc.property(
        fc.string().filter(s => s.length !== 11),
        (oib) => !validateOIB(oib)
      )
    );
  });

  it('always rejects non-numeric strings', () => {
    fc.assert(
      fc.property(
        fc.string().filter(s => /[^0-9]/.test(s)),
        (oib) => !validateOIB(oib)
      )
    );
  });
});
```

---

## Mutation Testing (Optional)

Verify your tests actually catch bugs using Stryker:

```bash
npm install --save-dev @stryker-mutator/core @stryker-mutator/jest-runner
npx stryker run
```

Mutation testing changes your code (e.g., `>` to `>=`) and checks if tests fail. If tests still pass, your tests aren't thorough enough.

---

## Troubleshooting

### "Coverage threshold not met"

```
ERROR: Coverage for lines (98.5%) does not meet global threshold (100%)
```

**Solution:** Run coverage report to see uncovered lines:
```bash
npm run test:coverage
open coverage/index.html  # View HTML report
```

Red lines = not covered. Write tests to execute those lines.

### "Cannot find module './setup'"

**Solution:** Create `tests/setup.ts` (can be empty):
```bash
mkdir -p tests
touch tests/setup.ts
```

Or remove `setupFilesAfterEnv` from your `jest.config.js`.

### "Tests are too slow"

**Solution:**
1. Reduce `maxWorkers` in CI: `jest --maxWorkers=2`
2. Use `--onlyChanged` during development: `jest --watch --onlyChanged`
3. Split large test suites into smaller files

---

## Examples

See existing services for reference:
- `services/cert-lifecycle-manager/` - 98% coverage (target: 100%)
- `services/fina-connector/` - Full test suite with mocks
- `services/xsd-validator/` - Schema validation tests

---

**Last Updated:** 2025-11-12
**Owner:** Technical Lead
**Questions:** See CLAUDE.md section 3.3
