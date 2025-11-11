# XSD Validator Tests

**Test Framework:** Jest with TypeScript
**Target Coverage:** 85% (branches, functions, lines, statements)

---

## Test Structure

```
tests/
├── setup.ts                          # Jest setup, environment configuration
├── fixtures/                         # Test data
│   ├── xml/                          # Sample XML files
│   │   ├── valid-invoice.xml         # Valid UBL 2.1 invoice
│   │   ├── invalid-invoice.xml       # Invalid invoice (missing required fields)
│   │   └── malformed.xml             # Malformed XML (parse error)
│   └── schemas/                      # Mock/test schemas (if needed)
├── unit/                             # Unit tests (fast, isolated)
│   ├── validator.test.ts             # Core validation logic tests
│   └── observability.test.ts        # Metrics, logging, tracing tests
└── integration/                      # Integration tests (slower, external dependencies)
    └── health-endpoints.test.ts      # HTTP health endpoints tests
```

---

## Running Tests

### All Tests
```bash
npm test
```

### Unit Tests Only
```bash
npm test -- tests/unit
```

### Integration Tests Only
```bash
npm test -- tests/integration
```

### Watch Mode (during development)
```bash
npm run test:watch
```

### Coverage Report
```bash
npm run test:coverage
```

Coverage report generated in `coverage/` directory.
Open `coverage/lcov-report/index.html` in browser for detailed view.

---

## Test Coverage

**Current Status:** (Run `npm run test:coverage` to see latest)

**Target Thresholds:**
- Branches: 85%
- Functions: 85%
- Lines: 85%
- Statements: 85%

**Coverage Breakdown:**

| File | Lines | Functions | Branches | Statements |
|------|-------|-----------|----------|------------|
| validator.ts | TBD% | TBD% | TBD% | TBD% |
| observability.ts | TBD% | TBD% | TBD% | TBD% |
| index.ts | TBD% | TBD% | TBD% | TBD% |

---

## Test Categories

### Unit Tests (validator.test.ts)

**What's Tested:**
- ✅ XSDValidator class instantiation
- ✅ Schema loading (success and error cases)
- ✅ XML validation (valid, invalid, malformed)
- ✅ Error handling (parse errors, validation errors)
- ✅ Security (XXE protection, billion laughs protection)
- ✅ Performance (validation speed)
- ✅ Edge cases (null input, empty input, large documents)

**Test Count:** 25+ tests

**Key Test Cases:**
1. Valid UBL 2.1 invoice → VALID status
2. Invalid invoice (missing fields) → INVALID status with detailed errors
3. Malformed XML → ERROR status with parse error
4. XXE attack attempt → Safely rejected
5. Billion laughs attack → Safely rejected
6. Large documents (1000+ elements) → Completes within 5s
7. Empty/null input → Graceful error handling
8. Line/column numbers in errors → Detailed error reporting

### Unit Tests (observability.test.ts)

**What's Tested:**
- ✅ Prometheus metrics (counters, histograms, gauges)
- ✅ OIB masking (PII protection per TODO-008)
- ✅ Logger functionality
- ✅ Tracer functionality (span creation, error handling)
- ✅ Metrics export format
- ✅ Concurrent metric updates

**Test Count:** 25+ tests

**Key Test Cases:**
1. OIB masking → All digits masked (`***********`)
2. Invalid OIB → Returns `INVALID_OIB`
3. Metrics collection → All metrics recorded correctly
4. Metrics export → Prometheus text format
5. Concurrent updates → No race conditions
6. Performance → Metrics collected in <100ms for 1000 operations

### Integration Tests (health-endpoints.test.ts)

**What's Tested:**
- ✅ `/health` endpoint (liveness probe)
- ✅ `/ready` endpoint (readiness probe)
- ✅ `/metrics` endpoint (Prometheus scraping)
- ✅ CORS headers
- ✅ Response times (<100ms)
- ✅ Concurrent requests (50+ simultaneous)
- ✅ Performance (100 requests/second)

**Test Count:** 15+ tests

**Key Test Cases:**
1. `/health` returns 200 + `{ status: 'ok' }`
2. `/ready` returns 200 when schemas loaded
3. `/ready` returns 503 when not ready
4. `/metrics` returns Prometheus format
5. 404 for unknown paths
6. Concurrent requests handled correctly
7. Performance target met (100 RPS)

---

## Test Fixtures

### XML Samples

**valid-invoice.xml**
- Minimal valid UBL 2.1 invoice
- Contains all required elements
- Used for "happy path" testing

**invalid-invoice.xml**
- Missing required elements (ID, IssueDate)
- Invalid date format
- Used for validation error testing

**malformed.xml**
- Unclosed XML tags
- Used for parse error testing

### Creating Additional Fixtures

```bash
cd tests/fixtures/xml
# Add new XML file
echo '<?xml version="1.0"?><Invoice>...</Invoice>' > new-test.xml
```

---

## Mocking Strategy

### What's Mocked:
- ❌ XML parsing (libxmljs2) → **NOT mocked** (use real library)
- ✅ RabbitMQ → **Mocked** (no real broker in tests)
- ✅ Jaeger → **Mocked** (no real trace collector)
- ❌ Prometheus → **NOT mocked** (use in-memory registry)

### Why Not Mock Everything:
- **Validator logic:** Real XML parsing ensures security protections work (XXE, billion laughs)
- **Observability:** Real Prometheus client ensures metrics format correct
- **RabbitMQ:** Mocked to avoid external dependency (integration tests use Testcontainers in CI)

---

## CI/CD Integration

### GitHub Actions Workflow

```yaml
- name: Run Tests
  run: npm test

- name: Check Coverage
  run: npm run test:coverage

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage/lcov.info
```

### Required Actions:
1. Tests must pass (exit code 0)
2. Coverage must meet 85% threshold
3. No flaky tests (tests must be deterministic)

---

## Writing New Tests

### Test Template

```typescript
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';

describe('Feature Name', () => {
  beforeAll(async () => {
    // Setup (runs once before all tests in this describe block)
  });

  afterAll(async () => {
    // Cleanup (runs once after all tests)
  });

  describe('Specific Function', () => {
    it('should do something specific', () => {
      // Arrange
      const input = 'test';

      // Act
      const result = functionUnderTest(input);

      // Assert
      expect(result).toBe('expected');
    });
  });
});
```

### Best Practices:
1. **One assertion per test** (or closely related assertions)
2. **Descriptive test names** (should read like documentation)
3. **Arrange-Act-Assert pattern**
4. **Independent tests** (no shared state between tests)
5. **Fast tests** (unit tests <10ms, integration tests <1s)
6. **Deterministic tests** (no randomness, no flakiness)

---

## Troubleshooting

### Tests Failing Locally

**Problem:** Tests fail on your machine but pass in CI

**Solutions:**
1. Check Node.js version (must be 20+)
2. Clear Jest cache: `npx jest --clearCache`
3. Reinstall dependencies: `rm -rf node_modules && npm install`
4. Check environment variables in `.env`

### Low Coverage

**Problem:** Coverage below 85% threshold

**Solutions:**
1. Run coverage report: `npm run test:coverage`
2. Open HTML report: `open coverage/lcov-report/index.html`
3. Identify uncovered lines (highlighted in red)
4. Add tests for uncovered code paths

### Slow Tests

**Problem:** Tests take too long (>30s for unit tests)

**Solutions:**
1. Check for network calls (should be mocked)
2. Check for large loops (should use smaller test data)
3. Run specific test file: `npm test -- validator.test.ts`
4. Use `--maxWorkers=1` for debugging: `npm test -- --maxWorkers=1`

### Flaky Tests

**Problem:** Tests pass sometimes, fail other times

**Solutions:**
1. Check for race conditions (use `await` properly)
2. Check for shared state (reset between tests)
3. Check for timing dependencies (avoid hardcoded timeouts)
4. Check for random data (use deterministic fixtures)

---

## Performance Benchmarks

**Unit Test Suite:**
- **Target:** <5 seconds total
- **Actual:** TBD (run `npm test -- tests/unit`)

**Integration Test Suite:**
- **Target:** <10 seconds total
- **Actual:** TBD (run `npm test -- tests/integration`)

**Full Test Suite:**
- **Target:** <15 seconds total
- **Actual:** TBD (run `npm test`)

---

## Security Testing

**Tested Attack Vectors:**
- ✅ XXE (XML External Entity) attacks
- ✅ Billion Laughs (exponential entity expansion)
- ✅ Large document DoS (1000+ elements)
- ✅ Null/empty input
- ✅ PII leakage (OIB masking verified)

**Not Tested (requires manual penetration testing):**
- ❌ Network-level attacks (DDoS, SYN floods)
- ❌ Container escape
- ❌ Privilege escalation
- ❌ Side-channel attacks

---

**Last Updated:** 2025-11-10
**Maintainer:** eRacun Development Team
