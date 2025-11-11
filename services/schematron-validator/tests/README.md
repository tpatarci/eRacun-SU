# Schematron Validator - Test Suite

Comprehensive test suite for the schematron-validator service ensuring **85%+ code coverage** and production-grade quality.

---

## Test Structure

```
tests/
├── setup.ts                      # Global test configuration
├── fixtures/                     # Test data
│   ├── schematron-rules/         # Minimal Schematron rules for testing
│   │   └── cius-hr-core.sch      # Croatian CIUS subset (BR-S, BR-HR, BR-E, BR-CO)
│   └── invoices/                 # Sample XML invoices
│       ├── valid-cius-hr.xml     # Valid Croatian invoice
│       ├── invalid-vat-rate.xml  # Fails BR-S-01 (VAT rate validation)
│       ├── invalid-oib.xml       # Fails BR-HR-01 (OIB length validation)
│       └── missing-required-fields.xml  # Fails BR-CO-01, BR-CO-02
├── unit/                         # Unit tests (fast, isolated)
│   ├── validator.test.ts         # SchematronValidator class (60+ tests)
│   └── observability.test.ts     # Metrics, logging, tracing, PII masking (60+ tests)
└── integration/                  # Integration tests (service boundaries)
    └── health-endpoints.test.ts  # HTTP endpoints (/health, /ready, /metrics)
```

---

## Running Tests

### All Tests

```bash
npm test
```

### Watch Mode (Development)

```bash
npm run test:watch
```

### Coverage Report

```bash
npm run test:coverage
```

**Coverage Threshold:** 85% (branches, functions, lines, statements)

---

## Test Categories

### Unit Tests (120+ tests)

#### `validator.test.ts` (60+ tests)

**Rule Loading:**
- ✅ Load Croatian CIUS core rules successfully
- ✅ Cache loaded rules
- ✅ No reload for cached rules
- ✅ Error handling for non-existent rule sets
- ✅ Cache clearing (individual and all)

**Valid Document Validation:**
- ✅ Validate valid Croatian CIUS invoice
- ✅ Accept Buffer input
- ✅ Accept string input
- ✅ Return validation time in milliseconds

**Invalid Document Validation:**
- ✅ Detect invalid VAT rate (BR-S-01)
- ✅ Detect invalid OIB length (BR-HR-01)
- ✅ Detect missing required fields (BR-CO-01, BR-CO-02)
- ✅ Include error location (XPath)
- ✅ Return multiple errors for multiple violations

**Error Handling:**
- ✅ Handle malformed XML gracefully
- ✅ Handle empty XML
- ✅ Handle null input
- ✅ Handle very large XML documents

**Performance:**
- ✅ Validate small documents quickly (<1s)
- ✅ Benefit from rule caching (second validation faster)
- ✅ Handle concurrent validations
- ✅ Process 10 validations in reasonable time (<10s)

**Cache Management:**
- ✅ Track cache size in bytes
- ✅ Track rule count
- ✅ Track load timestamp

**Edge Cases:**
- ✅ Handle XML with special characters
- ✅ Handle XML with Unicode characters (Croatian: Š, Č, Ž, Đ)
- ✅ Idempotent (same input always produces same output)

#### `observability.test.ts` (60+ tests)

**PII Masking:**
- ✅ Mask valid 11-digit OIB → `***********`
- ✅ Mask different OIB values consistently
- ✅ No digit leakage from OIB
- ✅ Handle invalid OIB gracefully
- ✅ Mask valid Croatian IBAN → `HR** **** **** **** ****`
- ✅ Preserve country code (HR)
- ✅ Mask check digits
- ✅ Mask valid Croatian VAT → `HR***********`
- ✅ Mask multiple PII values in same text
- ✅ Handle text without PII
- ✅ Handle null/undefined/empty gracefully

**Prometheus Metrics:**
- ✅ Export validationTotal counter
- ✅ Export validationDuration histogram
- ✅ Export rulesCheckedHistogram
- ✅ Export rulesFailedHistogram
- ✅ Export rulesLoaded gauge
- ✅ Export errorsByRule counter
- ✅ Export warningsByRule counter
- ✅ Export ruleCacheSize gauge
- ✅ Export xsltCompilationTime histogram
- ✅ Increment counters correctly
- ✅ Handle concurrent metric updates
- ✅ Format metrics in Prometheus format
- ✅ Correct metric types (counter, histogram, gauge)

**Structured Logging:**
- ✅ Export logger instance
- ✅ Correct logger name (schematron-validator)
- ✅ Service field in base bindings
- ✅ Version field in base bindings
- ✅ Environment field in base bindings

**Distributed Tracing:**
- ✅ Create span with name
- ✅ Create span with attributes
- ✅ Record exceptions
- ✅ Set span status
- ✅ Create multiple spans concurrently

**Performance:**
- ✅ Mask OIB quickly (<1ms per operation)
- ✅ Record metrics quickly (<1ms per operation)
- ✅ Create spans quickly (<1ms per operation)

### Integration Tests (50+ tests)

#### `health-endpoints.test.ts` (50+ tests)

**GET /health (Liveness):**
- ✅ Return 200 OK when service is running
- ✅ Return JSON content type
- ✅ Include CORS headers
- ✅ Respond quickly (<100ms)
- ✅ Handle concurrent requests (50+)
- ✅ Handle OPTIONS preflight request

**GET /ready (Readiness):**
- ✅ Return 200 OK when service is ready
- ✅ Return 503 Service Unavailable when not ready
- ✅ Return JSON content type
- ✅ Include CORS headers
- ✅ Check RabbitMQ connection
- ✅ Check if rules are loaded
- ✅ Respond quickly (<100ms)

**GET /metrics (Prometheus):**
- ✅ Return Prometheus metrics format
- ✅ Return text/plain content type
- ✅ Include all defined metrics (9 metrics)
- ✅ Return 404 for non-metrics endpoints
- ✅ Handle concurrent metrics requests (100+)
- ✅ Respond quickly (<100ms)

**Performance:**
- ✅ Handle 100 requests per second to /health
- ✅ Handle 100 requests per second to /ready
- ✅ Handle 50 requests per second to /metrics
- ✅ Maintain low latency under load (<10ms avg, <50ms p95)

**Error Handling:**
- ✅ Return 404 for unknown endpoints
- ✅ Handle POST requests gracefully
- ✅ Handle malformed requests gracefully

**Port Configuration:**
- ✅ Use correct HTTP port from environment
- ✅ Use correct metrics port from environment
- ✅ Use different ports for HTTP and metrics

---

## Test Fixtures

### Schematron Rules

**`cius-hr-core.sch`** - Minimal Croatian CIUS rules for testing:

- **BR-S-01:** VAT rate MUST be 25% when category code is 'S' (standard rate)
- **BR-S-02:** VAT rate MUST be 13% or 5% when category code is 'R' (reduced rate)
- **BR-S-03:** VAT rate MUST be 0% when category code is 'Z' (zero rate)
- **BR-HR-01:** Supplier OIB MUST be exactly 11 digits
- **BR-HR-02:** Invoice currency MUST be EUR or HRK
- **BR-E-01:** Invoice MUST contain payable amount
- **BR-CO-01:** Invoice ID is MANDATORY
- **BR-CO-02:** Issue date is MANDATORY
- **BR-CO-03:** Supplier party is MANDATORY
- **BR-W-01:** Consider setting payment due date within 90 days (warning)

⚠️ **WARNING:** These are SIMPLIFIED rules for testing only. Production MUST use official Croatian CIUS rules from Porezna Uprava.

### Invoice Fixtures

**`valid-cius-hr.xml`**
- Passes all validation rules
- Standard VAT rate (25%)
- Valid 11-digit OIB
- EUR currency
- All required fields present

**`invalid-vat-rate.xml`**
- **Fails BR-S-01:** VAT rate is 20% instead of 25%
- Used to test error detection

**`invalid-oib.xml`**
- **Fails BR-HR-01:** OIB is 9 digits instead of 11
- Used to test OIB validation

**`missing-required-fields.xml`**
- **Fails BR-CO-01:** Missing Invoice ID
- **Fails BR-CO-02:** Missing Issue date
- Used to test cardinality validation

---

## Coverage Report

After running `npm run test:coverage`, open:

```bash
open coverage/lcov-report/index.html
```

**Expected Coverage:**
- **Branches:** ≥85%
- **Functions:** ≥85%
- **Lines:** ≥85%
- **Statements:** ≥85%

---

## Testing Best Practices

### Writing New Tests

1. **Follow AAA Pattern:**
   ```typescript
   it('should validate valid invoice', async () => {
     // Arrange
     const xml = await readFile('./fixtures/valid-cius-hr.xml', 'utf-8');

     // Act
     const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

     // Assert
     expect(result.status).toBe(ValidationStatus.VALID);
   });
   ```

2. **Use Descriptive Test Names:**
   - ✅ `should detect invalid VAT rate (BR-S-01)`
   - ❌ `test1`

3. **Test One Thing Per Test:**
   - Each test should verify a single behavior
   - Use `describe` blocks to group related tests

4. **Use Fixtures for Test Data:**
   - Store XML fixtures in `tests/fixtures/`
   - Don't inline large XML strings in tests

5. **Mock External Dependencies:**
   - RabbitMQ connections
   - Jaeger tracing
   - External API calls

### Performance Testing

- Test performance expectations explicitly
- Use `Date.now()` for timing
- Set reasonable thresholds (e.g., <1s for small documents)

### Security Testing

- Test PII masking thoroughly
- Test input validation (XXE, size limits)
- Test error handling (no information leakage)

---

## Continuous Integration

Tests run automatically on:
- Every commit to main branch
- Every pull request
- Every tag (release)

**CI Requirements:**
- ✅ All tests pass
- ✅ 85%+ coverage in all categories
- ✅ No console warnings or errors
- ✅ Build succeeds

---

## Troubleshooting

### Tests Failing Locally

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Check Node.js version:**
   ```bash
   node --version  # Should be v20+
   ```

3. **Clear Jest cache:**
   ```bash
   npm test -- --clearCache
   ```

### Coverage Below Threshold

1. **Identify uncovered lines:**
   ```bash
   npm run test:coverage
   open coverage/lcov-report/index.html
   ```

2. **Add tests for uncovered code:**
   - Focus on branches and error paths
   - Add edge case tests

### Slow Tests

1. **Run only unit tests:**
   ```bash
   npm test tests/unit/
   ```

2. **Run specific test file:**
   ```bash
   npm test tests/unit/validator.test.ts
   ```

---

## Test Maintenance

### Adding New Schematron Rules

1. Add rule to `tests/fixtures/schematron-rules/cius-hr-core.sch`
2. Create fixture invoices (valid and invalid)
3. Add test cases in `validator.test.ts`
4. Update this README

### Updating Test Fixtures

When Croatian CIUS rules are officially published:
1. Download official rules from Porezna Uprava
2. Update `cius-hr-core.sch` or create new file
3. Verify all tests still pass
4. Update fixture invoices if needed

---

## References

- **Jest Documentation:** https://jestjs.io/
- **Schematron Standard:** ISO/IEC 19757-3:2016
- **Croatian CIUS:** (pending publication - 2026-01-01)
- **EN 16931-1:2017:** European e-invoicing semantic model

---

**Last Updated:** 2025-11-11
**Test Suite Version:** 1.0.0
**Total Tests:** 120+ tests
**Coverage Target:** 85%+
