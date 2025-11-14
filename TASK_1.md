# TASK 1: Test Coverage Audit

## Task Priority
**CRITICAL** - Legal compliance system requires 100% test coverage for core business logic

## Objective
Conduct a comprehensive audit to verify that all services meet the mandatory 100% test coverage requirement for core business logic, as failures could result in €66,360 penalties, VAT deduction loss, and criminal liability.

## Scope
Full project-wide test coverage analysis across all microservices, with special focus on:
- Invoice validation logic
- FINA integration components
- XML processing and security
- Financial calculations and VAT handling
- Compliance validation layers

## Detailed Approach

### 1. Coverage Measurement (Day 1)
**Execute coverage analysis for each service:**
```bash
# Run from project root
for service in services/*/; do
  echo "=== Testing ${service} ==="
  cd "${service}"
  npm test -- --coverage --coverageReporters=json-summary text
  cd ../..
done
```

**Generate consolidated report:**
```bash
# Create aggregate coverage report
npm run coverage:report
```

### 2. Core Business Logic Verification (Day 1-2)
**Identify and verify critical paths:**
- [ ] Invoice validation (all 6 layers)
- [ ] OIB number validation
- [ ] KPD classification validation
- [ ] VAT calculations (25%, 13%, 5%, 0%)
- [ ] Digital signature verification (XMLDSig)
- [ ] Qualified timestamp validation
- [ ] UBL 2.1 transformation logic
- [ ] Croatian CIUS business rules
- [ ] Error handling and circuit breakers
- [ ] Idempotency key handling

### 3. Infrastructure Exemption Review (Day 2)
**Verify documented exemptions are valid:**
- Check `jest.config.js` for excluded patterns
- Ensure only infrastructure code is excluded:
  - RabbitMQ consumers
  - Service entry points
  - systemd integration code
- Confirm each exemption has justification documented

### 4. Test Quality Assessment (Day 2-3)
**Evaluate test effectiveness:**
- [ ] Run mutation testing with Stryker
- [ ] Target: 80%+ mutation score for critical modules
- [ ] Review test assertions (no empty tests)
- [ ] Check for proper mocking boundaries
- [ ] Verify error path testing
- [ ] Confirm edge case coverage

### 5. Integration Test Coverage (Day 3)
**Verify service boundary testing:**
- [ ] Message contract tests (Pact)
- [ ] Database transaction tests
- [ ] External API mock coverage
- [ ] Circuit breaker failure scenarios
- [ ] Retry logic verification

## Required Tools
- Jest with coverage reporters
- Stryker for mutation testing
- nyc for coverage aggregation
- Coverage threshold validator

## Pass/Fail Criteria

### MUST PASS (Non-negotiable)
- ✅ 100% statement coverage for core business logic
- ✅ 100% branch coverage for validation modules
- ✅ 100% function coverage for financial calculations
- ✅ All infrastructure exemptions documented with justification
- ✅ Mutation score >80% for critical paths

### RED FLAGS (Immediate escalation)
- ❌ Any uncovered validation logic
- ❌ Missing tests for error paths
- ❌ Undocumented coverage exemptions
- ❌ Tests without assertions
- ❌ Disabled or skipped tests in production code

## Deliverables
1. **Coverage Report Dashboard** - HTML report showing all services
2. **Gap Analysis Document** - List of uncovered critical paths
3. **Risk Assessment** - Impact analysis of any coverage gaps
4. **Remediation Plan** - Timeline to achieve 100% coverage
5. **Test Quality Metrics** - Mutation testing results

## Time Estimate
- **Duration:** 3 days
- **Effort:** 1 senior engineer
- **Prerequisites:** All services must be buildable

## Risk Factors
- **High Risk:** Financial calculation modules below 100%
- **High Risk:** Validation layers with coverage gaps
- **Medium Risk:** Integration points not fully tested
- **Low Risk:** UI components with lower coverage

## Escalation Path
If coverage is below 100% for core business logic:
1. Immediate notification to Engineering Lead
2. Create P0 PENDING items for gaps
3. Block all deployments until resolved
4. Daily status updates until 100% achieved

## Related Documentation
- @docs/DEVELOPMENT_STANDARDS.md (Section 2: Testing Requirements)
- @docs/guides/testing-best-practices.md
- jest.config.js files in each service

## Audit Checklist
- [ ] All services have jest.config.js with coverage thresholds
- [ ] Coverage thresholds set to 100% for branches, functions, lines, statements
- [ ] npm test command includes coverage flags
- [ ] CI/CD pipeline fails on coverage drop
- [ ] Coverage reports archived for compliance audit
- [ ] Mutation testing configured for critical modules
- [ ] Contract tests implemented for all service boundaries
- [ ] E2E tests cover critical user journeys
- [ ] Chaos testing results documented
- [ ] Property-based tests for validators

## Notes
This audit is **mandatory** before January 1, 2026 go-live. Non-compliance with test coverage requirements could result in undetected bugs leading to regulatory violations and severe financial penalties.