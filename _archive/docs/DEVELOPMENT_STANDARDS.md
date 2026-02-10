# Development Standards

## Core Principles

**"Created with utmost care, but not abundant"** - Every line serves a purpose.

### Development Philosophy
- **No speculative features** - Build what's needed now
- **No premature optimization** - Optimize after measurement
- **No clever code** - Clarity over brevity
- **No silent failures** - Explicit error handling everywhere
- **No magic numbers** - Constants are named and documented

---

## 1. Reliability Patterns (MANDATORY)

Every service MUST implement these patterns:

### 1.1 Idempotency
- All operations use idempotency keys
- Duplicate requests produce identical results
- No partial state mutations
- Use UUIDs or content-based hashing for keys

### 1.2 Circuit Breakers
- External API calls protected by circuit breakers
- Graceful degradation on dependency failures
- Health checks expose circuit states
- Default thresholds: 50% failure rate triggers open circuit

### 1.3 Retry with Exponential Backoff
- Transient failures automatically retried
- Max retry limits enforced (default: 3 retries)
- Jitter added to prevent thundering herd
- Backoff formula: `delay = base * (2^attempt) + random_jitter`

### 1.4 Structured Logging
- JSON-formatted logs (compatible with ELK/Loki)
- Request IDs propagated through entire call chain
- Error context captured (never swallow exceptions)
- Log levels: DEBUG, INFO, WARN, ERROR, FATAL

### 1.5 Distributed Tracing
- OpenTelemetry instrumentation required
- Every service operation creates spans
- Trace IDs link cross-service operations
- Attributes: service.name, service.version, environment

---

## 2. Testing Requirements

### Philosophy

This system handles legally binding financial documents with **zero error tolerance**. Basic tests prove code isn't broken - 100% coverage is the **bare minimum** for a system where failures result in:
- 66,360 EUR penalties for non-compliance
- Loss of VAT deduction rights
- 11-year audit liability
- Criminal prosecution for data destruction

Tests that merely prove "code reads CLI and writes to disk" are proof of non-garbage, not proof of correctness. We require **proof of correctness**.

### Coverage Requirements

**Minimum Coverage:** 100% (enforced in CI)

**Jest Configuration:**
```javascript
coverageThreshold: {
  global: {
    branches: 100,
    functions: 100,
    lines: 100,
    statements: 100
  }
}
```

**Pragmatic Exceptions:**
- Infrastructure modules (RabbitMQ consumers, service entry points) may be excluded
- Must be documented in `jest.config.js` with justification
- Core business logic always requires 100%

### Test Pyramid

- **Unit Tests:** 70% of test suite
  - Fast execution (<1ms per test)
  - Isolated (no I/O, no external dependencies)
  - Mock all boundaries
  - Test pure functions, business logic

- **Integration Tests:** 25% of test suite
  - Test service boundaries
  - Message contract verification
  - Database interactions
  - External API integration

- **E2E Tests:** 5% of test suite
  - Critical user journeys only
  - Full system flow validation
  - Run in staging environment

### Special Testing Techniques

**Chaos Testing:**
- Inject failures (network, CPU, disk) in staging
- Tools: Chaos Monkey, Gremlin
- Test circuit breaker behavior
- Verify graceful degradation

**Property-Based Testing:**
- For validators and transformers
- Use `fast-check` library
- Generate edge cases automatically
- Example: `fc.assert(fc.property(fc.string(), isValidOIB))`

**Contract Testing:**
- Use Pact/Pactflow for inter-service contracts
- Provider verifies consumer expectations
- Prevents breaking changes
- Run on every deploy

**Mutation Testing (Optional but Recommended):**
- Use Stryker to verify tests catch bugs
- Introduces code mutations
- Tests must fail on mutations
- Target: 80%+ mutation score

---

## 3. Code Style

### TypeScript
- Strict mode enabled (`strict: true`)
- No `any` types without explicit justification
- Functional components with hooks (React)
- Async/await over callbacks
- Named exports over default exports

### Linting
- ESLint with Airbnb config (modified)
- Prettier for formatting
- Pre-commit hooks enforce standards
- CI fails on lint errors

### Naming Conventions
- **Files:** `kebab-case.ts`
- **Classes:** `PascalCase`
- **Functions:** `camelCase`
- **Constants:** `SCREAMING_SNAKE_CASE`
- **Interfaces:** `PascalCase` (no `I` prefix)

---

## 4. Performance Standards

### Response Time SLAs
- Document upload: <200ms (p95)
- Validation pipeline: <5s (p99)
- XML generation: <1s (p95)
- FINA submission: <3s (p99)

### Resource Limits (per service)
- Memory: 512MB baseline (burst to 1GB)
- CPU: 0.5 cores baseline (burst to 2 cores)
- Disk I/O: 100 IOPS sustained

### Optimization Guidelines
- Profile before optimizing
- Use caching strategically (Redis)
- Lazy load heavy dependencies
- Stream large files (don't buffer)

---

## 5. Documentation Requirements

### Service README.md
Every service must have:
- Purpose and scope
- API contract (OpenAPI/gRPC spec)
- Dependencies (internal and external)
- Performance characteristics
- Failure modes and recovery
- Example usage

### Code Comments
- Document "why", not "what"
- Complex algorithms require explanation
- Public APIs require JSDoc
- TODO comments include ticket numbers

### Architecture Decision Records (ADRs)
- Major decisions documented in `docs/adr/`
- Format: Context, Decision, Consequences
- Immutable once accepted
- See ADR template in `docs/adr/template.md`

---

## 6. Git Workflow

### Commit Messages
Follow Conventional Commits format:
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `chore`
**Scope:** Service name (e.g., `email-worker`, `schema-validator`)

### Branch Strategy
- Trunk-Based Development
- `main` branch always deployable
- Feature branches max 2 days lifespan
- CI/CD on every commit to `main`

### Pull Request Standards
- Requires 1 approval
- All tests must pass
- Coverage must not decrease
- No merge conflicts
- Linear history (rebase, no merge commits)

---

## 7. Code Review Guidelines

### Reviewer Checklist
- [ ] Business logic is correct
- [ ] Error handling is comprehensive
- [ ] Tests cover edge cases
- [ ] Performance is acceptable
- [ ] Security vulnerabilities checked
- [ ] Documentation is updated
- [ ] No hardcoded secrets

### Red Flags (Auto-reject)
- Missing error handling
- Hardcoded credentials
- Synchronous blocking in async contexts
- Unbounded loops/recursion
- Missing input validation
- `any` types without justification

---

## Related Documentation

- **Security Standards:** @docs/SECURITY.md
- **Architecture Patterns:** @docs/ARCHITECTURE.md
- **Compliance Requirements:** @docs/COMPLIANCE_REQUIREMENTS.md
- **Testing Guide:** @docs/guides/testing-best-practices.md
- **TypeScript Standards:** @docs/guides/typescript-standards.md

---

**Last Updated:** 2025-11-12
**Document Owner:** Engineering Lead
**Review Cadence:** Quarterly
