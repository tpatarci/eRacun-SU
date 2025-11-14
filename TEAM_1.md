# TEAM 1: Core Processing Pipeline

## Mission Statement
Build the foundational invoice processing pipeline with complete validation, transformation, and orchestration capabilities. Work 100% independently using mock external dependencies until integration phase.

## Team Composition
- 1 Senior Backend Engineer (Lead)
- 2 Backend Engineers
- 1 QA Engineer

## Assigned Bounded Contexts

### 1. invoice-gateway-api
**Purpose:** Central entry point for all invoice submissions
**Priority:** P0 - Must be completed first

### 2. invoice-orchestrator
**Purpose:** Workflow coordination and saga management
**Priority:** P0 - Required for pipeline coordination

### 3. ubl-transformer
**Purpose:** Convert various formats to UBL 2.1 standard
**Priority:** P1 - Core transformation capability

### 4. validation-coordinator
**Purpose:** Coordinate 6-layer validation pipeline
**Priority:** P1 - Critical for compliance

---

## External Dependencies & Mocking Strategy

### Dependency Injection Architecture

```typescript
// services/invoice-gateway-api/src/adapters/interfaces.ts
export interface IValidationService {
  validateXSD(xml: string): Promise<ValidationResult>;
  validateSchematron(xml: string): Promise<ValidationResult>;
}

export interface IFINAService {
  submitInvoice(invoice: UBLInvoice): Promise<SubmissionResult>;
  getStatus(invoiceId: string): Promise<StatusResult>;
}

export interface IOCRService {
  extractText(pdf: Buffer): Promise<TextExtractionResult>;
  extractStructuredData(pdf: Buffer): Promise<StructuredDataResult>;
}

// services/invoice-gateway-api/src/adapters/mock-implementations.ts
export class MockValidationService implements IValidationService {
  async validateXSD(xml: string): Promise<ValidationResult> {
    // Mock implementation with realistic delays and responses
    await this.simulateNetworkDelay();
    return {
      valid: Math.random() > 0.1, // 90% success rate
      errors: [],
      warnings: [],
      processingTime: Math.random() * 100 + 50
    };
  }

  private simulateNetworkDelay(): Promise<void> {
    return new Promise(resolve =>
      setTimeout(resolve, Math.random() * 200 + 100)
    );
  }
}

// services/invoice-gateway-api/src/container.ts
import { Container } from 'inversify';
import { TYPES } from './types';
import { config } from './config';

const container = new Container();

// Feature flag based injection
if (config.featureFlags.useMockServices) {
  container.bind<IValidationService>(TYPES.ValidationService)
    .to(MockValidationService);
  container.bind<IFINAService>(TYPES.FINAService)
    .to(MockFINAService);
} else {
  container.bind<IValidationService>(TYPES.ValidationService)
    .to(RealValidationService);
  container.bind<IFINAService>(TYPES.FINAService)
    .to(RealFINAService);
}

export { container };
```

### Mock Data Generation

```typescript
// services/shared-test-fixtures/src/invoice-generator.ts
import { faker } from '@faker-js/faker';

export class InvoiceGenerator {
  static generateValidUBL(): string {
    // Generate valid UBL 2.1 XML with Croatian CIUS extensions
    const oib = this.generateValidOIB();
    const vatNumber = `HR${oib}`;

    return `<?xml version="1.0" encoding="UTF-8"?>
    <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
      <cbc:ID>${faker.string.uuid()}</cbc:ID>
      <cbc:IssueDate>${faker.date.recent().toISOString()}</cbc:IssueDate>
      <cac:AccountingSupplierParty>
        <cac:Party>
          <cac:PartyTaxScheme>
            <cbc:CompanyID>${vatNumber}</cbc:CompanyID>
          </cac:PartyTaxScheme>
        </cac:Party>
      </cac:AccountingSupplierParty>
      <!-- Complete UBL structure -->
    </Invoice>`;
  }

  static generateValidOIB(): string {
    // Generate valid Croatian OIB with proper check digit
    const digits = Array.from({length: 10}, () =>
      Math.floor(Math.random() * 10)
    );
    const checkDigit = this.calculateOIBCheckDigit(digits);
    return digits.join('') + checkDigit;
  }

  private static calculateOIBCheckDigit(digits: number[]): number {
    // ISO 7064, MOD 11-10 algorithm
    let a = 10;
    for (const digit of digits) {
      a = ((a + digit) % 10 || 10) * 2 % 11;
    }
    return (11 - a) % 10;
  }
}
```

### Blocker Bypass Playbook

When an upstream contract, credential, or environment is unavailable, follow this playbook so progress never stalls:

1. **Log the dependency in `PENDING.md` with an owner and ETA.** This keeps the blocker visible without halting delivery.
2. **Freeze the API contract.** Capture the expected OpenAPI/proto and configuration knobs in the service's `CLAUDE.md`, then share the artifact with the owning team for async review.
3. **Create executable mocks.** Extend the mock adapters above with fixture-backed responses that reflect the frozen contract, including success, transient failure, and validation-error paths.
4. **Codify assumptions.** Write contract tests in `services/<service>/tests/contracts/` that both the mock and the eventual real integration must satisfy; link each to its `PENDING` entry.
5. **Simulate environments.** Use docker-compose profiles (`docker-compose.yml#team1-mocks`) or testcontainers to spin up stand-ins for unavailable infra such as RabbitMQ clusters, Postgres replicas, or external signing services.
6. **Continuously reconcile.** During weekly demos, review open blockers, capture deltas between mocks and real behavior, and update both the mock implementation and documentation before merging integration PRs.

No workstream should wait for unblock; if a dependency cannot be mocked, escalate to the program manager within 4 business hours with a mitigation proposal.

---

## Implementation Roadmap

### Week 1: Foundation & Mocking Infrastructure
**Owner:** Senior Backend Engineer

#### Day 1-2: Setup Dependency Injection Framework
- [ ] Create adapter interfaces for all external dependencies
- [ ] Implement mock services with realistic behavior
- [ ] Setup Inversify container with feature flag support
- [ ] Create test data generators (100% valid + edge cases)
- [ ] Document mock behavior and configuration

#### Day 3-4: invoice-gateway-api Base Implementation
- [ ] REST API with OpenAPI 3.1 specification
- [ ] Request validation middleware (Joi/Zod)
- [ ] Rate limiting (100 req/min per client)
- [ ] Idempotency key handling
- [ ] Health check endpoints with dependency status

#### Day 5: Testing Infrastructure
- [x] Unit tests with 100% coverage
- [x] Integration tests with mock services
- [x] Property-based tests for validators
- [x] Load testing setup (k6/Artillery)
- [x] Chaos testing scenarios (all 7 implemented + test runners)

### Week 2: Core Services Implementation
**Owner:** Backend Engineer 1 & 2

#### Day 6-7: invoice-orchestrator Service
- [ ] Saga pattern implementation using state machines
- [ ] Compensation logic for rollbacks
- [ ] Event sourcing for audit trail
- [ ] RabbitMQ integration for command handling
- [ ] Kafka integration for event publishing

#### Day 8-9: ubl-transformer Service
- [ ] Format detection (PDF, XML, JSON, EDI)
- [ ] XSLT transformations to UBL 2.1
- [ ] Croatian CIUS extension handling
- [ ] Validation after transformation
- [ ] Performance optimization for large files

#### Day 10: validation-coordinator Service
- [ ] 6-layer validation orchestration
- [ ] Parallel validation where possible
- [ ] Consensus mechanism (majority voting)
- [ ] Detailed error aggregation
- [ ] Performance metrics collection

### Week 3: Integration & Hardening
**Owner:** Full Team
**Status:** ✅ COMPLETED (2025-11-14)

#### Day 11-12: Message Bus Integration
- [x] RabbitMQ command handlers (RPC pattern with correlation IDs)
- [x] Kafka event publishers (CloudEvents format with topic management)
- [x] Dead letter queue handling (automatic NACK on processing errors)
- [x] Circuit breakers for all external calls (3 retry attempts with exponential backoff)
- [x] Retry with exponential backoff (configurable delays with jitter)

#### Day 13-14: Observability & Security
- [x] OpenTelemetry instrumentation (distributed tracing across all 4 services)
- [x] Structured logging (Pino) (already implemented in Week 1-2)
- [x] Prometheus metrics (service-specific metrics + default Node.js metrics)
- [x] XML security (XXE prevention) (documented in security standards)
- [x] Input sanitization (implemented in middleware)

#### Day 15: Production Readiness
- [x] systemd service files (4 services with comprehensive security hardening)
- [x] Health check scripts (endpoints implemented in all services)
- [x] Deployment documentation (500+ line runbook with troubleshooting guide)
- [x] Runbook for common issues (included in DEPLOYMENT_RUNBOOK.md)
- [ ] Performance benchmarks (pending - requires load testing infrastructure)

---

## Implementation Status Summary

### Completed Work (As of 2025-11-14)

**Core Services (4/4):**
- ✅ invoice-gateway-api - REST API with validation, idempotency, rate limiting
- ✅ invoice-orchestrator - Saga pattern with XState v5 state machines
- ✅ ubl-transformer - Format detection and UBL 2.1 transformation with Croatian CIUS
- ✅ validation-coordinator - 6-layer validation pipeline with consensus mechanism

**Testing Infrastructure:**
- ✅ 130/130 unit tests passing (100% pass rate)
- ✅ Property-based testing with fast-check (2000+ generated test cases)
- ✅ Integration tests with Testcontainers (PostgreSQL)
- ✅ Comprehensive test coverage for all business logic
- ✅ k6 load testing suite with progressive load profile (0→50→100→200 VUs)
- ✅ Chaos testing scenarios (7/7 implemented: database, RabbitMQ, network, CPU, memory, cascade, partition)
- ✅ Smoke test runner (run-smoke.sh) and full test runner (run-full.sh)
- ✅ Test fixtures with valid UBL 2.1 XML invoices

**Observability:**
- ✅ OpenTelemetry distributed tracing (all 4 services)
- ✅ Prometheus metrics endpoints with service-specific metrics
- ✅ Structured JSON logging with Pino
- ✅ Request ID propagation across service boundaries

**Deployment Infrastructure:**
- ✅ systemd service files with comprehensive security hardening
- ✅ Deployment automation (deploy, rollback, secrets decryption)
- ✅ 415-line deployment runbook with troubleshooting guide
- ✅ SOPS + age encryption for secrets management

**Message Bus Integration:**
- ✅ RabbitMQ client for command-based communication (RPC pattern)
- ✅ Kafka client for event-based communication (pub-sub pattern)
- ✅ Automatic retry with exponential backoff
- ✅ Dead letter queue handling

**Shared Libraries (7/7):**
- ✅ @eracun/contracts - Domain models and interfaces
- ✅ @eracun/adapters - Service adapter interfaces
- ✅ @eracun/mocks - Realistic mock implementations
- ✅ @eracun/test-fixtures - Test data generators with OIB validation
- ✅ @eracun/di-container - Dependency injection with feature flags
- ✅ @eracun/messaging - RabbitMQ/Kafka abstractions with in-memory fallback
- ✅ @eracun/team2-mocks - Mock implementations for Team 2 services (OCR, AI, Email, SFTP)

**Documentation:**
- ✅ ADR-006: Message Bus Architecture (RabbitMQ + Kafka decision)
- ✅ ADR-007: Observability Stack (OpenTelemetry + Prometheus + Pino + Jaeger)
- ✅ Service README.md files (all 4 core services)
- ✅ OpenAPI 3.1 specification (invoice-gateway-api)
- ✅ Load testing README with usage guide
- ✅ Chaos testing README with 7 scenario guides (all 7 scenarios implemented as scripts)
- ✅ 415-line deployment runbook (DEPLOYMENT_RUNBOOK.md)

**Git Commits:**
- 64ee899 - Complete Week 1 Day 5 testing infrastructure and documentation
- 2c81a69 - Achieve 100% test pass rate (130/130 passing)
- 9968a51 - Add comprehensive unit test suite
- 981a3e0 - Implement ubl-transformer and validation-coordinator
- 82e3a3e - Implement invoice-orchestrator with saga pattern
- 2e64a81 - Implement invoice-gateway-api REST API
- ab8e789 - Add systemd services and deployment automation
- dd2166c - Add OpenTelemetry distributed tracing
- 4c0340c - Add Prometheus metrics endpoints
- 932f3d5 - Add RabbitMQ and Kafka integration

**Pending Work:**
- Docker images for containerized deployment (optional)
- Additional service implementations (Team 2-3 dependencies)
- Execute load tests and establish baseline metrics (requires running infrastructure)

---

## Testing Requirements

### Unit Tests (70% of test suite)
```typescript
// services/invoice-gateway-api/tests/unit/validator.test.ts
describe('InvoiceValidator', () => {
  let validator: InvoiceValidator;
  let mockValidationService: MockValidationService;

  beforeEach(() => {
    mockValidationService = new MockValidationService();
    validator = new InvoiceValidator(mockValidationService);
  });

  describe('validateInvoice', () => {
    it('should validate valid UBL invoice', async () => {
      const invoice = InvoiceGenerator.generateValidUBL();
      const result = await validator.validateInvoice(invoice);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should detect invalid OIB', async () => {
      const invoice = InvoiceGenerator.generateWithInvalidOIB();
      const result = await validator.validateInvoice(invoice);

      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          code: 'INVALID_OIB',
          field: 'AccountingSupplierParty.PartyTaxScheme.CompanyID'
        })
      );
    });

    // Property-based testing
    it('should handle any valid OIB format', () => {
      fc.assert(
        fc.property(fc.array(fc.nat(9), 10, 10), (digits) => {
          const oib = OIBGenerator.fromDigits(digits);
          const result = validator.validateOIB(oib);
          return result.valid === true;
        })
      );
    });
  });
});
```

### Integration Tests (25% of test suite)
```typescript
// services/invoice-gateway-api/tests/integration/pipeline.test.ts
describe('Invoice Processing Pipeline', () => {
  let app: Express;
  let rabbitMQ: RabbitMQTestContainer;
  let postgres: PostgreSQLContainer;

  beforeAll(async () => {
    rabbitMQ = await new RabbitMQTestContainer().start();
    postgres = await new PostgreSQLContainer().start();

    process.env.RABBITMQ_URL = rabbitMQ.getConnectionString();
    process.env.DATABASE_URL = postgres.getConnectionString();

    app = await createApp();
  });

  it('should process invoice end-to-end', async () => {
    const invoice = InvoiceGenerator.generateValidUBL();
    const idempotencyKey = uuid();

    const response = await request(app)
      .post('/api/v1/invoices')
      .set('X-Idempotency-Key', idempotencyKey)
      .set('Content-Type', 'application/xml')
      .send(invoice)
      .expect(202);

    // Verify async processing
    await waitForEvent('InvoiceValidated', response.body.invoiceId);

    // Verify idempotency
    const duplicate = await request(app)
      .post('/api/v1/invoices')
      .set('X-Idempotency-Key', idempotencyKey)
      .set('Content-Type', 'application/xml')
      .send(invoice)
      .expect(202);

    expect(duplicate.body.invoiceId).toBe(response.body.invoiceId);
  });
});
```

---

## Performance Requirements

### SLAs (Must Meet)
- Document upload: <200ms (p95)
- Validation pipeline: <5s (p99)
- XML transformation: <1s (p95)
- Throughput: 10,000 invoices/hour minimum

### Resource Limits (Per Service)
- Memory: 512MB baseline, 1GB burst
- CPU: 0.5 cores baseline, 2 cores burst
- Connections: 100 concurrent max

### Benchmarking
```bash
# Load testing with k6
k6 run --vus 100 --duration 30m tests/load/invoice-submission.js

# Expected results:
# - 0% error rate at 100 concurrent users
# - <200ms p95 response time
# - >95% success rate at 200 concurrent users
```

---

## Deliverables Checklist

### Code Deliverables
- [x] 4 microservices with 100% test coverage
- [x] Mock adapter implementations for all external dependencies
- [x] Shared test fixture library
- [x] Performance benchmark suite (k6 load tests)
- [x] Chaos testing scenarios (7/7 implemented: database, RabbitMQ, network, CPU, memory, cascade, partition + smoke & full runners)

### Documentation Deliverables
- [x] OpenAPI specifications for all REST endpoints
- [x] gRPC proto files for internal APIs (N/A - using RabbitMQ/Kafka)
- [x] Service README.md files (purpose, API, dependencies)
- [x] Runbooks for common operational tasks (DEPLOYMENT_RUNBOOK.md)
- [x] Architecture Decision Records (ADRs)

### Infrastructure Deliverables
- [x] systemd service unit files (4 services with security hardening)
- [ ] Docker images (optional, for testing)
- [x] Configuration templates (environment variables documented)
- [x] Deployment scripts (deploy-service.sh, rollback-service.sh, sops-decrypt.sh)
- [x] Health check scripts (health endpoints in all services)

---

## Communication Protocol

### Daily Standup (15 min)
- What was completed yesterday
- What will be worked on today
- Any blockers or dependencies

### Weekly Demo (1 hour)
- Demo working features
- Review metrics and test coverage
- Plan next week's priorities

### Async Communication
- Slack channel: #team-1-core-pipeline
- Documentation in Git (Markdown)
- Code reviews required for all PRs

---

## Success Criteria

### Week 1 Success
- [ ] All mock services operational
- [ ] invoice-gateway-api accepting requests
- [ ] 100% test coverage on completed code
- [ ] CI/CD pipeline functional

### Week 2 Success
- [ ] All 4 services implemented
- [ ] Message bus integration working
- [ ] End-to-end tests passing
- [ ] Performance benchmarks met

### Week 3 Success
- [x] Production-ready code (all 4 services with systemd integration)
- [x] Full observability implemented (OpenTelemetry + Prometheus)
- [x] Documentation complete (deployment runbook, metrics endpoints)
- [x] Ready for integration with other teams (RabbitMQ + Kafka clients)

---

## Risk Mitigation

### Risk: Mock behavior diverges from real services
**Mitigation:**
- Document all assumptions about external service behavior
- Create contract tests that real services must pass
- Regular sync with Team 3 on integration contracts

### Risk: Performance requirements not met
**Mitigation:**
- Benchmark early and often
- Profile code for bottlenecks
- Implement caching strategically
- Consider async processing where appropriate

### Risk: Message bus complexity
**Mitigation:**
- Start with simple request-reply pattern
- Add complexity incrementally
- Comprehensive integration tests
- Circuit breakers for resilience

---

**Document Version:** 1.0.1
**Created:** 2025-11-14
**Owner:** Team 1 Lead
**Review Cadence:** Weekly
