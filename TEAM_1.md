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
- [ ] Unit tests with 100% coverage
- [ ] Integration tests with mock services
- [ ] Property-based tests for validators
- [ ] Load testing setup (k6/Artillery)
- [ ] Chaos testing scenarios

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

#### Day 11-12: Message Bus Integration
- [ ] RabbitMQ command handlers
- [ ] Kafka event publishers
- [ ] Dead letter queue handling
- [ ] Circuit breakers for all external calls
- [ ] Retry with exponential backoff

#### Day 13-14: Observability & Security
- [ ] OpenTelemetry instrumentation
- [ ] Structured logging (Pino)
- [ ] Prometheus metrics
- [ ] XML security (XXE prevention)
- [ ] Input sanitization

#### Day 15: Production Readiness
- [ ] systemd service files
- [ ] Health check scripts
- [ ] Deployment documentation
- [ ] Runbook for common issues
- [ ] Performance benchmarks

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
- [ ] 4 microservices with 100% test coverage
- [ ] Mock adapter implementations for all external dependencies
- [ ] Shared test fixture library
- [ ] Performance benchmark suite
- [ ] Chaos testing scenarios

### Documentation Deliverables
- [ ] OpenAPI specifications for all REST endpoints
- [ ] gRPC proto files for internal APIs
- [ ] Service README.md files (purpose, API, dependencies)
- [ ] Runbooks for common operational tasks
- [ ] Architecture Decision Records (ADRs)

### Infrastructure Deliverables
- [ ] systemd service unit files
- [ ] Docker images (optional, for testing)
- [ ] Configuration templates
- [ ] Deployment scripts
- [ ] Health check scripts

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
- [ ] Production-ready code
- [ ] Full observability implemented
- [ ] Documentation complete
- [ ] Ready for integration with other teams

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
