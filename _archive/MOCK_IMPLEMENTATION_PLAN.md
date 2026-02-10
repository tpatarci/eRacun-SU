# High-Quality Mock Services Implementation Plan

**Date:** 2025-11-16
**Context:** Migration 90% complete (26/29 services extracted)
**Priority:** Implement production-grade mocks to unblock development
**Timeline:** 1 week for full mock suite

---

## ✅ Current Situation

### Migration Status: SUCCESSFUL
- **Completed:** 26-27 services (90%)
- **Blocked:** Only 2 services (admin-portal-api, email-ingestion-worker)
- **Ready for Testing:** 26 services need external mocks to function

### The Real Need
The migration is **substantially complete**. Now we need **high-quality mocks** to:
1. Enable testing of the 26 extracted services
2. Unblock development without waiting for external services
3. Provide deterministic testing environment
4. Enable chaos engineering and resilience testing

---

## 🎯 Mock Services Required

### Priority 1: Critical External Services (Day 1-2)

#### 1. FINA Fiscalization Mock
**Purpose:** Tax authority invoice submission
**Protocol:** SOAP/XML
**Complexity:** HIGH - Must handle XML signatures, certificates

```typescript
// Key Features Required
- SOAP endpoint with WS-Security
- X.509 certificate validation (mock validation)
- JIR generation (UUID format)
- Realistic response delays (100-500ms)
- Error injection (rate limiting, service unavailable)
- Test data: 100+ sample invoices
```

#### 2. Porezna API Mock
**Purpose:** Tax reporting and validation
**Protocol:** REST/JSON
**Complexity:** MEDIUM

```typescript
// Key Features Required
- OAuth 2.0 authentication flow
- Batch submission endpoints
- Async processing simulation
- Webhook callbacks for status updates
- Rate limiting simulation
```

#### 3. Email Service Mock
**Purpose:** Invoice ingestion via email
**Protocol:** SMTP/IMAP
**Complexity:** MEDIUM

```typescript
// Key Features Required
- SMTP server for receiving
- IMAP server for reading
- Attachment handling
- Multi-part MIME support
- Folder operations
```

### Priority 2: Supporting Services (Day 3-4)

#### 4. KLASUS Registry Mock
**Purpose:** Product code validation
**Protocol:** REST/JSON
**Complexity:** LOW

```typescript
// Key Features Required
- Complete 2025 KLASUS codes (10,000+ entries)
- Search/filter endpoints
- Version management
- Bulk validation
```

#### 5. Bank API Mock
**Purpose:** Payment verification
**Protocol:** REST/JSON
**Complexity:** MEDIUM

```typescript
// Key Features Required
- Account verification
- Transaction queries
- Payment status checks
- IBAN validation
- MT940 statement generation
```

#### 6. Certificate Authority Mock
**Purpose:** X.509 certificate operations
**Protocol:** REST + PKCS
**Complexity:** HIGH

```typescript
// Key Features Required
- Certificate generation
- Certificate validation
- CRL/OCSP responses
- Certificate renewal flow
- Test certificates for all services
```

---

## 🏗️ Implementation Architecture

### Technology Stack
```yaml
Core:
  Language: TypeScript (matching main services)
  Runtime: Node.js 20+
  Framework: Express + Fastify (performance)

Protocols:
  SOAP: soap-server (for FINA)
  REST: Express/Fastify
  SMTP: smtp-server
  IMAP: imap-server

Data:
  Storage: In-memory + JSON files
  Persistence: Optional Redis
  Test Data: JSON/XML fixtures

Testing:
  Contract Testing: OpenAPI/WSDL validation
  Load Testing: k6 scripts
  Chaos: Built-in failure injection
```

### Repository Structure
```
eracun-mocks/
├── packages/                      # Monorepo with workspaces
│   ├── core/                     # Shared utilities
│   │   ├── chaos-engine/         # Failure injection
│   │   ├── data-generator/       # Test data generation
│   │   └── contract-validator/   # API contract validation
│   │
│   ├── fina-mock/               # FINA SOAP service
│   │   ├── src/
│   │   ├── contracts/           # WSDL/XSD
│   │   ├── fixtures/            # Sample invoices
│   │   └── tests/
│   │
│   ├── porezna-mock/            # Porezna REST API
│   ├── email-mock/              # SMTP/IMAP servers
│   ├── klasus-mock/             # Product registry
│   ├── bank-mock/               # Banking API
│   └── cert-mock/               # Certificate operations
│
├── docker/                       # Container configurations
├── k6/                          # Load test scripts
├── contracts/                   # OpenAPI/WSDL specs
└── docker-compose.yml           # Orchestration
```

---

## 💎 Quality Requirements

### 1. Production Parity (95% behavior match)
```typescript
// Mock must match production behavior
interface MockBehavior {
  requestValidation: 'identical';      // Same validation rules
  responseFormat: 'identical';         // Exact response structure
  errorCodes: 'identical';             // Same error codes
  timing: 'realistic';                 // 100-500ms latency
  stateManagement: 'stateful';        // Remember transactions
}
```

### 2. Deterministic Testing
```typescript
// Reproducible test scenarios
interface TestScenario {
  seed: string;                       // Deterministic randomness
  sequence: Operation[];              // Ordered operations
  expectedOutcome: Result;            // Predictable result
  replay: () => Promise<Result>;      // Repeatable execution
}
```

### 3. Comprehensive Test Data
```typescript
// Rich test data sets
interface TestDataSet {
  validInvoices: Invoice[];           // 100+ valid samples
  invalidInvoices: InvalidCase[];     // Edge cases, errors
  edgeCases: EdgeCase[];              // Boundary conditions
  performanceSet: LargeDataSet;       // 10,000+ for load testing
}
```

### 4. Chaos Engineering Built-in
```typescript
interface ChaosMode {
  latency: { min: 100, max: 5000 };   // Variable delays
  errorRate: 0.05;                    // 5% random failures
  partialFailure: true;               // Incomplete responses
  networkIssues: true;                // Connection drops
  dataCorruption: false;              // Data integrity (off by default)
}
```

---

## 🚀 Implementation Plan

### Day 1: Foundation + FINA Mock
```bash
Morning (4h):
- [ ] Set up monorepo structure with Lerna/NPM workspaces
- [ ] Create core chaos engine
- [ ] Implement contract validator

Afternoon (4h):
- [ ] Implement FINA SOAP endpoint
- [ ] Add XML signature validation
- [ ] Generate test certificates
- [ ] Create 50 sample invoices
```

### Day 2: Porezna + Email Mocks
```bash
Morning (4h):
- [ ] Implement Porezna REST API
- [ ] Add OAuth 2.0 flow
- [ ] Create batch endpoints

Afternoon (4h):
- [ ] Implement SMTP server
- [ ] Implement IMAP server
- [ ] Add attachment handling
- [ ] Test with real email clients
```

### Day 3: Supporting Services
```bash
Morning (4h):
- [ ] Import KLASUS 2025 data (10,000+ codes)
- [ ] Create search/filter APIs
- [ ] Add bulk validation

Afternoon (4h):
- [ ] Implement Bank API mock
- [ ] Add IBAN validation
- [ ] Create transaction queries
- [ ] Generate MT940 statements
```

### Day 4: Certificate Mock + Integration
```bash
Morning (4h):
- [ ] Implement cert generation
- [ ] Add validation endpoints
- [ ] Create CRL/OCSP responders

Afternoon (4h):
- [ ] Docker compose setup
- [ ] Integration testing
- [ ] Performance testing with k6
```

### Day 5: Polish + Documentation
```bash
Morning (4h):
- [ ] Add comprehensive logging
- [ ] Implement mock admin UI
- [ ] Create debugging tools

Afternoon (4h):
- [ ] Write usage documentation
- [ ] Create video tutorials
- [ ] Deploy to shared environment
```

---

## 📊 Success Metrics

### Functional Coverage
- [ ] All 6 external services mocked
- [ ] 95% API coverage per service
- [ ] 100+ test scenarios per service
- [ ] Chaos mode for each service

### Performance
- [ ] <10ms response time (excluding artificial delay)
- [ ] Support 1000 req/sec per service
- [ ] <100MB memory per service
- [ ] Startup time <1 second

### Developer Experience
- [ ] One command startup: `docker-compose up`
- [ ] Hot reload in development
- [ ] Detailed request/response logging
- [ ] Mock admin UI for configuration

### Testing Capabilities
- [ ] Deterministic scenarios
- [ ] State management
- [ ] Error injection
- [ ] Performance profiling

---

## 🎨 Advanced Features

### 1. Scenario Recording/Playback
```typescript
// Record real interactions for replay
mockServer.record('invoice-submission-flow');
// ... perform operations
const scenario = mockServer.stopRecording();
mockServer.replay(scenario); // Exact reproduction
```

### 2. State Machine Simulation
```typescript
// Complex stateful workflows
const invoiceStateMachine = {
  states: ['received', 'validating', 'validated', 'submitted', 'confirmed'],
  transitions: [
    { from: 'received', to: 'validating', action: 'validate' },
    { from: 'validating', to: 'validated', action: 'complete' }
  ]
};
```

### 3. Smart Response Generation
```typescript
// AI-powered response variation
const responseGenerator = new ResponseGenerator({
  baseResponse: validResponse,
  variability: 0.2,  // 20% variation
  constraints: schemaConstraints
});
```

### 4. Performance Profiling
```typescript
// Built-in performance metrics
mockServer.profile({
  trackLatency: true,
  trackMemory: true,
  trackCPU: true,
  reportInterval: 1000
});
```

---

## 🔧 Configuration Management

### Environment-Based Config
```yaml
# config/development.yml
fina:
  latency: 100ms
  errorRate: 0.01
  authentication: relaxed

# config/testing.yml
fina:
  latency: 10ms
  errorRate: 0
  authentication: strict

# config/chaos.yml
fina:
  latency: 100-5000ms
  errorRate: 0.3
  authentication: random
```

### Dynamic Reconfiguration
```typescript
// Runtime configuration changes
await mockAPI.configure({
  service: 'fina',
  errorRate: 0.5,
  latency: { min: 1000, max: 3000 }
});
```

---

## ✅ Deliverables

### Week 1 Completion
1. **6 Production-Grade Mocks** running in Docker
2. **1000+ Test Data Samples** covering all scenarios
3. **Chaos Engineering** modes for resilience testing
4. **Admin UI** for mock configuration
5. **Documentation** with examples and videos
6. **k6 Load Tests** proving performance
7. **Contract Tests** ensuring accuracy

### For Developers
- One-command setup
- Deterministic testing
- Comprehensive scenarios
- Performance profiling

### For QA
- Error injection
- Edge case testing
- Load testing capability
- Scenario recording

### For DevOps
- Docker deployment
- Monitoring endpoints
- Resource efficiency
- High availability

---

## 🎯 Why This Approach Works

1. **Immediate Value**: Unblocks testing for 26 services TODAY
2. **Production Quality**: Not throwaway code - useful long-term
3. **Developer Friendly**: Matches mental model of real services
4. **Test Coverage**: Enables 100% scenario testing
5. **Future Proof**: Valuable even after real services available

---

## 📅 Timeline Summary

**Day 1-2:** Core mocks (FINA, Porezna, Email)
**Day 3-4:** Supporting mocks (KLASUS, Bank, Certs)
**Day 5:** Polish and documentation
**Result:** Complete mock suite in 1 week

---

**Next Step:** Start with FINA mock implementation (highest complexity, highest value)

The migration is done. Now let's build world-class mocks to make those 26 services sing! 🚀