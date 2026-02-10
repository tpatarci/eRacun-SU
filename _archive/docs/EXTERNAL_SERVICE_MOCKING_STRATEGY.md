# External Service Mocking Strategy

## Executive Summary

This document establishes the strategy for simulating external service providers to enable parallel development while actual services remain unavailable. We adopt a **separate repository approach** (`eracun-mocks`) to maintain clean separation between production code and simulation infrastructure.

**Repository:** `eracun-mocks` (separate from main eRačun repositories)
**Timeline:** Immediate implementation to unblock development
**Philosophy:** Contract-first development with production parity

---

## 1. Strategic Principles

### 1.1 Contract-First Development
- Define OpenAPI/AsyncAPI/WSDL contracts before implementation
- Generate both mock servers AND client SDKs from same source
- When real services arrive, integration = changing endpoint URL

### 1.2 Production Parity
- Mock services must behave identically to production specifications
- Include realistic delays, error rates, and edge cases
- Support all authentication mechanisms (X.509, JWT, API keys)

### 1.3 Environment Flexibility
- Single environment variable toggles between mock/real services
- No code changes required when switching to production
- Support partial mocking (some services real, others mocked)

### 1.4 Chaos Engineering by Default
- Every mock includes configurable failure modes
- Test resilience patterns (circuit breakers, retries, fallbacks)
- Validate system behavior under degraded conditions

---

## 2. Repository Structure

```
eracun-mocks/
├── fina-simulator/                 # FINA Tax Authority mock
│   ├── src/
│   │   ├── server.ts              # Express/SOAP server
│   │   ├── handlers/              # Request handlers
│   │   ├── data/                  # Sample responses
│   │   └── chaos/                 # Failure injection
│   ├── contracts/
│   │   ├── fiscalization.wsdl     # SOAP contract
│   │   └── openapi.yaml           # REST documentation
│   ├── certs/                     # Mock X.509 certificates
│   ├── tests/
│   └── README.md
│
├── porezna-simulator/              # Porezna Uprava mock
│   ├── src/
│   ├── contracts/
│   └── README.md
│
├── email-provider-simulator/      # Email service mock
│   ├── src/
│   │   ├── smtp-server.ts        # Mock SMTP server
│   │   └── imap-server.ts        # Mock IMAP server
│   ├── contracts/
│   └── README.md
│
├── bank-api-simulator/           # Banking API mock
│   ├── src/
│   ├── contracts/
│   └── README.md
│
├── dzs-klasus-simulator/         # DZS KLASUS registry mock
│   ├── src/
│   ├── data/
│   │   └── klasus-2025.json     # Complete product codes
│   └── README.md
│
├── shared/
│   ├── chaos-engine/             # Shared chaos testing
│   │   ├── latency.ts           # Inject delays
│   │   ├── errors.ts            # Inject failures
│   │   └── corruption.ts        # Data corruption
│   ├── contracts/                # Shared schemas
│   │   ├── common-types.proto   # Shared Protobuf
│   │   └── error-codes.yaml     # Standard errors
│   ├── test-data/                # Sample documents
│   │   ├── valid-invoices/
│   │   ├── invalid-invoices/
│   │   └── edge-cases/
│   └── utils/
│       ├── cert-generator.ts    # Generate mock X.509
│       └── oib-validator.ts     # OIB validation
│
├── docker-compose.yml            # Run all mocks together
├── scripts/
│   ├── generate-contracts.sh    # Generate from OpenAPI
│   ├── validate-contracts.sh    # Contract testing
│   └── deploy-mocks.sh         # Deploy to environment
│
├── docs/
│   ├── SETUP.md                # Getting started guide
│   ├── CHAOS_TESTING.md        # Failure injection guide
│   └── MIGRATION.md            # Moving to real services
│
└── README.md                    # Overview and quick start
```

---

## 3. Implementation Approach

### 3.1 Phase 1: Critical Services (Week 1-2)
1. **FINA Simulator**
   - SOAP endpoints for fiscalization
   - X.509 certificate validation
   - JIR generation for receipts
   - Configurable response delays

2. **Porezna Connector**
   - REST API for tax reporting
   - OAuth 2.0 authentication
   - Batch processing endpoints

3. **Email Provider**
   - SMTP server for receiving
   - IMAP server for reading
   - Attachment handling

### 3.2 Phase 2: Supporting Services (Week 3-4)
1. **Bank API Simulator**
   - Payment status checks
   - Account verification
   - Transaction queries

2. **DZS KLASUS Registry**
   - Product code validation
   - Search functionality
   - Version management

### 3.3 Phase 3: Chaos Engineering (Week 5)
1. **Failure Modes**
   - Network timeouts
   - Rate limiting
   - Malformed responses
   - Service unavailable
   - Partial failures

2. **Configuration**
   ```yaml
   chaos:
     enabled: true
     modes:
       latency:
         enabled: true
         min_ms: 100
         max_ms: 5000
       errors:
         enabled: true
         rate: 0.05  # 5% error rate
       corruption:
         enabled: false
   ```

---

## 4. Configuration Management

### 4.1 Environment Variables
```bash
# Service toggles
FINA_USE_MOCK=true
FINA_MOCK_URL=http://localhost:8449
FINA_REAL_URL=https://cis.porezna-uprava.hr:8449

POREZNA_USE_MOCK=true
POREZNA_MOCK_URL=http://localhost:8450
POREZNA_REAL_URL=https://api.porezna.hr

# Chaos settings
CHAOS_MODE=moderate  # off|light|moderate|extreme
CHAOS_SEED=12345     # Reproducible chaos
```

### 4.2 Service Discovery
```typescript
// services/fina-connector/src/config.ts
export const FINA_ENDPOINT = process.env.FINA_USE_MOCK === 'true'
  ? process.env.FINA_MOCK_URL
  : process.env.FINA_REAL_URL;
```

---

## 5. Contract Testing Strategy

### 5.1 Contract Validation
```bash
# Validate mock responses against contracts
npm run validate:fina
npm run validate:porezna
npm run validate:all
```

### 5.2 Pact Testing
```typescript
// Generate consumer contracts
describe('FINA Integration', () => {
  it('should fiscalize invoice', () => {
    const interaction = {
      state: 'invoice ready for fiscalization',
      request: { /* ... */ },
      response: { /* ... */ }
    };
    // Pact records interaction
  });
});
```

### 5.3 Contract Evolution
1. Update OpenAPI/WSDL specification
2. Regenerate mock server code
3. Update client SDKs
4. Run contract tests
5. Deploy new version

---

## 6. Development Workflow

### 6.1 Local Development
```bash
# Clone mock repository
git clone git@github.com:eracun/eracun-mocks.git
cd eracun-mocks

# Install dependencies
npm install

# Start all mocks
docker-compose up

# Or start individual mock
cd fina-simulator
npm run dev
```

### 6.2 CI/CD Integration
```yaml
# .github/workflows/test.yml
services:
  mocks:
    image: eracun/mocks:latest
    ports:
      - 8449:8449  # FINA
      - 8450:8450  # Porezna
```

### 6.3 Team Onboarding
1. Read this strategy document
2. Clone `eracun-mocks` repository
3. Run `npm run setup` to initialize
4. Review service contracts in `contracts/`
5. Test with sample requests in `docs/examples/`

---

## 7. Migration to Production Services

### 7.1 Pre-Migration Checklist
- [ ] Production endpoints documented
- [ ] Certificates acquired and deployed
- [ ] Rate limits understood
- [ ] Error handling tested
- [ ] Monitoring configured

### 7.2 Migration Steps
1. **Contract Verification**
   - Compare mock contracts with production
   - Update any discrepancies
   - Run contract tests against production

2. **Gradual Rollout**
   - Enable production for one service
   - Monitor for errors
   - Roll back if issues detected
   - Proceed to next service

3. **Configuration Update**
   ```bash
   # Stage 1: All mocked
   FINA_USE_MOCK=true
   POREZNA_USE_MOCK=true

   # Stage 2: FINA production
   FINA_USE_MOCK=false
   POREZNA_USE_MOCK=true

   # Stage 3: All production
   FINA_USE_MOCK=false
   POREZNA_USE_MOCK=false
   ```

---

## 8. Success Metrics

### 8.1 Development Velocity
- Teams unblocked from day 1
- Parallel development enabled
- No waiting for external services

### 8.2 Quality Metrics
- Contract test coverage >95%
- Mock/production behavior parity >99%
- Zero integration bugs from contract mismatches

### 8.3 Resilience Metrics
- All failure modes tested
- Circuit breakers validated
- Recovery procedures documented

---

## 9. Responsibilities

### 9.1 Mock Repository Maintainers
- Keep contracts up to date
- Fix mock behavior discrepancies
- Add new failure scenarios
- Document changes

### 9.2 Service Teams
- Report mock issues promptly
- Contribute test data
- Validate mock behavior
- Update when contracts change

### 9.3 DevOps Team
- Deploy mock infrastructure
- Configure environments
- Monitor mock availability
- Coordinate production migration

---

## 10. Quick Reference

### Common Commands
```bash
# Start all mocks
docker-compose up

# Run contract tests
npm run test:contracts

# Enable chaos mode
export CHAOS_MODE=extreme

# Generate new mock certificate
npm run cert:generate -- --cn "Test Issuer" --oib "12345678901"

# Validate against production
npm run validate:production -- --service fina
```

### Troubleshooting
| Problem | Solution |
|---------|----------|
| Mock not responding | Check docker-compose logs |
| Contract mismatch | Run `npm run validate:contracts` |
| Certificate error | Regenerate with `npm run cert:generate` |
| Chaos too aggressive | Reduce with `CHAOS_MODE=light` |

---

## Related Documentation

- **Architecture:** @docs/ARCHITECTURE.md
- **Development Standards:** @docs/DEVELOPMENT_STANDARDS.md
- **External Integrations:** @docs/api-contracts/
- **FINA Specification:** @docs/standards/fina-fiscalization.pdf
- **Porezna API:** @docs/standards/porezna-api.yaml

---

**Version:** 1.0.0
**Created:** 2025-11-15
**Owner:** Platform Team
**Review:** Monthly