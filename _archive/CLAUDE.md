# CLAUDE.md - eRačun Invoice Processing Platform

## Project Context
Mission-critical B2B electronic invoice processing for Croatian legal entities.
Zero-tolerance for data corruption or regulatory non-compliance.
Fire-and-forget reliability with triple redundancy validation.
**HARD DEADLINE: January 1, 2026** for Croatian Fiskalizacija 2.0 compliance.
**Penalties for failure:** €66,360 fines + VAT deduction loss + criminal liability.

---

## Tech Stack
- **Languages:** TypeScript (strict mode), Node.js 20+
- **Backend:** Express (REST), gRPC (internal APIs)
- **Database:** PostgreSQL 15+ (managed), Redis (caching)
- **Message Bus:** RabbitMQ (commands), Kafka (events)
- **Validation:** XSD/Schematron for UBL 2.1, Croatian CIUS
- **Infrastructure:** DigitalOcean droplets, systemd services
- **Monitoring:** Prometheus + Grafana, OpenTelemetry + Jaeger

---

## Repository Structure
```
eRacun-development/
├── services/          # Microservices (max 2,500 LOC each)
│   ├── invoice-gateway-api/
│   ├── email-ingestion-worker/
│   ├── schema-validator/
│   ├── fina-connector/
│   └── ... (15+ services)
├── shared/            # Shared libs (only after 3+ service usage)
├── docs/              # All detailed documentation
│   ├── adr/                # Architecture Decision Records
│   ├── pending/            # Deferred critical issues
│   ├── reports/            # Completion documentation
│   ├── guides/             # Implementation guides
│   └── standards/          # Regulatory standards
├── config/            # Templates only (see ADR-001)
├── secrets/           # SOPS encrypted (see ADR-002)
├── deployment/        # systemd units, terraform
└── scripts/           # Build and orchestration
```

**Service pattern:** Each service = one bounded context with own README.md

---

## Commands
```bash
# Development
npm run dev              # Start development server
npm run build            # Build all services
npm test                 # Run tests (100% coverage required)
npm run test:e2e         # End-to-end tests
npm run lint             # ESLint + Prettier
npm run typecheck        # TypeScript strict check

# Validation
npm run validate:schema  # Validate UBL schemas
npm run validate:cius    # Validate Croatian CIUS

# Deployment
./scripts/deploy.sh      # Deploy to environment
./scripts/sops.sh        # Decrypt secrets

# Utilities
npm run coverage         # Generate coverage report
npm run benchmark        # Run performance benchmarks
```

---

## Critical Constraints (NEVER VIOLATE)
- **NEVER** modify files in `src/legacy/` directory
- **NEVER** commit `.env`, `.p12`, `.key`, `.pem` files (use SOPS)
- **NEVER** skip 100% test coverage requirement
- **NEVER** use synchronous I/O in async contexts
- **NEVER** trust input without validation
- **NEVER** swallow exceptions silently
- **NEVER** exceed 2,500 LOC per service
- **NEVER** share code until pattern appears 3+ times
- **NEVER** deploy without running full test suite

---

## Code Standards

### TypeScript
- Strict mode enabled (`strict: true`)
- No `any` types without explicit justification
- Functional components with hooks (React)
- Async/await over callbacks
- Named exports over default exports

### Reliability Patterns (MANDATORY)
1. **Idempotency** - All operations use idempotency keys
2. **Circuit Breakers** - External API calls protected (default: 50% failure threshold)
3. **Retry with Exponential Backoff** - Max 3 retries with jitter
4. **Structured Logging** - JSON format with request ID propagation
5. **Distributed Tracing** - OpenTelemetry spans for all operations

### Error Handling
- Error boundaries around all external calls
- Explicit error types (no generic `Error`)
- Context captured in all errors
- Circuit breaker state exposed in health checks

### Naming Conventions
- **Files:** `kebab-case.ts`
- **Classes:** `PascalCase`
- **Functions:** `camelCase`
- **Constants:** `SCREAMING_SNAKE_CASE`

---

## Service Architecture

**Event-Driven Microservices with CQRS:**
- Each service owns one bounded context
- Inter-service: RabbitMQ (commands), Kafka (events)
- All messages use Protocol Buffers with versioned schemas
- Service size limit: 2,500 LOC (excluding tests)

**Communication Patterns:**
- Commands: Direct service-to-service (RabbitMQ RPC)
- Events: Broadcast state changes (Kafka topics)
- Queries: Synchronous HTTP/gRPC (limited use)

See @docs/ARCHITECTURE.md for detailed patterns and data flow.

---

## Testing Requirements

**Minimum Coverage:** 100% (enforced in CI)

**Philosophy:** This system handles legally binding financial documents with zero error tolerance. 100% coverage is the bare minimum for a system where failures result in €66,360 penalties, VAT deduction loss, 11-year audit liability, and criminal prosecution.

**Test Pyramid:**
- Unit Tests: 70% (fast, isolated, no I/O)
- Integration Tests: 25% (service boundaries, message contracts)
- E2E Tests: 5% (critical user journeys only)

**Pragmatic Exceptions:**
- Infrastructure modules (RabbitMQ consumers, service entry points) may be excluded
- Must be documented in `jest.config.js` with justification
- Core business logic always requires 100%

See @docs/DEVELOPMENT_STANDARDS.md for detailed testing requirements.

---

## Security

**Zero Trust Architecture:**
- No service trusts incoming data without validation
- All inter-service communication authenticated (mTLS in production)
- Secrets managed via SOPS + age encryption
- Input sanitization at every boundary

**XML Security (Critical):**
- XXE attacks prevented (disable external entities)
- Schema validation before parsing
- Size limits enforced (max 10MB per document)
- Billion laughs attack protection

**systemd Hardening:**
- `ProtectSystem=strict` - Read-only filesystem
- `NoNewPrivileges=true` - Prevent privilege escalation
- `CapabilityBoundingSet=` - Drop all Linux capabilities
- `SystemCallFilter=@system-service` - Restrict system calls

See @docs/SECURITY.md for complete security standards.

---

## Compliance

**Croatian Fiskalizacija 2.0:**
- **Deadline:** January 1, 2026 (MANDATORY)
- **Standards:** UBL 2.1, EN 16931, Croatian CIUS
- **Validation:** 6 layers (XSD, Schematron, KPD, semantic, AI, consensus)
- **Retention:** 11 years (NOT 7 years)
- **Penalties:** Up to €66,360 + VAT loss + criminal liability

**Key Requirements:**
- OIB numbers (Issuer, Operator, Recipient)
- KPD classification (KLASUS 2025 codes)
- Digital signature (XMLDSig with FINA X.509 certificate)
- Qualified timestamp (eIDAS-compliant)

See @docs/COMPLIANCE_REQUIREMENTS.md for complete regulatory specifications.

---

## Deployment

**Target Environment:**
- Platform: DigitalOcean Dedicated Droplets (Linux)
- OS: Ubuntu 22.04 LTS or Debian 12+
- Orchestrator: systemd (native Linux service manager)
- Philosophy: Classic Unix conventions (POSIX, FHS compliance)

**Environments:**
- Development: `dev.eracun.internal`
- Staging: `staging.eracun.internal` (FINA test: cistest.apis-it.hr)
- Production: `production.eracun.hr` (FINA prod: cis.porezna-uprava.hr)

**Deployment Process:**
1. Build and test locally or in CI/CD
2. rsync artifacts to `/opt/eracun/services/`
3. Update configuration in `/etc/eracun/`
4. Reload systemd: `systemctl daemon-reload`
5. Restart service: `systemctl restart eracun-{service}`
6. Verify health: `systemctl status eracun-{service}`

See @docs/DEPLOYMENT_GUIDE.md for detailed procedures.

---

## Workflow

**Git Strategy:** Trunk-Based Development
- `main` branch always deployable
- Feature branches max 2 days lifespan
- Conventional Commits format

**PENDING Tracking (MANDATORY):**
- All critical gaps tracked in `PENDING.md`
- Detailed specs in `docs/pending/{number}-{slug}.md`
- Priority levels: P0 (critical) → P3 (low)
- Weekly triage required

**Completion Reports (MANDATORY):**
- All significant work documented in `docs/reports/`
- Format: `YYYY-MM-DD-{task-id}-{description}.md`
- Required for TODO/PENDING completion, service implementation, deployments

See @docs/WORKFLOW.md for complete workflow standards.

---

## External Documentation

**Core Documents:**
- **Compliance:** @docs/COMPLIANCE_REQUIREMENTS.md (Croatian standards)
- **Architecture:** @docs/ARCHITECTURE.md (patterns, performance)
- **Development:** @docs/DEVELOPMENT_STANDARDS.md (testing, quality)
- **Security:** @docs/SECURITY.md (hardening, certificates)
- **Deployment:** @docs/DEPLOYMENT_GUIDE.md (systemd, environments)
- **Operations:** @docs/OPERATIONS.md (monitoring, incidents)
- **Workflow:** @docs/WORKFLOW.md (git, PENDING tracking)

**Decisions & Planning:**
- **ADRs:** @docs/adr/ (architecture decision records)
- **Pending Work:** @docs/pending/ (deferred critical issues)
- **Reports:** @docs/reports/ (completion documentation)

**Implementation Guides:**
- **Standards:** @docs/standards/ (UBL, CIUS-HR specifications)
- **Research:** @docs/research/ (OIB, VAT, XMLDSig guides)
- **API Contracts:** @docs/api-contracts/ (OpenAPI/gRPC specs)

---

**Version:** 2.0.0 (Post-overhaul)
**Lines:** ~200 (from 742)
**Token Estimate:** ~1,000 (from ~3,710)
**Token Savings:** 71% reduction
**Last Updated:** 2025-11-12
