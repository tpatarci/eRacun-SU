# CLAUDE.md - eRacun Invoice Processing Platform

## Mission-Critical System Architecture Document

**System Classification:** Five-Nines Availability (99.999% uptime)
**Architecture Pattern:** Event-Driven Microservices with CQRS
**Development Approach:** AI-Assisted, Context-Window Optimized
**Repository Type:** Monorepo

---

## 1. PROJECT MISSION

This platform is the **architectural foundation** for a production-grade B2B electronic invoice processing system serving Croatian legal entities. This is not a prototype. This is not an experiment. This system will handle **legally binding financial documents** with zero tolerance for data corruption, loss, or regulatory non-compliance.

**Core Commitments:**
- **Fire-and-forget reliability** - Clients submit documents and trust the system completely
- **Triple redundancy validation** - AI/heuristic verification with consensus mechanisms
- **Regulatory compliance** - Full adherence to Croatian e-invoice standards (FINA e-Račun, UBL 2.1, EN 16931)
- **Multi-channel ingestion** - Email, web upload, API, manual scanning
- **Zero-error tolerance** - Multiple validation layers prevent bad data reaching authorities

---

## 2. MONOREPO STRUCTURE PRINCIPLES

### 2.1 Repository Organization

```
eRacun-development/
├── services/               # Individual microservices (bounded contexts)
│   ├── invoice-gateway-api/
│   ├── email-ingestion-worker/
│   ├── ocr-processing-service/
│   ├── schema-validator/
│   ├── ai-validation-service/
│   ├── ubl-transformer/
│   ├── fina-connector/
│   └── porezna-connector/
├── shared/                 # Shared libraries (use with performance awareness)
│   ├── common-types/       # TypeScript interfaces, domain models
│   ├── validation-core/    # Reusable validation primitives
│   ├── messaging/          # Message bus abstractions
│   └── observability/      # Logging, tracing, metrics
├── infrastructure/         # IaC, deployment configs, K8s manifests
│   ├── terraform/          # DigitalOcean infrastructure
│   ├── kubernetes/         # Service deployments
│   └── systemd/            # Critical daemon configurations
├── docs/                   # Architectural Decision Records (ADRs)
│   ├── adr/                # Architecture decisions
│   ├── api-contracts/      # OpenAPI/gRPC specs
│   └── diagrams/           # System architecture visuals
└── scripts/                # Build, deployment, orchestration scripts
```

### 2.2 Context-Window Optimization Strategy

**Problem:** Large codebases exhaust AI assistant context windows, reducing code quality.

**Solution:** Aggressive service decomposition with clear boundaries.

**Rules:**
1. **Service Size Limit:** No service exceeds 2,500 LOC (excluding tests)
2. **Single Responsibility:** Each service has ONE clearly defined bounded context
3. **Explicit Contracts:** All inter-service communication through typed schemas
4. **Isolated Development:** Services can be developed/reviewed independently
5. **Documentation Proximity:** Each service contains its own README.md with:
   - Purpose and scope
   - API contract
   - Dependencies
   - Performance characteristics
   - Failure modes

### 2.3 Shared Libraries - Performance Considerations

**Philosophy:** Share code carefully. Premature abstraction creates coupling.

**Guidelines:**
- **Only extract to `shared/` after pattern appears in 3+ services**
- **Measure impact:** Every shared library addition requires performance justification
- **Version independently:** Shared libs use semantic versioning
- **Tree-shaking compatible:** All shared code must support dead code elimination
- **Zero-dependency preferred:** Minimize transitive dependencies

**Performance Checklist for Shared Code:**
- [ ] Does not introduce runtime overhead >1ms
- [ ] Bundle size impact <10KB
- [ ] No synchronous I/O in critical paths
- [ ] Benchmark results documented in `shared/*/PERFORMANCE.md`

---

## 3. CODE QUALITY STANDARDS

### 3.1 Development Principles

**"Created with utmost care, but not abundant"** - Every line serves a purpose.

- **No speculative features** - Build what's needed now
- **No premature optimization** - Optimize after measurement
- **No clever code** - Clarity over brevity
- **No silent failures** - Explicit error handling everywhere
- **No magic numbers** - Constants are named and documented

### 3.2 Reliability Patterns (Mandatory)

Every service MUST implement:

1. **Idempotency**
   - All operations use idempotency keys
   - Duplicate requests produce identical results
   - No partial state mutations

2. **Circuit Breakers**
   - External API calls protected by circuit breakers
   - Graceful degradation on dependency failures
   - Health checks expose circuit states

3. **Retry with Exponential Backoff**
   - Transient failures automatically retried
   - Max retry limits enforced (default: 3)
   - Jitter added to prevent thundering herd

4. **Structured Logging**
   - JSON-formatted logs
   - Request IDs propagated through entire call chain
   - Error context captured (never swallow exceptions)

5. **Distributed Tracing**
   - OpenTelemetry instrumentation
   - Every service operation creates spans
   - Trace IDs link cross-service operations

### 3.3 Testing Requirements

**Minimum Coverage:** 85% (enforced in CI)

**Test Pyramid:**
- **Unit Tests:** 70% of test suite - Fast, isolated, no I/O
- **Integration Tests:** 25% - Test service boundaries, message contracts
- **E2E Tests:** 5% - Critical user journeys only

**Special Requirements:**
- **Chaos Testing:** Inject failures (network, CPU, disk) in staging
- **Property-Based Testing:** For validators and transformers
- **Contract Testing:** Pact/Pactflow for inter-service contracts

### 3.4 Security Hardening

**Zero Trust Architecture:**
- No service trusts incoming data without validation
- All inter-service communication authenticated (mTLS in production)
- Secrets managed via HashiCorp Vault or K8s secrets
- Input sanitization at every boundary

**XML Security (Critical for e-invoice processing):**
- XXE (XML External Entity) attacks prevented
- Schema validation before parsing
- Size limits enforced (max 10MB per document)
- Billion laughs attack protection

---

## 4. AI-ASSISTED DEVELOPMENT GUIDELINES

### 4.1 Context Window Management

**Problem:** AI assistants lose coherence when context exceeds token limits.

**Solutions:**

1. **Service-Scoped Sessions**
   - Develop one service at a time in isolation
   - Load only relevant service code into context
   - Use `CLAUDE.md` + service `README.md` as foundation

2. **Progressive Disclosure**
   - Start with interfaces/types
   - Then core business logic
   - Finally infrastructure concerns

3. **Checkpoint Documentation**
   - After each significant change, update service README
   - Document decisions in ADRs
   - AI sessions can resume from documented state

### 4.2 Code Review Protocol

**Every AI-generated code block must:**
1. Be read and understood by human developer
2. Pass automated tests
3. Be reviewed for security vulnerabilities
4. Be profiled if performance-critical
5. Include error handling for all failure modes

**Red Flags (Auto-reject):**
- Missing error handling
- Hardcoded credentials
- Synchronous blocking in async contexts
- Unbounded loops/recursion
- Missing input validation

---

## 5. SERVICE COMMUNICATION

### 5.1 Message Bus Architecture

**Primary:** RabbitMQ (reliability, mature tooling)
**Event Store:** Apache Kafka (event sourcing, replay capability)

**Message Patterns:**
- **Commands:** Direct service-to-service (RabbitMQ RPC)
- **Events:** Broadcast state changes (Kafka topics)
- **Queries:** Synchronous HTTP/gRPC (limited use)

**Message Schema:**
- All messages defined in Protocol Buffers (`.proto`)
- Versioned schemas (backward compatibility required)
- Schema registry enforced (no runtime schema mismatches)

### 5.2 API Contracts

**External APIs:** REST + OpenAPI 3.1 specifications
**Internal APIs:** gRPC with Protocol Buffers
**Webhooks:** CloudEvents standard

**Contract Testing:**
- Producer provides contract tests
- Consumers verify against contracts
- Breaking changes require major version bump

---

## 6. DEPLOYMENT & ORCHESTRATION

### 6.1 Target Environment

**Platform:** DigitalOcean Kubernetes (DOKS)
**Orchestrator:** Kubernetes 1.28+
**Workflow Engine:** Temporal (distributed saga orchestration)
**Service Mesh:** Istio (observability, traffic management)

### 6.2 Deployment Strategy

**Blue-Green Deployments:**
- Zero-downtime releases
- Instant rollback capability
- Health checks gate traffic switching

**Canary Releases:**
- High-risk changes deployed to 5% traffic
- Automated rollback on error rate increase
- Gradual rollout over 24 hours

### 6.3 System-Level Services

**Critical Daemons (systemd units):**
- `eracun-healthcheck.service` - System-wide health monitoring
- `eracun-deadletter.service` - Failed message reprocessing
- `eracun-audit.service` - Immutable audit log writer

**Cron-Based Tasks:**
- `eracun-daily-report.timer` - Daily reconciliation reports
- `eracun-cert-renewal.timer` - TLS certificate rotation
- `eracun-backup-verification.timer` - Backup integrity checks

---

## 7. OBSERVABILITY

### 7.1 The Three Pillars

**Metrics (Prometheus + Grafana):**
- Request latency (p50, p95, p99)
- Error rates by service
- Queue depths
- Database connection pool utilization

**Logs (ELK Stack or Loki):**
- Structured JSON logs
- Request ID correlation
- Error context preservation

**Traces (Jaeger):**
- End-to-end request flow
- Performance bottleneck identification
- Cross-service dependency visualization

### 7.2 Alerting

**On-Call Severity Levels:**
- **P0 (Page immediately):** Service down, data loss risk
- **P1 (Page in 15min):** Degraded performance, SLA breach risk
- **P2 (Ticket next day):** Non-critical errors, capacity warnings

**Alert Principles:**
- Every alert must be actionable
- No noisy alerts (max 1 false positive per week)
- Runbooks linked in alert descriptions

---

## 8. REGULATORY COMPLIANCE

### 8.1 Croatian E-Invoice Standards

**Mandatory Formats:**
- UBL 2.1 (Universal Business Language)
- EN 16931 (European e-invoicing standard)
- FINA e-Račun schema (Croatia-specific extensions)

**Validation Layers:**
1. **Syntactic:** XSD schema validation
2. **Semantic:** Business rules engine (tax rates, VAT validation)
3. **Cross-Reference:** AI-based anomaly detection
4. **Consensus:** Triple redundancy with majority voting

### 8.2 Audit Requirements

**Immutable Audit Trail:**
- Every document transformation logged
- Original documents retained (S3-compatible storage)
- Cryptographic signatures on audit entries
- 7-year retention period (legal requirement)

---

## 9. DEVELOPMENT WORKFLOW

### 9.1 Git Branching Strategy

**Trunk-Based Development:**
- `main` branch always deployable
- Feature branches max 2 days lifespan
- CI/CD on every commit to `main`

**Branch Naming:**
```
feature/<service-name>/<short-description>
fix/<service-name>/<issue-number>
refactor/<service-name>/<improvement>
```

### 9.2 Commit Standards

**Conventional Commits:**
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `chore`
**Scope:** Service name (e.g., `email-worker`, `schema-validator`)

### 9.3 CI/CD Pipeline

**On Every Commit:**
1. Lint (ESLint, Prettier)
2. Type check (TypeScript strict mode)
3. Unit tests (Jest)
4. Security scan (Snyk, Trivy)
5. Build Docker images
6. Push to registry (only on `main`)

**On Merge to Main:**
7. Integration tests (Testcontainers)
8. Deploy to staging
9. E2E smoke tests
10. Deploy to production (manual approval gate)

---

## 10. PERFORMANCE BUDGETS

**API Response Times:**
- Document upload: <200ms (p95)
- Validation pipeline: <5s (p99)
- XML generation: <1s (p95)
- FINA submission: <3s (p99)

**Resource Limits (per service):**
- Memory: 512MB (burst to 1GB)
- CPU: 0.5 cores (burst to 2 cores)
- Disk I/O: 100 IOPS sustained

**Scalability Targets:**
- 10,000 invoices/hour (initial)
- 100,000 invoices/hour (12-month target)
- Horizontal scaling to 50+ service replicas

---

## 11. DISASTER RECOVERY

### 11.1 Backup Strategy

**RTO (Recovery Time Objective):** 1 hour
**RPO (Recovery Point Objective):** 5 minutes

**Backup Scope:**
- Database: Continuous WAL archiving + daily snapshots
- Object storage: Cross-region replication
- Configuration: Git-versioned IaC

### 11.2 Incident Response

**Runbook Requirements:**
- Every service has failure mode documentation
- Recovery procedures tested quarterly
- Incident commander rotation schedule

---

## 12. OPEN QUESTIONS & CONSTRAINTS

See `TBD.md` for unresolved architectural decisions requiring stakeholder input.

---

## 13. CONTINUOUS IMPROVEMENT

This document is a living artifact. Update it when:
- New architectural patterns are adopted
- Performance budgets change
- Regulatory requirements evolve
- Post-incident learnings require process changes

**Version History:**
- `v1.0.0` - Initial architecture foundation (2025-11-09)

---

**Last Updated:** 2025-11-09
**Document Owner:** System Architect
**Review Cadence:** Monthly
