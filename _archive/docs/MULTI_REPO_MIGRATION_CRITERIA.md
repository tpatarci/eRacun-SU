# Multi-Repository Migration Criteria

## Purpose
This document defines the rules and criteria for decomposing the eRačun monorepo into a multi-repository architecture. These criteria ensure consistency, maintainability, and clear boundaries during and after migration.

---

## 1. Repository Boundary Rules

### Rule 1.1: Single Bounded Context per Repository
**Criteria:** Each repository must represent exactly one bounded context from Domain-Driven Design.

**Indicators to SPLIT:**
- Different domain language/terminology used
- Different business stakeholders/owners
- Independent business processes
- No shared domain models needed

**Indicators to KEEP TOGETHER:**
- Shared domain models that change in lockstep
- Single business process implementation
- Same team ownership
- Transaction boundaries require atomicity

### Rule 1.2: Team Ownership Alignment
**Criteria:** One repository should be owned by one team (2-5 developers).

**Implementation:**
- Each repository has a CODEOWNERS file
- Single team responsible for CI/CD pipeline
- On-call rotation aligned with repo ownership
- Team can deploy independently

### Rule 1.3: Deployment Coupling
**Criteria:** Services that must be deployed together belong in the same repository.

**SPLIT if:**
- Services can be deployed independently
- Different deployment schedules needed
- Different SLA requirements
- Independent scaling requirements

**KEEP TOGETHER if:**
- Coordinated deployment required
- Shared infrastructure resources
- Single Kubernetes deployment/pod
- Database migration dependencies

---

## 2. Service Granularity Rules

### Rule 2.1: Size Limits
**Maximum per repository:**
- 15,000 lines of code (excluding tests)
- 5 services maximum
- 10 developer contributors

**Minimum per repository:**
- 2,000 lines of code (excluding tests)
- 1 complete bounded context
- Clear business value

### Rule 2.2: Change Frequency Correlation
**Criteria:** Measure co-change frequency over last 6 months.

**Decision matrix:**
- >70% commits touch both services → KEEP TOGETHER
- 30-70% commits touch both → EVALUATE COUPLING
- <30% commits touch both → SPLIT

### Rule 2.3: Data Boundary Enforcement
**Strict rules:**
- No shared database schemas between repos
- Each repo owns its database/schema
- Cross-repo data access only via APIs or events
- No distributed transactions

---

## 3. Shared Code Extraction Rules

### Rule 3.1: Rule of Three
**Criteria:** Code becomes a shared library only after appearing in 3+ repositories.

**Process:**
1. First occurrence: Keep in service
2. Second occurrence: Duplicate (intentionally)
3. Third occurrence: Extract to shared library
4. Document the extraction decision

### Rule 3.2: Stability Requirements
**Shared library criteria:**
- API stable for >3 months
- Comprehensive test coverage (>95%)
- Semantic versioning enforced
- Backward compatibility for 2 major versions

### Rule 3.3: Dependency Direction
**Allowed dependencies:**
```
Services → Shared Libraries → Contracts
Services → Infrastructure Libraries
Services ✗ Services (direct dependency forbidden)
```

**Forbidden patterns:**
- Circular dependencies
- Service-to-service compile-time dependencies
- Shared libraries depending on services

---

## 4. Communication Pattern Rules

### Rule 4.1: Synchronous vs Asynchronous
**Use SYNCHRONOUS (HTTP/gRPC) when:**
- Response needed within same user request (<100ms)
- Simple query operations
- Strong consistency required
- Request-response pattern

**Use ASYNCHRONOUS (RabbitMQ/Kafka) when:**
- Response time >100ms acceptable
- Fire-and-forget operations
- Event notification patterns
- Workflow/saga orchestration

### Rule 4.2: Contract Ownership
**Protocol Buffer/AsyncAPI contracts:**
- Owned by the service repository that PRODUCES the API
- Versioned independently
- Published to central schema registry
- Breaking changes require major version bump

### Rule 4.3: Integration Testing
**Cross-repo integration tests:**
- Separate integration test repository
- Runs on schedule (not on every commit)
- Uses released versions (not latest)
- Contract testing preferred over E2E

---

## 5. Migration Sequencing Rules

### Rule 5.1: Migration Order Priority
**Priority order (highest first):**
1. **Leaf services** - No other services depend on them
2. **Stable services** - <5 commits in last month
3. **Clean boundaries** - No shared database access
4. **Single team** - Clear ownership
5. **High value** - Business critical but isolated

### Rule 5.2: Parallel Run Requirements
**During migration phase:**
- Both monorepo and multi-repo versions run
- Feature flags control traffic routing
- Gradual traffic shift (canary deployment)
- Rollback plan documented and tested

### Rule 5.3: Migration Completion Criteria
**Service is fully migrated when:**
- [ ] All traffic routed to new repo (100%)
- [ ] Monorepo version deleted
- [ ] CI/CD pipeline fully operational
- [ ] Monitoring/alerting configured
- [ ] Team trained on new workflow
- [ ] 2 weeks stable in production

---

## 6. Repository Naming and Structure

### Rule 6.1: Naming Convention
```
eracun-{bounded-context}
eracun-lib-{capability}
eracun-adapter-{external-system}
```

**Examples:**
- `eracun-invoice-validation`
- `eracun-lib-messaging`
- `eracun-adapter-fina`

### Rule 6.2: Repository Structure
```
repository-root/
├── src/               # Source code
├── tests/             # Tests
├── api/               # API contracts (OpenAPI/Proto)
├── docs/              # Documentation
├── deployment/        # K8s manifests, Terraform
├── .github/           # CI/CD workflows
├── CODEOWNERS        # Team ownership
├── README.md         # Purpose, setup, API docs
└── MIGRATION.md      # Migration status/notes
```

---

## 7. Decision Criteria Checklist

### When Evaluating a Service Group for Extraction:

**Technical Criteria:**
- [ ] Can be built independently?
- [ ] Can be deployed independently?
- [ ] Can be tested independently?
- [ ] Has clear API boundaries?
- [ ] No shared database access?

**Organizational Criteria:**
- [ ] Single team ownership?
- [ ] Clear business domain?
- [ ] Independent stakeholders?
- [ ] Separate budget/resources?

**Operational Criteria:**
- [ ] Different scaling needs?
- [ ] Different SLA requirements?
- [ ] Different deployment frequency?
- [ ] Independent monitoring needs?

**Score:**
- 10-12 ✓ → **DEFINITELY SPLIT**
- 7-9 ✓ → **PROBABLY SPLIT** (review coupling)
- 4-6 ✓ → **PROBABLY KEEP** (review benefits)
- 0-3 ✓ → **DEFINITELY KEEP**

---

## 8. Anti-Patterns to Avoid

### ❌ **Distributed Monolith**
Creating separate repos but maintaining tight coupling through synchronous calls.

### ❌ **Chatty Services**
Excessive service-to-service communication for single operations.

### ❌ **Shared Database**
Multiple repositories accessing same database schema.

### ❌ **Premature Extraction**
Splitting services before understanding boundaries.

### ❌ **Big Bang Migration**
Attempting to migrate everything simultaneously.

### ❌ **Missing Observability**
Splitting without distributed tracing and correlation IDs.

---

## 9. Success Metrics

### Measure SUCCESS by:
- **Deployment frequency** increases by >50%
- **Mean time to recovery** decreases by >30%
- **Cross-team dependencies** decrease by >60%
- **Build time** decreases to <5 minutes per repo
- **Cognitive load** (survey) improves by >40%

### Measure FAILURE by:
- **Integration bugs** increase by >20%
- **Deployment coordination** meetings increase
- **Rollback frequency** increases by >30%
- **Developer satisfaction** decreases
- **Time to onboard** new developers increases

---

## 10. Governance

### Architecture Review Board
**Composition:**
- 1 representative per team
- 1 DevOps/Platform engineer
- 1 Security representative
- 1 Business stakeholder

**Responsibilities:**
- Review repository split proposals
- Approve shared library extractions
- Resolve boundary disputes
- Monitor migration metrics

### Migration Approval Process
1. **Proposal:** Team submits migration plan using criteria
2. **Review:** Architecture board evaluates (1 week SLA)
3. **Pilot:** Implement with feature flags
4. **Measure:** Run for 2 weeks, collect metrics
5. **Decision:** Go/No-go based on success criteria
6. **Execute:** Full migration with parallel run
7. **Cleanup:** Remove monorepo version

---

**Document Version:** 1.0.0
**Last Updated:** 2024-11-15
**Review Cycle:** Monthly during migration, Quarterly post-migration
**Owner:** Platform Architecture Team