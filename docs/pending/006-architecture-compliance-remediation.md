# PENDING-006: Architecture Compliance Remediation

**Priority:** 🔴 P0 (Critical)
**Created:** 2025-11-12
**Estimated Effort:** 2-3 weeks (15-20 engineering days)
**Owner:** Platform Engineering Lead + Backend Engineering Team

---

## Problem Statement

**Architectural Audit (2025-11-12) found:**
- ❌ `admin-portal-api` has direct HTTP clients to 3 internal services (health-monitor, cert-lifecycle-manager, dead-letter-handler)
- ❌ `cert-lifecycle-manager` calls notification-service directly (alerting)
- ❌ `health-monitor` calls notification-service directly (alerting)
- ❌ **Total: 5 violations** across 3 services
- ❌ This violates hub-and-spokes architecture (spokes should not call each other directly)
- ❌ Creates tight coupling, deployment dependencies, and cascade failures

**Consequences if not addressed:**
- Services cannot deploy independently (admin-portal requires all 3 services running)
- One service failure cascades to admin-portal
- Cannot scale services horizontally (no service discovery)
- Contract drift risk (endpoint changes break callers without compiler errors)

**Regulatory Impact:**
- Does not directly block 2026-01-01 compliance deadline
- DOES block production scalability and fault tolerance

---

## Scope

### **What Needs Remediation**

**Files to Remediate:**
```
services/admin-portal-api/src/clients/
├── health-monitor.ts          ❌ DELETE (168 lines)
├── cert-lifecycle-manager.ts  ❌ DELETE (~150 lines)
└── dead-letter-handler.ts     ❌ DELETE (~150 lines)

services/cert-lifecycle-manager/src/
└── alerting.ts                ❌ REMEDIATE (replace HTTP with message bus)

services/health-monitor/src/
└── alerting.ts                ❌ REMEDIATE (replace HTTP with message bus)
```

**Total:** ~470 lines to delete + 2 alerting modules to remediate

**Files to Create:**
```
services/admin-portal-api/src/messaging/
├── message-bus.ts             ✅ CREATE (message bus abstraction)
├── health-queries.ts          ✅ CREATE (health-monitor queries via RPC)
├── cert-queries.ts            ✅ CREATE (cert-lifecycle queries via RPC)
└── dlq-queries.ts             ✅ CREATE (dead-letter queries via RPC)

services/health-monitor/src/consumers/
└── query-handler.ts           ✅ CREATE (consume health queries)

services/cert-lifecycle-manager/src/consumers/
└── query-handler.ts           ✅ CREATE (consume cert queries)

services/dead-letter-handler/src/consumers/
└── query-handler.ts           ✅ CREATE (consume DLQ queries)
```

**Total:** ~800 lines of message-driven code

---

## Open Questions Requiring Decisions

1. **Message Bus RPC Pattern:** Use request-reply with correlation IDs OR implement gRPC?
   - **Recommendation:** Request-reply (simpler, already have RabbitMQ)

2. **Query Timeout:** 5 seconds (default) OR 10 seconds for slow queries?
   - **Recommendation:** 5 seconds (force services to optimize)

3. **Caching Strategy:** Cache query results in admin-portal OR always fetch fresh?
   - **Recommendation:** Cache health dashboard for 30 seconds, certs for 5 minutes

4. **Fallback Behavior:** Return stale cached data OR return error when service unavailable?
   - **Recommendation:** Return error (prefer consistency over availability)

---

## Deliverables Required to Close

### **Phase 1: Message Bus Abstraction (Week 1, Days 1-3)**

- [ ] Create message bus client library (`services/admin-portal-api/src/messaging/message-bus.ts`)
- [ ] Implement request-reply pattern with correlation IDs
- [ ] Add timeout handling (5 seconds default)
- [ ] Add retry logic (3 attempts with exponential backoff)
- [ ] Add circuit breaker (open after 5 consecutive failures, half-open after 30s)
- [ ] Add OpenTelemetry tracing (span creation for all requests)
- [ ] Write unit tests (100% coverage required)

**Effort:** 3 days (1 engineer)

---

### **Phase 2: Health-Monitor Query Migration (Week 1, Days 4-5)**

- [ ] Create `services/health-monitor/src/consumers/query-handler.ts`
- [ ] Implement query handlers:
  - `health.query.dashboard` → `GET /health/dashboard` (internal call)
  - `health.query.services` → `GET /health/services`
  - `health.query.external` → `GET /health/external`
  - `health.query.circuit-breakers` → `GET /health/circuit-breakers`
- [ ] Replace `admin-portal-api/src/clients/health-monitor.ts` with message bus queries
- [ ] Update admin-portal route handlers to use new query service
- [ ] Write integration tests (testcontainers: RabbitMQ + health-monitor)
- [ ] Deploy to staging and verify

**Effort:** 2 days (1 engineer)

---

### **Phase 3: Cert-Lifecycle Query Migration (Week 2, Days 1-3)**

- [ ] Create `services/cert-lifecycle-manager/src/consumers/query-handler.ts`
- [ ] Implement query handlers:
  - `cert.query.list` → `GET /v1/certificates`
  - `cert.query.by-id` → `GET /v1/certificates/:id`
  - `cert.query.expiring` → `GET /v1/certificates/expiring`
- [ ] Replace `admin-portal-api/src/clients/cert-lifecycle-manager.ts` with message bus queries
- [ ] Update admin-portal route handlers
- [ ] Write integration tests
- [ ] Deploy to staging and verify

**Effort:** 3 days (1 engineer)

---

### **Phase 4: Dead-Letter Handler Query Migration (Week 2, Days 4-5)**

- [ ] Create `services/dead-letter-handler/src/consumers/query-handler.ts`
- [ ] Implement query handlers:
  - `dlq.query.messages` → `GET /v1/dead-letters`
  - `dlq.query.stats` → `GET /v1/dead-letters/stats`
  - `dlq.command.replay` → `POST /v1/dead-letters/:id/replay`
- [ ] Replace `admin-portal-api/src/clients/dead-letter-handler.ts` with message bus queries
- [ ] Update admin-portal route handlers
- [ ] Write integration tests
- [ ] Deploy to staging and verify

**Effort:** 2 days (1 engineer)

---

### **Phase 5: Architecture Governance (Week 3, Days 1-3)**

- [ ] Install pre-commit hooks (`husky` + `scripts/check-architecture-compliance.sh`)
- [ ] Add CI/CD architecture compliance check (GitHub Actions)
- [ ] Document message contracts in `docs/message-contracts/README.md`
- [ ] Update service registry (`docs/architecture/SERVICE_REGISTRY.md`)
- [ ] Update admin-portal README with new architecture
- [ ] Train team on message-driven patterns (1-hour session)

**Effort:** 3 days (1 DevOps engineer + 1 architect)

---

### **Phase 6: Production Deployment (Week 3, Days 4-5)**

- [ ] Run architecture compliance check (must pass before deploy)
- [ ] Deploy message bus changes to production (rolling deployment)
- [ ] Deploy admin-portal-api to production
- [ ] Verify all queries working via message bus
- [ ] Monitor for errors (circuit breaker trips, timeouts)
- [ ] Rollback plan: Keep HTTP clients commented out for 1 week

**Effort:** 2 days (DevOps + on-call engineer)

---

## What It Blocks

- **Production Scalability:** Cannot scale services independently
- **Fault Tolerance:** One service failure cascades to admin-portal
- **Independent Deployment:** admin-portal deployment requires all 3 services
- **Service Discovery:** Hardcoded URLs prevent dynamic scaling

---

## Why Deferred

**Reason:** ADR-005 (Bounded Context Isolation) was created 2025-11-12 after architectural audit. This is remediation work for existing violations.

**Higher Priority Work (Already Completed):**
- Archive-service architecture design (ADR-004)
- Service skeleton implementation
- Operational runbooks

---

## Estimated Effort

**Total:** 2-3 weeks (15-20 engineering days)

**Breakdown:**
- Phase 1 (message bus abstraction): 3 days
- Phase 2 (health-monitor migration): 2 days
- Phase 3 (cert-lifecycle migration): 3 days
- Phase 4 (dead-letter migration): 2 days
- Phase 5 (governance): 3 days
- Phase 6 (production deployment): 2 days

**Team:** 1 senior backend engineer + 1 DevOps engineer (overlapping work)

---

## Dependencies

- **RabbitMQ:** Already deployed and operational ✅
- **OpenTelemetry:** Already instrumented in all services ✅
- **Protocol Buffers:** Contracts exist in `docs/api-contracts/protobuf/` ✅
- **CI/CD Pipeline:** Must add architecture compliance check (new requirement)

---

## Success Criteria

✅ **Architecture compliance when:**
1. Zero services have `axios` calls to internal services (enforced by pre-commit hook)
2. All admin-portal queries use message bus (request-reply pattern)
3. All services consume queries from dedicated queues
4. Pre-commit hooks block architectural violations (100% enforcement)
5. CI/CD pipeline fails on non-compliance (GitHub Actions check)
6. Service dependency graph shows only message bus connections

---

## Risks & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Message bus latency** | Medium | High | Cache query results (30s for health, 5m for certs) |
| **Timeout handling complexity** | High | Medium | Use battle-tested circuit breaker library (opossum) |
| **Team unfamiliarity with RPC** | Medium | High | 1-hour training session + code examples in docs |
| **Regression bugs** | Medium | High | 100% integration test coverage required before deploy |
| **Production incident** | Low | Critical | Rollback plan: Keep commented HTTP clients for 1 week |

---

## Rollback Plan

**If production issues occur:**

1. Revert admin-portal-api to HTTP clients (uncomment code)
2. Redeploy admin-portal-api
3. Investigate message bus latency/timeout issues
4. Fix and re-test in staging
5. Re-deploy with fixes

**Rollback Time:** <30 minutes (single service redeploy)

---

## References

- **Architectural Audit:** `docs/architecture/MONOREPO_COMPLIANCE_AUDIT.md`
- **Architecture Decision:** `docs/adr/005-bounded-context-isolation.md`
- **Service Registry:** `docs/architecture/SERVICE_REGISTRY.md`
- **Message Contracts:** `docs/message-contracts/README.md`
- **Compliance Script:** `scripts/check-architecture-compliance.sh`
- **CLAUDE.md:** §5.1 (Message Bus Architecture)

---

**Created:** 2025-11-12
**Target Resolution:** 2025-12-05 (before M3 milestone for archive-service)
**Status:** Active
**Next Action:** Approve remediation plan and assign engineers
