# ADR-005: Enforce Strict Bounded Context Isolation

**Status:** 🟢 Accepted
**Date:** 2025-11-12
**Deciders:** System Architect, Platform Engineering Lead
**Technical Story:** Prevent tight coupling and ensure independent service deployability

---

## Context

The eRacun monorepo contains 20+ microservices implementing event-driven CQRS architecture. To achieve the core benefit of microservices—**independent deployability and scalability**—we must enforce strict bounded context isolation per Domain-Driven Design principles.

**Problem Identified:**
- `admin-portal-api` contains direct HTTP clients to 3 internal services (health-monitor, cert-lifecycle-manager, dead-letter-handler)
- This creates tight coupling: deploying admin-portal-api requires all 3 services to be running
- No API Gateway exists to provide service discovery and protocol translation
- Contract drift risk: services can change endpoints without compiler errors

**Consequences if not addressed:**
- Cannot deploy services independently (deployment dependencies)
- Cascade failures (one service down → multiple services fail)
- Testing complexity (must mock HTTP clients for every test)
- Cannot scale services horizontally (no service discovery)
- Violates hub-and-spokes architecture (spokes calling each other directly)

---

## Decision

We will enforce **strict bounded context isolation** with the following rules:

### **Rule 1: No Direct Service-to-Service HTTP Calls** ❌

**Forbidden:**
```typescript
// ❌ WRONG: Direct HTTP call to internal service
const response = await axios.get('http://health-monitor:8084/health/dashboard');
```

**Required:**
```typescript
// ✅ CORRECT: Request via message bus (RPC pattern)
const response = await messageBus.request({
  exchange: 'health.queries',
  routingKey: 'health.query.dashboard',
  payload: { requestId },
  timeout: 5000
});
```

**Rationale:**
- Services become independently deployable (no knowledge of URLs)
- Message bus provides built-in retry, circuit breaking, load balancing
- Service discovery handled by message broker (no hardcoded addresses)

---

### **Rule 2: All Contracts Defined in Protocol Buffers** ✅

**Required:** Centralized contract registry in `docs/api-contracts/protobuf/`

```protobuf
syntax = "proto3";

package eracun.v1.health;  // Versioned package

service HealthMonitorService {
  rpc GetDashboard(GetDashboardRequest) returns (GetDashboardResponse);
}

message GetDashboardRequest {
  string request_id = 1;
}

message GetDashboardResponse {
  repeated ServiceStatus services = 1;
  int64 timestamp = 2;
}
```

**Rationale:**
- Type-safe contracts (compile-time errors on breaking changes)
- Versioning support (v1, v2 coexist during migration)
- Language-agnostic (can generate Go, Java, Python clients if needed)
- Schema evolution rules (backward/forward compatibility)

---

### **Rule 3: Message Bus for Commands/Events, Gateway for Queries** ✅

**Architecture:**

```
┌─────────────────┐
│   EXTERNAL      │
│   CLIENTS       │
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐       ┌──────────────────┐
│  API Gateway    │──────►│  admin-portal    │
│  (Kong/Envoy)   │       │  (BFF)           │
└─────────────────┘       └────────┬─────────┘
                                   │
                                   │ Publishes/Subscribes
                                   ▼
                          ┌────────────────────┐
                          │   MESSAGE BUS      │
                          │   (RabbitMQ)       │
                          └──────────┬─────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
       ┌──────▼──────┐        ┌─────▼──────┐       ┌──────▼──────┐
       │ health-     │        │ cert-      │       │ archive-    │
       │ monitor     │        │ lifecycle  │       │ service     │
       └─────────────┘        └────────────┘       └─────────────┘
```

**Commands/Events:** Async via RabbitMQ (fire-and-forget or request-reply)
**Queries:** Sync via API Gateway (if needed) OR request-reply via message bus

---

### **Rule 4: Contract Versioning** ✅

**Package Naming:**
```protobuf
package eracun.v1.health;  // Version 1
package eracun.v2.health;  // Version 2 (breaking changes)
```

**Evolution Rules:**
- **Adding optional fields:** Backward compatible (patch/minor version)
- **Removing fields:** Breaking change (major version)
- **Changing field types:** Breaking change (major version)

**Migration Process:**
1. Deploy v2 service alongside v1 (both running)
2. Update consumers to v2 (gradual rollout)
3. Deprecate v1 (mark as obsolete, 6-month window)
4. Remove v1

---

### **Rule 5: Pre-Commit Enforcement** ✅

**Automated Checks:**
```bash
#!/bin/sh
# .husky/pre-commit

# Check for cross-service imports
if grep -r "from.*'\.\./\.\./.*services/" services/*/src; then
  echo "❌ VIOLATION: Cross-service imports detected"
  exit 1
fi

# Check for direct HTTP calls to internal services
if grep -r "http://.*-service:" services/*/src --include="*.ts"; then
  echo "❌ VIOLATION: Direct service HTTP calls detected"
  exit 1
fi

# Check for unversioned proto files
if grep -L "package eracun\.v[0-9]" docs/api-contracts/protobuf/*.proto; then
  echo "❌ VIOLATION: Unversioned proto files detected"
  exit 1
fi
```

**CI/CD Pipeline:**
- Architecture compliance check runs on every PR
- Breaks build if violations detected
- Requires manual override with justification

---

## Remediation Plan

### **Phase 1: Immediate (Week 1-2)**

**Remove admin-portal-api HTTP clients:**

1. **Delete files:**
   ```
   services/admin-portal-api/src/clients/
   ├── health-monitor.ts          ❌ DELETE
   ├── cert-lifecycle-manager.ts  ❌ DELETE
   └── dead-letter-handler.ts     ❌ DELETE
   ```

2. **Replace with message bus RPC:**
   ```typescript
   // services/admin-portal-api/src/services/health-service.ts
   import { MessageBus } from '../messaging/message-bus';

   export class HealthService {
     constructor(private messageBus: MessageBus) {}

     async getDashboard(requestId: string): Promise<DashboardData> {
       const response = await this.messageBus.request({
         exchange: 'health.queries',
         routingKey: 'health.query.dashboard',
         payload: { requestId },
         timeout: 5000,
         correlationId: requestId
       });

       return response.data;
     }
   }
   ```

3. **Update health-monitor to consume queries:**
   ```typescript
   // services/health-monitor/src/consumers/query-handler.ts
   messageBus.consume({
     queue: 'health-monitor.queries',
     handler: async (msg) => {
       if (msg.routingKey === 'health.query.dashboard') {
         const dashboard = await getDashboardData();
         return { data: dashboard };
       }
     }
   });
   ```

**Effort:** 6-9 days (2-3 days per client)

---

### **Phase 2: Governance (Week 2-3)**

1. ✅ Install pre-commit hooks (`husky`)
2. ✅ Add CI/CD architecture checks
3. ✅ Document message contracts in registry
4. ✅ Generate TypeScript types from proto files

**Effort:** 3-4 days

---

## Consequences

### **Positive**

- ✅ **Independent Deployability** - Services can deploy without dependencies
- ✅ **Fault Isolation** - One service failure doesn't cascade
- ✅ **Testability** - Services test in isolation (no HTTP mocking)
- ✅ **Scalability** - Services scale independently based on load
- ✅ **Contract Safety** - Proto files provide compile-time validation
- ✅ **Service Discovery** - Message bus handles routing (no hardcoded URLs)

### **Negative**

- ❌ **Increased Complexity** - Message bus adds operational overhead
- ❌ **Eventual Consistency** - Async communication requires careful design
- ❌ **Debugging Difficulty** - Distributed tracing required for request flows
- ❌ **Learning Curve** - Team must learn message-driven architecture

### **Mitigation**

- **Complexity:** Provide message bus abstractions (simple request/reply API)
- **Consistency:** Use request-reply pattern for queries (looks like sync call)
- **Debugging:** Enforce OpenTelemetry tracing (correlation IDs in all messages)
- **Learning:** Architecture training session + code examples in docs

---

## Alternatives Considered

### **Alternative 1: Service Mesh (Istio/Linkerd)**

**Pros:**
- Transparent service discovery (no code changes)
- Automatic mTLS, retry, circuit breaking

**Cons:**
- Operational complexity (control plane, sidecars)
- Resource overhead (sidecar per pod = 2x memory)
- Still requires proto contracts for type safety

**Decision:** Defer until service count >20 OR mTLS mandate

---

### **Alternative 2: API Gateway for Internal Communication**

**Pros:**
- Centralized routing, rate limiting, authentication

**Cons:**
- Gateway becomes single point of failure
- Adds latency (extra network hop)
- Doesn't solve async communication (still need message bus)

**Decision:** Use gateway for external→internal only, message bus for internal→internal

---

### **Alternative 3: Shared NPM Packages**

**Pros:**
- Direct function calls (looks simple)

**Cons:**
- Tight coupling (services can't deploy independently)
- Violates bounded contexts (shared runtime state)
- Deployment hell (change shared package → redeploy all services)

**Decision:** Rejected. Only shared test config allowed.

---

## Enforcement Checklist

**New Service:**
- [ ] Proto contract defined in `docs/api-contracts/protobuf/{service}.proto`
- [ ] TypeScript types generated: `npm run proto:generate`
- [ ] Message contracts documented in `docs/message-contracts/`
- [ ] No `axios` calls to internal services
- [ ] Service registered in `docs/architecture/service-registry.md`

**Code Review:**
- [ ] No cross-service imports (`grep check`)
- [ ] No hardcoded service URLs (`grep "http://.*-service:"`)
- [ ] All message handlers have correlation ID propagation
- [ ] OpenTelemetry spans created for all operations

**CI/CD:**
- [ ] Architecture compliance check passes
- [ ] Contract breaking change detection runs (`buf breaking`)
- [ ] No service-to-service HTTP calls detected

---

## References

- **CLAUDE.md §5.1** - Message Bus Architecture (RabbitMQ + Kafka)
- **CLAUDE.md §5.2** - API Contracts (gRPC + Protocol Buffers)
- **MONOREPO_COMPLIANCE_AUDIT.md** - Detailed violation analysis
- **Domain-Driven Design (Evans)** - Bounded Context pattern
- **Building Microservices (Newman)** - Service independence principles

---

**Decision Outcome:** ✅ **ACCEPTED**

**Rationale:** The benefits of independent deployability and fault isolation outweigh the complexity cost. Message-driven architecture is industry-standard for microservices at scale.

**Next Actions:**
1. Create PENDING-006 tracking remediation work
2. Remove admin-portal-api HTTP clients (6-9 days)
3. Install pre-commit hooks
4. Train team on message-driven patterns

---

**Last Updated:** 2025-11-12
**Document Owner:** System Architect
**Review Cadence:** Quarterly
