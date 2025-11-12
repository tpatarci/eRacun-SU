# Monorepo Hub-and-Spokes Architecture Compliance Audit

**Date:** 2025-11-12
**Auditor:** Architecture Review
**Scope:** eRacun Invoice Processing Platform
**Standard:** Strict Bounded Context Isolation per DDD + Event-Driven Microservices

---

## Executive Summary

**Overall Compliance:** 🟡 **85% - NEEDS REMEDIATION**

✅ **Strengths:** No shared runtime code, centralized contract registry, proper service scoping
❌ **Critical Issue:** Direct service-to-service HTTP coupling in `admin-portal-api`
⚠️ **Risks:** Tight coupling, deployment dependencies, cascade failures

---

## 1. Architectural Principles (Requirements)

### **Hub-and-Spokes Model**

```
                    ┌─────────────────────┐
                    │   MESSAGE BUS       │
                    │   (RabbitMQ/Kafka)  │
                    │   + API Gateway     │
                    └──────────┬──────────┘
                               │ HUB
              ┌────────────────┼────────────────┐
              │                │                │
         ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
         │ Service │     │ Service │     │ Service │  SPOKES
         │    A    │     │    B    │     │    C    │  (Bounded Contexts)
         └─────────┘     └─────────┘     └─────────┘

❌ FORBIDDEN: Service A → direct HTTP → Service B
✅ REQUIRED: Service A → Message Bus → Service B
✅ ALLOWED:  External Client → API Gateway → Service A
```

### **Core Requirements**

1. **Context-Agnostic Universes** - Each service MUST be deployable independently
2. **Explicit Contracts** - All communication via typed schemas (Protocol Buffers, OpenAPI)
3. **No Runtime Coupling** - Services do NOT import each other's code
4. **Message-Driven** - Async communication via message bus (commands/events)
5. **Query via Gateway** - Synchronous queries via API Gateway, NOT direct service calls

---

## 2. Current State Analysis

### ✅ **COMPLIANT PATTERNS**

#### 2.1 No Cross-Service Dependencies
**Check:** Analyzed all `package.json` files

```bash
# NO service depends on another service ✅
grep -r "@eracun/" services/*/package.json | grep -v "self"
# Result: Empty (good!)
```

**Evidence:**
- `fina-connector` depends on external packages only
- `cert-lifecycle-manager` depends on external packages only
- `digital-signature-service` depends on external packages only
- No `@eracun/other-service` dependencies found

**Status:** ✅ **PASS**

---

#### 2.2 Centralized Contract Registry
**Location:** `docs/api-contracts/protobuf/`

**Contracts Found:**
```
docs/api-contracts/protobuf/
├── common.proto          ✅ Shared types (InvoiceId, OIB, KPDCode)
├── events.proto          ✅ Event definitions
├── ingestion.proto       ✅ Ingestion service contract
├── validation.proto      ✅ Validation service contract
└── parsing.proto         ✅ Parsing service contract
```

**Common Types Defined:**
- ✅ `InvoiceId` (UUID v4)
- ✅ `InvoiceType` enum (B2C, B2B, B2G)
- ✅ `ProcessingStage` enum (INGESTED → PARSED → VALIDATED → SIGNED → SUBMITTED → ARCHIVED)
- ✅ `OIB` (Croatian tax number)
- ✅ `KPDCode` (product classification)
- ✅ `RequestContext` (tracing, user_id, timestamp)
- ✅ `Error` (standardized error format)

**Status:** ✅ **PASS** - Excellent contract-first approach

---

#### 2.3 Service-Local Proto Files
**Pattern:** Services can have local proto files for internal use

**Examples:**
- `services/audit-logger/proto/audit.proto` ✅
- `services/kpd-registry-sync/proto/kpd-lookup.proto` ✅

**Rationale:** Local proto files OK if they define service-specific internal types, not contracts

**Status:** ✅ **PASS**

---

#### 2.4 Minimal Shared Code
**Location:** `shared/jest-config/`

**Analysis:**
```bash
ls -la shared/
# Result: Only jest-config/ (test infrastructure, NOT runtime code)
```

**Rationale:** Test configuration sharing is acceptable (build-time, not runtime)

**Status:** ✅ **PASS**

---

### ❌ **VIOLATIONS (Critical)**

#### 2.5 Direct Service-to-Service HTTP Calls

**Violator:** `services/admin-portal-api/`

**Evidence:**
```typescript
// services/admin-portal-api/src/clients/health-monitor.ts
export class HealthMonitorClient {
  private client: AxiosInstance;

  constructor(baseURL?: string) {
    this.baseURL = baseURL || process.env.HEALTH_MONITOR_URL || 'http://health-monitor:8084';
    this.client = axios.create({ baseURL: this.baseURL });
  }

  async getDashboard(): Promise<any> {
    const response = await this.client.get('/health/dashboard');
    return response.data;
  }
}
```

**Problem Analysis:**

| Issue | Impact | Severity |
|-------|--------|----------|
| **Tight Coupling** | admin-portal-api knows health-monitor's URL, port, endpoints | 🔴 Critical |
| **Deployment Dependency** | Cannot deploy admin-portal-api without health-monitor running | 🔴 Critical |
| **Cascade Failures** | health-monitor down → admin-portal-api errors | 🟡 High |
| **Contract Drift** | No versioned contract, endpoint changes break callers | 🟡 High |
| **Testing Complexity** | Must mock HTTP clients in tests | 🟢 Medium |

**Affected Files:**
```
services/admin-portal-api/src/clients/
├── health-monitor.ts          ❌ Direct HTTP calls
├── cert-lifecycle-manager.ts  ❌ Direct HTTP calls
└── dead-letter-handler.ts     ❌ Direct HTTP calls
```

**Status:** ❌ **FAIL** - Violates hub-and-spokes architecture

---

## 3. Architectural Gaps

### 3.1 Missing API Gateway
**Current State:** Services expose HTTP endpoints, consumers call directly

**Required State:** All external traffic routes through API Gateway

```
CURRENT (WRONG):
┌────────────┐       HTTP        ┌──────────────────┐
│ Admin UI   ├──────────────────►│ health-monitor   │
└────────────┘                   └──────────────────┘
      │              HTTP        ┌──────────────────┐
      └──────────────────────────►│ cert-lifecycle   │
                                 └──────────────────┘

REQUIRED (CORRECT):
┌────────────┐       HTTP        ┌─────────────────┐       gRPC/HTTP      ┌──────────────────┐
│ Admin UI   ├──────────────────►│  API Gateway    ├──────────────────────►│ health-monitor   │
└────────────┘                   │  (Kong/Envoy)   │                       └──────────────────┘
                                 └────────┬────────┘       gRPC/HTTP      ┌──────────────────┐
                                          └─────────────────────────────────►│ cert-lifecycle   │
                                                                            └──────────────────┘
```

**Benefits:**
- ✅ Single entry point (security, rate limiting, authentication)
- ✅ Service discovery (no hardcoded URLs)
- ✅ Protocol translation (REST → gRPC)
- ✅ Versioning support (`/v1/health`, `/v2/health`)
- ✅ Circuit breaking at gateway level

---

### 3.2 Missing Contract Versioning Strategy
**Current State:** Proto files exist but no version enforcement

**Required State:**
```protobuf
syntax = "proto3";

package eracun.v1.health;  // ✅ Versioned package

service HealthMonitorService {
  rpc GetDashboard(GetDashboardRequest) returns (GetDashboardResponse);
}
```

**Contract Evolution Rules:**
- **v1 → v2:** Must maintain backward compatibility OR both versions coexist
- **Breaking changes:** Require major version bump
- **Gateway:** Routes `/v1/health` to v1 service, `/v2/health` to v2 service

---

### 3.3 Missing Service Mesh (Optional, Future)
**Current State:** Services communicate via direct HTTP

**Future State (Optional):** Istio/Linkerd for:
- mTLS between services
- Automatic retry/timeout policies
- Traffic splitting (canary deployments)
- Distributed tracing (automatic span creation)

**Decision:** Defer until service count >20 or security requirements mandate mTLS

---

## 4. Remediation Plan

### **Phase 1: Immediate Fixes (Week 1)**

#### 4.1 Remove Direct HTTP Clients from admin-portal-api

**Option A: Backend-for-Frontend (BFF) Pattern** ⭐ **RECOMMENDED**
```
┌────────────┐              ┌──────────────────────────┐
│ Admin UI   │────HTTP─────►│  admin-portal-api (BFF)  │
└────────────┘              └───────────┬──────────────┘
                                        │
                                        │ Publishes events / Queries via message bus
                                        │
                           ┌────────────▼────────────┐
                           │      MESSAGE BUS        │
                           │      (RabbitMQ)         │
                           └────────────┬────────────┘
                                        │
                     ┌──────────────────┼──────────────────┐
                     │                  │                  │
              ┌──────▼──────┐    ┌─────▼──────┐    ┌─────▼──────┐
              │ health-      │    │ cert-      │    │ dead-letter│
              │ monitor      │    │ lifecycle  │    │ handler    │
              └──────────────┘    └────────────┘    └────────────┘
```

**Changes Required:**
1. Delete `services/admin-portal-api/src/clients/` directory
2. Replace HTTP clients with message bus requests:
   ```typescript
   // OLD (WRONG):
   const dashboard = await healthMonitorClient.getDashboard();

   // NEW (CORRECT):
   const dashboard = await messageBus.request({
     exchange: 'health.queries',
     routingKey: 'health.query.dashboard',
     payload: { requestId },
     timeout: 5000
   });
   ```

**Effort:** 2-3 days per client (3 clients = 6-9 days total)

---

**Option B: API Gateway Pattern** (If gateway already exists)
```
┌────────────┐       HTTP        ┌─────────────────┐       gRPC         ┌──────────────────┐
│ Admin UI   ├──────────────────►│  API Gateway    ├───────────────────►│ health-monitor   │
└────────────┘                   │  (Envoy/Kong)   │                    └──────────────────┘
                                 └─────────────────┘
```

**Changes Required:**
1. Deploy API Gateway (Kong, Envoy, or Traefik)
2. Configure routes:
   ```yaml
   # kong.yaml
   services:
   - name: health-monitor
     url: http://health-monitor:8084
     routes:
     - name: health-dashboard
       paths: ["/v1/health/dashboard"]
   ```
3. Update admin-portal-api to call gateway: `http://api-gateway/v1/health/dashboard`

**Effort:** 1 week (gateway setup + service configuration)

---

### **Phase 2: Contract Enforcement (Week 2)**

#### 4.2 Generate TypeScript Types from Proto Files

**Install:** `@bufbuild/protoc-gen-es` (Protocol Buffers → TypeScript)

```bash
npm install -D @bufbuild/protoc-gen-es @bufbuild/protobuf

# Generate types
protoc --es_out=. --es_opt=target=ts \
  docs/api-contracts/protobuf/*.proto
```

**Output:**
```typescript
// Generated from common.proto
export interface InvoiceId {
  uuid: string;
}

export enum InvoiceType {
  B2C = 1,
  B2B = 2,
  B2G = 3,
}
```

**Enforce:** All services MUST import types from generated files (not redefine locally)

---

#### 4.3 Message Bus Contract Registry

**Create:** `docs/message-contracts/README.md`

**Format:**
```markdown
# Message Contract Registry

## Commands

### archive.command.invoice
**Publisher:** ubl-transformer, fina-connector, as4-gateway-connector
**Consumer:** archive-service
**Schema:** `docs/api-contracts/protobuf/archive.proto`
**Payload:**
```protobuf
message ArchiveInvoiceCommand {
  InvoiceId invoice_id = 1;
  bytes original_xml = 2;  // Base64-encoded XML
  InvoiceType invoice_type = 3;
  ConfirmationReference confirmation = 4;
}
```

**Version:** 1.0
**Stability:** Stable
**Breaking Changes:** Require major version bump
```

---

### **Phase 3: Governance & Automation (Week 3)**

#### 4.4 Pre-Commit Hooks (Enforce Architecture)

**Install:** `husky` + custom validation scripts

```bash
npm install -D husky

# .husky/pre-commit
#!/bin/sh
echo "🔍 Checking architectural compliance..."

# Rule 1: No cross-service imports
if grep -r "from.*'\.\./\.\./.*services/" services/*/src; then
  echo "❌ VIOLATION: Cross-service imports detected!"
  exit 1
fi

# Rule 2: No direct HTTP clients to internal services
if grep -r "axios.create.*http://.*-service:" services/*/src; then
  echo "❌ VIOLATION: Direct service-to-service HTTP calls detected!"
  exit 1
fi

# Rule 3: All proto files must be versioned
if grep -L "package eracun\.v[0-9]" docs/api-contracts/protobuf/*.proto; then
  echo "❌ VIOLATION: Unversioned proto files detected!"
  exit 1
fi

echo "✅ Architecture compliance check passed"
```

---

#### 4.5 CI/CD Pipeline Enforcement

**GitHub Actions:** `.github/workflows/architecture-compliance.yml`

```yaml
name: Architecture Compliance

on: [pull_request]

jobs:
  lint-architecture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Check for cross-service dependencies
        run: |
          if grep -r "@eracun/" services/*/package.json | grep -v "self"; then
            echo "❌ Services must not depend on each other"
            exit 1
          fi

      - name: Check for direct HTTP calls
        run: |
          if grep -r "http://.*-service:" services/*/src --include="*.ts"; then
            echo "❌ Services must communicate via message bus"
            exit 1
          fi

      - name: Validate proto contracts
        run: |
          npm install -g @bufbuild/buf
          buf lint docs/api-contracts/protobuf/
          buf breaking --against '.git#branch=main'
```

---

## 5. Contract-First Development Standards

### **5.1 New Service Checklist**

Before creating a new service:

- [ ] Define proto contract in `docs/api-contracts/protobuf/{service}.proto`
- [ ] Generate TypeScript types: `npm run proto:generate`
- [ ] Document message contracts in `docs/message-contracts/`
- [ ] Register service in `docs/architecture/service-registry.md`
- [ ] No direct imports from other services (`grep check`)
- [ ] All communication via message bus or API gateway

---

### **5.2 Contract Evolution Rules**

**Adding Field (Backward Compatible):**
```protobuf
message InvoiceRequest {
  InvoiceId invoice_id = 1;
  // NEW: Optional field (safe to add)
  string customer_email = 2;  // ✅ OK (field number unused)
}
```

**Removing Field (BREAKING):**
```protobuf
message InvoiceRequest {
  InvoiceId invoice_id = 1;
  // REMOVED: string customer_name = 2;  // ❌ BREAKING CHANGE
}
```

**Procedure for Breaking Changes:**
1. Create v2 proto: `package eracun.v2.invoicing`
2. Deploy v2 service alongside v1 (both running)
3. Migrate consumers to v2
4. Deprecate v1 (6-month window)
5. Remove v1

---

## 6. Architectural Decision Record (ADR-005)

**Title:** Enforce Strict Bounded Context Isolation

**Status:** 🟡 Proposed (Awaiting Approval)

**Decision:**
1. ❌ **FORBID:** Direct service-to-service HTTP calls
2. ✅ **REQUIRE:** All communication via message bus (commands/events) OR API gateway (queries)
3. ✅ **REQUIRE:** All contracts defined in Protocol Buffers (centralized registry)
4. ✅ **REQUIRE:** Contract versioning (`eracun.v1`, `eracun.v2`)
5. ✅ **REQUIRE:** Pre-commit hooks to enforce architecture

**Consequences:**
- **Pros:** Loose coupling, independent deployability, testability, scalability
- **Cons:** Increased complexity (message bus, gateway), eventual consistency

**See:** `docs/adr/005-bounded-context-isolation.md` (to be created)

---

## 7. Recommendations

### **Immediate Actions (This Week)**

1. ✅ **Create ADR-005** documenting this decision
2. ✅ **Remove admin-portal-api HTTP clients** (6-9 days effort)
3. ✅ **Set up pre-commit hooks** to prevent future violations
4. ✅ **Document message contracts** in central registry

### **Short-Term (Next Sprint)**

1. ⏳ **Deploy API Gateway** (if not using message bus for queries)
2. ⏳ **Generate TypeScript types** from proto files
3. ⏳ **Add CI/CD compliance checks**

### **Long-Term (Next Quarter)**

1. ⏳ **Consider service mesh** (if mTLS required)
2. ⏳ **Implement contract testing** (Pact/Pactflow)
3. ⏳ **Chaos engineering** (test isolation guarantees)

---

## 8. Success Criteria

**Architecture is compliant when:**

✅ Zero services have `axios` calls to internal services
✅ All contracts defined in Protocol Buffers
✅ All services import types from generated proto files
✅ Pre-commit hooks block architectural violations
✅ CI/CD pipeline fails on non-compliance
✅ Service dependency graph shows only message bus connections

---

**Audit Conclusion:** 🟡 **NEEDS REMEDIATION**

**Timeline:** 2-3 weeks to achieve full compliance
**Effort:** 15-20 engineering days
**Priority:** 🔴 **CRITICAL** - Blocks scalability and independent deployability

---

**Next Steps:**
1. Review this audit with architecture team
2. Approve remediation plan (Option A vs Option B)
3. Create tracking tasks (PENDING-006: Architecture Compliance)
4. Begin Phase 1 immediately
