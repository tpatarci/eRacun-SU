# CLAUDE.md - KPD Registry Sync Service

**Service:** `kpd-registry-sync`
**Layer:** Management (Layer 10)
**Implementation Status:** 🔴 Not Started
**Your Mission:** Implement this service from specification to production-ready

---

## 1. YOUR MISSION

You are implementing the **kpd-registry-sync** service for the eRacun e-invoice processing platform. This service maintains the **local cache of Croatian product classification codes** (KLASUS 2025), which are **mandatory for every invoice line item**.

**What you're building:**
- DZS KLASUS API consumer (fetch official KPD code registry)
- PostgreSQL local cache (fast lookups, no external dependency during validation)
- Daily sync scheduler (keep codes up-to-date)
- gRPC lookup API (provides KPD codes to kpd-validator service)

**Estimated effort:** 2-3 days
**Complexity:** Low (~800 LOC)

---

## 2. REQUIRED READING (Read in Order)

**Before writing any code, read these documents:**

1. **`README.md`** (in this directory) - Complete service specification
2. **`/CLAUDE.md`** (repository root) - System architecture and standards
3. **`/CROATIAN_COMPLIANCE.md`** - KPD code requirements (MANDATORY)
4. **`/docs/TODO-008-cross-cutting-concerns.md`** - Observability requirements (MANDATORY)
5. **`/services/xsd-validator/`** - Reference implementation pattern
6. **`/services/schematron-validator/`** - Reference observability module

**Time investment:** 25-35 minutes reading
**Why mandatory:** Prevents rework, ensures compliance with Croatian fiscalization law, establishes patterns

---

## 3. ARCHITECTURAL CONTEXT

### 3.1 Where This Service Fits

```
            ┌────────────────────┐
            │  DZS KLASUS API    │
            │  (Croatian Bureau  │
            │   of Statistics)   │
            │  api.dzs.hr        │
            └────────┬───────────┘
                     │
                     │ Fetch KPD codes (daily)
                     ▼
            ┌────────────────────┐
            │  THIS SERVICE      │
            │  kpd-registry-sync │
            └────────┬───────────┘
                     │
                     │ Store in local cache
                     ▼
            ┌────────────────────┐
            │  PostgreSQL        │
            │  kpd_codes         │
            │  (50,000 codes)    │
            └────────┬───────────┘
                     │
                     │ gRPC lookup API
                     ▼
            ┌────────────────────┐
            │  kpd-validator     │
            │  (validates        │
            │   invoice line     │
            │   item codes)      │
            └────────────────────┘
                     │
                     │ HTTP REST API
                     ▼
            ┌────────────────────┐
            │  admin-portal-api  │
            │  (KPD code search) │
            └────────────────────┘
```

### 3.2 Critical Dependencies

**Upstream (Consumes From):**
- DZS KLASUS API: `https://api.dzs.hr/klasus/v1/codes?version=2025` (hypothetical)
- OR CSV/XML file download from DZS portal

**Downstream (Produces To):**
- PostgreSQL table: `kpd_codes` (local cache)
- gRPC API: `LookupKPDCode(code)` → `KPDCodeInfo`
- HTTP REST API: `/api/v1/kpd/codes` (for admin portal)

**Consumed By:**
- `kpd-validator` service (validates invoice line item KPD codes)
- `admin-portal-api` (KPD code search/lookup)

### 3.3 KPD Code Schema

**PostgreSQL:**

```sql
CREATE TABLE kpd_codes (
  id BIGSERIAL PRIMARY KEY,
  kpd_code VARCHAR(10) NOT NULL UNIQUE,  -- e.g., "010101"
  description TEXT NOT NULL,              -- Product/service description
  level INT NOT NULL,                     -- Hierarchy level (1-6)
  parent_code VARCHAR(10),                -- Parent code (if level > 1)
  active BOOLEAN DEFAULT true,
  effective_from DATE NOT NULL,
  effective_to DATE,                      -- NULL if still active
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_kpd_code ON kpd_codes(kpd_code, active);
CREATE INDEX idx_kpd_parent ON kpd_codes(parent_code);
```

**gRPC API Schema:**

```protobuf
service KPDLookupService {
  rpc LookupCode(LookupCodeRequest) returns (LookupCodeResponse);
  rpc ValidateCode(ValidateCodeRequest) returns (ValidateCodeResponse);
}

message LookupCodeRequest {
  string kpd_code = 1;
}

message LookupCodeResponse {
  bool found = 1;
  KPDCodeInfo code_info = 2;
}

message KPDCodeInfo {
  string kpd_code = 1;
  string description = 2;
  int32 level = 3;
  string parent_code = 4;
  bool active = 5;
}

message ValidateCodeRequest {
  string kpd_code = 1;
}

message ValidateCodeResponse {
  bool valid = 1;
  string error_message = 2;
}
```

---

## 4. IMPLEMENTATION WORKFLOW

**Follow this sequence strictly:**

### Phase 1: Setup (Day 1, Morning)

1. **Create package.json**
   ```bash
   npm init -y
   npm install --save axios csv-parser pg @grpc/grpc-js @grpc/proto-loader express node-cron prom-client pino opentelemetry
   npm install --save-dev typescript @types/node @types/pg @types/express jest @types/jest ts-jest
   ```

2. **Create tsconfig.json** (strict mode)
   ```json
   {
     "compilerOptions": {
       "target": "ES2022",
       "module": "commonjs",
       "strict": true,
       "esModuleInterop": true,
       "outDir": "./dist"
     }
   }
   ```

3. **Create directory structure**
   ```
   src/
   ├── index.ts              # Main entry (gRPC + HTTP API + cron)
   ├── sync.ts               # DZS KLASUS sync logic
   ├── repository.ts         # PostgreSQL KPD code operations
   ├── grpc-server.ts        # gRPC lookup API
   ├── api.ts                # HTTP REST API (admin portal)
   └── observability.ts      # Metrics, logs, traces (TODO-008)
   proto/
   └── kpd-lookup.proto      # gRPC service definition
   tests/
   ├── setup.ts
   ├── fixtures/
   │   └── klasus-codes.csv  # Sample KPD codes
   ├── unit/
   │   ├── sync.test.ts
   │   ├── repository.test.ts
   │   └── observability.test.ts
   └── integration/
       ├── grpc-api.test.ts
       └── sync-flow.test.ts
   ```

### Phase 2: Core Implementation (Day 1 Afternoon - Day 2)

1. **Implement observability.ts FIRST** (TODO-008 compliance)
   - Copy pattern from `/services/xsd-validator/src/observability.ts`
   - Define 5+ Prometheus metrics (see README.md Section 7)
   - Structured logging (Pino)
   - Distributed tracing (OpenTelemetry)
   - No PII (KPD codes are public data)

2. **Implement repository.ts** (PostgreSQL operations)
   - Connection pool (min: 10, max: 50)
   - `insertKPDCode(code: KPDCode): Promise<void>`
   - `updateKPDCode(code: KPDCode): Promise<void>`
   - `softDeleteKPDCode(code: string): Promise<void>` (set active = false)
   - `getAllKPDCodes(): Promise<KPDCode[]>`
   - `getKPDCode(code: string): Promise<KPDCode | null>`
   - `searchKPDCodes(query: string): Promise<KPDCode[]>` (description search)

3. **Implement sync.ts** (DZS KLASUS sync logic)
   - `syncKPDCodes(): Promise<void>`
   - Steps:
     1. Fetch from DZS API or CSV file
     2. Parse response (CSV or JSON)
     3. Compare with local database
     4. Identify new/updated/deleted codes
     5. Apply changes to PostgreSQL
     6. Log sync statistics
     7. Publish sync event to Kafka (optional)
   - Algorithm:
     ```typescript
     async function syncKPDCodes() {
       logger.info('Starting KPD registry sync');

       // Fetch from DZS
       const response = await axios.get(DZS_KLASUS_API_URL);
       const remoteCodes = parseKPDResponse(response.data);

       // Compare with local
       const localCodes = await getAllKPDCodes();
       const { toAdd, toUpdate, toDelete } = compareCodes(remoteCodes, localCodes);

       // Apply changes
       for (const code of toAdd) {
         await insertKPDCode(code);
       }
       for (const code of toUpdate) {
         await updateKPDCode(code);
       }
       for (const code of toDelete) {
         await softDeleteKPDCode(code.kpd_code);
       }

       // Metrics
       kpdCodesSynced.inc({ action: 'added' }, toAdd.length);
       kpdCodesSynced.inc({ action: 'updated' }, toUpdate.length);
       kpdCodesSynced.inc({ action: 'deleted' }, toDelete.length);

       logger.info(`KPD sync complete: +${toAdd.length}, ~${toUpdate.length}, -${toDelete.length}`);
     }
     ```

4. **Implement grpc-server.ts** (gRPC lookup API)
   - Define `.proto` file (see Section 3.3)
   - Implement 2 RPC methods:
     - `LookupCode(code)` → Find KPD code in database
     - `ValidateCode(code)` → Check if code exists and is active
   - gRPC server on port 50052

5. **Implement api.ts** (HTTP REST API)
   - Express server (port 8088)
   - Endpoints:
     - GET `/api/v1/kpd/codes` - List all KPD codes (paginated)
     - GET `/api/v1/kpd/codes/:code` - Get specific KPD code details
     - GET `/api/v1/kpd/search?q=cattle` - Search KPD codes by description
     - POST `/api/v1/kpd/sync/trigger` - Manually trigger sync
     - GET `/api/v1/kpd/sync/status` - Last sync status
   - Pagination: 100 codes per page (default)

6. **Implement index.ts** (Main entry point)
   - Start gRPC server
   - Start HTTP API server
   - Start cron job (daily sync at 3 AM)
   - Sync on startup (optional, via SYNC_ON_STARTUP env var)
   - Start Prometheus metrics endpoint (port 9093)
   - Health check endpoint (GET /health, GET /ready)
   - Graceful shutdown (SIGTERM, SIGINT)

### Phase 3: Testing (Day 2-3)

1. **Create test fixtures**
   - `tests/fixtures/klasus-codes.csv` (100 sample KPD codes)
   - Mock DZS API (nock or similar)
   - Testcontainers for PostgreSQL

2. **Write unit tests** (70% of suite)
   - `sync.test.ts`: Sync logic (add, update, delete codes)
   - `repository.test.ts`: PostgreSQL operations
   - `observability.test.ts`: Metrics, logging
   - Target: 90%+ coverage for critical paths

3. **Write integration tests** (25% of suite)
   - `grpc-api.test.ts`: Both RPC methods (lookup, validate)
   - `sync-flow.test.ts`: End-to-end (fetch → parse → store)

4. **Run tests**
   ```bash
   npm test -- --coverage
   ```
   - **MUST achieve 85%+ coverage** (enforced in jest.config.js)

### Phase 4: Documentation (Day 3)

1. **Create RUNBOOK.md** (operations guide)
   - Copy structure from `/services/schematron-validator/RUNBOOK.md`
   - Sections: Deployment, Monitoring, Common Issues, Troubleshooting, Disaster Recovery
   - Scenarios:
     - DZS API unavailable
     - Invalid KPD codes in DZS response
     - Sync failures (network, parsing)
     - PostgreSQL connection lost
   - Minimum 8 operational scenarios documented

2. **Create proto/kpd-lookup.proto** (gRPC service definition)
   - See Section 3.3 for schema

3. **Create .env.example**
   - All environment variables documented
   - Include: DZS_KLASUS_API_URL, DATABASE_URL, SYNC_CRON, SYNC_ON_STARTUP

4. **Create Dockerfile**
   - Multi-stage build (build → production)
   - Security: Run as non-root user, minimal base image

5. **Create systemd unit file** (`kpd-registry-sync.service`)
   - Security hardening: ProtectSystem=strict, NoNewPrivileges=true
   - Restart policy: always, RestartSec=10
   - Copy from `/services/xsd-validator/*.service`

6. **Create completion report**
   - File: `/docs/reports/{date}-kpd-registry-sync-completion.md`
   - Template: `/docs/reports/2025-11-11-schematron-validator-completion.md`
   - Sections: Executive Summary, Deliverables, Git Status, Traceability, Next Steps

### Phase 5: Commit & Push (Day 3)

1. **Commit all work**
   ```bash
   git add services/kpd-registry-sync/
   git commit -m "feat(kpd-registry-sync): implement KLASUS product code registry sync"
   ```

2. **Push to branch**
   ```bash
   git push -u origin claude/kpd-registry-sync-{your-session-id}
   ```

---

## 5. QUALITY STANDARDS (Non-Negotiable)

### 5.1 Code Quality

- ✅ **TypeScript strict mode** (no `any` types)
- ✅ **ESLint + Prettier** compliant
- ✅ **85%+ test coverage** (enforced in jest.config.js)
- ✅ **All errors explicitly handled** (no swallowed exceptions)

### 5.2 Security

- ✅ **No secrets in code** (use environment variables)
- ✅ **PostgreSQL prepared statements** (prevent SQL injection)
- ✅ **DZS API authentication** (if required)
- ✅ **systemd security hardening** (ProtectSystem=strict, etc.)

### 5.3 Observability (TODO-008 Compliance)

**MANDATORY - Your service MUST include:**

- ✅ **5+ Prometheus metrics**:
  - `kpd_codes_synced_total` (Counter, labels: action) - added, updated, deleted
  - `kpd_sync_duration_seconds` (Histogram)
  - `kpd_total_codes` (Gauge)
  - `kpd_lookup_requests_total` (Counter, labels: status) - found, not_found
  - `kpd_lookup_duration_seconds` (Histogram)

- ✅ **Structured JSON logging** (Pino):
  - Log level: DEBUG (development), INFO (production)
  - Fields: timestamp, service_name, request_id, message
  - No PII (KPD codes are public data)

- ✅ **Distributed tracing** (OpenTelemetry):
  - 100% sampling
  - Spans: sync, postgres.read, postgres.write, grpc.lookup
  - Trace ID for each sync operation

- ✅ **Health endpoints**:
  - GET /health → { status: "healthy", uptime_seconds: 86400 }
  - GET /ready → { status: "ready", dependencies: {...} }
  - GET /metrics → Prometheus text format

### 5.4 Performance

- ✅ **Sync duration:** <60 seconds (50,000 codes)
- ✅ **Lookup latency:** <5ms p95 (local database query)
- ✅ **Throughput:** 1,000 lookups/second

### 5.5 Testing

- ✅ **85%+ coverage** (jest.config.js threshold)
- ✅ **Unit tests:** 70% of suite
- ✅ **Integration tests:** 25% of suite
- ✅ **E2E tests:** 5% of suite (critical paths)
- ✅ **All tests pass** before committing

---

## 6. COMMON PITFALLS (Avoid These)

❌ **DON'T:**
- Use `.clear()` on Prometheus registry (use `.resetMetrics()` in tests)
- Hard-delete KPD codes (use soft delete, set active = false)
- Skip sync on startup (risk of stale data)
- Ignore DZS API failures (retry with backoff)
- Allow incomplete sync (transaction rollback on error)
- Skip pagination on HTTP API (50,000 codes = memory issue)

✅ **DO:**
- Follow patterns from xsd-validator and schematron-validator
- Implement TODO-008 observability compliance
- Test sync logic thoroughly (add, update, delete scenarios)
- Test gRPC API (both lookup and validate methods)
- Document all operational scenarios in RUNBOOK
- Create comprehensive completion report

---

## 7. ACCEPTANCE CRITERIA

**Your service is COMPLETE when:**

### 7.1 Functional Requirements
- [ ] Fetch KPD codes from DZS API (or CSV file)
- [ ] Store in PostgreSQL local cache
- [ ] Daily sync (cron job at 3 AM)
- [ ] gRPC lookup API (2 methods: LookupCode, ValidateCode)
- [ ] HTTP REST API (5 endpoints)
- [ ] Track sync statistics (added/updated/deleted)
- [ ] Sync on startup (optional, configurable)

### 7.2 Non-Functional Requirements
- [ ] Sync duration: <60s for 50,000 codes (benchmarked)
- [ ] Lookup latency: <5ms p95 (verified)
- [ ] Test coverage: 85%+ (jest report confirms)
- [ ] Observability: 5+ Prometheus metrics implemented
- [ ] Security: systemd hardening applied
- [ ] Documentation: README.md + RUNBOOK.md complete

### 7.3 Deliverables
- [ ] All code in `src/` directory
- [ ] All tests in `tests/` directory (passing)
- [ ] Sample KPD codes in `tests/fixtures/klasus-codes.csv`
- [ ] gRPC proto file in `proto/kpd-lookup.proto`
- [ ] `.env.example` (all variables documented)
- [ ] `Dockerfile` (multi-stage, secure)
- [ ] `kpd-registry-sync.service` (systemd unit with hardening)
- [ ] `RUNBOOK.md` (comprehensive operations guide)
- [ ] Completion report in `/docs/reports/`
- [ ] Committed and pushed to `claude/kpd-registry-sync-{session-id}` branch

---

## 8. HELP & REFERENCES

**If you get stuck:**

1. **Reference implementations:**
   - `/services/xsd-validator/` - First service (validation pattern)
   - `/services/schematron-validator/` - Second service (observability pattern)

2. **Specifications:**
   - `README.md` (this directory) - Your primary spec
   - `/CROATIAN_COMPLIANCE.md` - KPD code requirements

3. **Standards:**
   - `/CLAUDE.md` - System architecture
   - `/docs/TODO-008-cross-cutting-concerns.md` - Observability requirements

4. **Dependencies:**
   - This service has ZERO service dependencies (can implement immediately)
   - Only depends on PostgreSQL and DZS API (external)

---

## 9. SUCCESS METRICS

**You've succeeded when:**

✅ All tests pass (`npm test`)
✅ Coverage ≥85% (`npm run test:coverage`)
✅ Service starts without errors (`npm run dev`)
✅ Health endpoints respond correctly
✅ DZS API sync works (fetch → parse → store)
✅ gRPC API works (LookupCode, ValidateCode)
✅ HTTP API works (all 5 endpoints)
✅ Daily cron job executes (sync at 3 AM)
✅ Sync statistics tracked (added/updated/deleted metrics)
✅ RUNBOOK.md covers all operational scenarios
✅ Completion report written
✅ Code pushed to branch

---

## 10. TIMELINE CHECKPOINT

**Day 1 End:** Core implementation complete (sync, repository, observability)
**Day 2 End:** gRPC API + HTTP API complete
**Day 3 End:** All tests written and passing (85%+ coverage), documentation complete, code committed & pushed

**If you're behind schedule:**
- Prioritize gRPC API (most critical for kpd-validator)
- HTTP API can be simplified (fewer endpoints)
- Ensure observability compliance (non-negotiable)
- Ask for help if blocked >2 hours

---

**Status:** 🔴 Ready for Implementation
**Last Updated:** 2025-11-11
**Assigned To:** [Your AI Instance]
**Session ID:** [Your Session ID]

---

## FINAL REMINDER

**Read the specification (`README.md`) thoroughly before writing code.**

This CLAUDE.md provides workflow and context. The README.md provides technical details. Together, they contain everything you need to implement this service to production standards.

**Good luck!**
