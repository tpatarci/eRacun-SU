# KPD Registry Sync Service - Specification

**Service Name:** `kpd-registry-sync`
**Layer:** Management (Layer 10)
**Complexity:** Low (~800 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Single Responsibility

**Sync KLASUS product classification codes from DZS (Croatian Bureau of Statistics), update local cache, and provide lookup API for validation services.**

This service maintains a **local copy of the official KPD product code registry** (KLASUS 2025 standard). Since KPD codes are mandatory for every invoice line item (Croatian fiscalization law), this service ensures:
- Always up-to-date KPD code list
- Fast local lookups (no external API dependency during validation)
- Version tracking (KLASUS registry updates periodically)

---

## 2. Integration Architecture

### 2.1 Dependencies

**Consumes:**
- DZS KLASUS registry API: https://api.dzs.hr/klasus/v1/codes (hypothetical - check actual DZS endpoint)
- OR CSV/XML file download from official DZS portal

**Produces:**
- PostgreSQL table: `kpd_codes` (local cache)
- gRPC API: `LookupKPDCode(code)` → `KPDCodeInfo`

**Consumed By:**
- `kpd-validator` service (validates invoice line item KPD codes)

### 2.2 KPD Code Schema

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

**Example KPD Codes (KLASUS 2025):**
- `01` - Agricultural products
- `0101` - Live animals
- `010101` - Cattle
- `010102` - Pigs
- `01010201` - Piglets

---

## 3. Sync Strategy

### 3.1 Scheduled Sync (Cron)

**Frequency:**
- Daily at 3 AM (DZS updates registry monthly, but check daily for safety)
- Manual trigger via HTTP POST `/sync/trigger`

**Sync Process:**
1. Fetch latest KPD codes from DZS API/file
2. Parse CSV/JSON response
3. Compare with local database (identify new/updated/deleted codes)
4. Update local cache (INSERT new, UPDATE changed, soft-delete removed)
5. Log sync statistics (added: 5, updated: 2, deleted: 0)
6. Publish sync event to Kafka (for audit trail)

### 3.2 Data Source

**Option A: DZS API** (preferred if available):
```bash
curl -X GET "https://api.dzs.hr/klasus/v1/codes?version=2025"
```

**Option B: CSV File Download** (if no API):
- Download from official DZS portal
- Parse CSV (columns: code, description, level, parent, effective_from, effective_to)
- Import into PostgreSQL

---

## 4. Technology Stack

**Core:**
- Node.js 20+ / TypeScript 5.3+
- `axios` - HTTP client (DZS API)
- `csv-parser` - CSV parsing (if file-based)
- `pg` - PostgreSQL client
- `@grpc/grpc-js` - gRPC server (lookup API)
- `node-cron` - Scheduled sync

**Observability:**
- `prom-client`, `pino`, `opentelemetry`

---

## 5. Performance Requirements

**Sync:**
- Complete sync in <60 seconds (est. 50,000 KPD codes)
- No impact on validation services during sync

**Lookup API:**
- Latency: <5ms p95 (local database query)
- Throughput: 1,000 lookups/second

---

## 6. Implementation Guidance

### 6.1 Core Logic

```typescript
async function syncKPDCodes() {
  logger.info('Starting KPD registry sync');

  // Fetch from DZS
  const response = await axios.get('https://api.dzs.hr/klasus/v1/codes?version=2025');
  const remoteCodes = response.data.codes;

  // Compare with local database
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
    await softDeleteKPDCode(code); // Set active = false
  }

  // Metrics
  kpdCodesSynced.inc({ action: 'added' }, toAdd.length);
  kpdCodesSynced.inc({ action: 'updated' }, toUpdate.length);
  kpdCodesSynced.inc({ action: 'deleted' }, toDelete.length);

  logger.info(`KPD sync complete: +${toAdd.length}, ~${toUpdate.length}, -${toDelete.length}`);
}
```

### 6.2 gRPC Lookup API

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

## 7. Observability (TODO-008)

**Metrics:**
```typescript
const kpdCodesSynced = new Counter({
  name: 'kpd_codes_synced_total',
  labelNames: ['action']  // added, updated, deleted
});

const kpdSyncDuration = new Histogram({
  name: 'kpd_sync_duration_seconds',
  buckets: [1, 5, 10, 30, 60]
});

const kpdTotalCodes = new Gauge({
  name: 'kpd_total_codes',
  help: 'Total KPD codes in local cache'
});

const kpdLookupRequests = new Counter({
  name: 'kpd_lookup_requests_total',
  labelNames: ['status']  // found, not_found
});

const kpdLookupDuration = new Histogram({
  name: 'kpd_lookup_duration_seconds',
  buckets: [0.001, 0.005, 0.01, 0.05]
});
```

---

## 8. Configuration

```bash
# .env.example
SERVICE_NAME=kpd-registry-sync
HTTP_PORT=8088
GRPC_PORT=50052

# DZS KLASUS API
DZS_KLASUS_API_URL=https://api.dzs.hr/klasus/v1/codes
DZS_KLASUS_VERSION=2025
DZS_API_KEY=<if required>

# PostgreSQL
DATABASE_URL=postgresql://kpd_user:password@localhost:5432/eracun

# Sync Schedule
SYNC_CRON=0 3 * * *  # Daily at 3 AM
SYNC_ON_STARTUP=true  # Sync immediately on service start

# Observability
LOG_LEVEL=info
PROMETHEUS_PORT=9093
```

---

## 9. HTTP API (Admin Portal Integration)

```
GET    /api/v1/kpd/codes              # List all KPD codes (paginated)
GET    /api/v1/kpd/codes/:code        # Get specific KPD code details
GET    /api/v1/kpd/search?q=cattle    # Search KPD codes by description
POST   /api/v1/kpd/sync/trigger       # Manually trigger sync
GET    /api/v1/kpd/sync/status        # Last sync status
```

---

## 10. Failure Modes

**Scenario 1: DZS API Unavailable**
- **Impact:** Cannot sync new codes, validation uses stale data
- **Detection:** HTTP request timeout/error
- **Recovery:**
  1. Retry sync after 1 hour
  2. Alert if unavailable for >24 hours
  3. Use last known good data (acceptable for short outages)

**Scenario 2: Invalid KPD Codes in DZS Response**
- **Impact:** Corrupted local cache
- **Detection:** Validation error during parsing
- **Recovery:**
  1. Skip invalid codes (log error)
  2. Continue with valid codes
  3. Alert DZS about data quality issue

---

## 11. Acceptance Criteria

- [ ] Fetch KPD codes from DZS API (or CSV file)
- [ ] Store in PostgreSQL local cache
- [ ] Daily sync (cron job)
- [ ] gRPC lookup API (2 methods)
- [ ] HTTP REST API (5 endpoints)
- [ ] Track sync statistics (added/updated/deleted)
- [ ] Test coverage 85%+
- [ ] 5+ Prometheus metrics

---

**Status:** 🔴 Ready for Implementation
**Estimate:** 2-3 days | **Complexity:** Low (~800 LOC)
**Dependencies:** None

---

**Last Updated:** 2025-11-11
