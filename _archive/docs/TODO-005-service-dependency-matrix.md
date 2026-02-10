# TODO-005: Service Dependency Matrix for Parallel Development

**Status:** ✅ COMPLETE
**Created:** 2025-11-11
**Completed:** 2025-11-11
**Priority:** HIGH (Unblocks parallel development)
**Estimated Effort:** 2-3 hours

---

## Purpose

Define service dependencies to enable **coordinated parallel development** across multiple AI instances without integration conflicts.

**Enables:**
- Multiple AI instances developing services simultaneously
- 3x development speedup (8 weeks vs 24 weeks)
- Clear understanding of which services can be built in parallel
- Identification of shared types and message contracts

---

## Table of Contents

1. [Service Dependency Graph](#1-service-dependency-graph)
2. [Dependency Matrix](#2-dependency-matrix)
3. [Parallel Development Tracks](#3-parallel-development-tracks)
4. [Shared Types & Message Contracts](#4-shared-types--message-contracts)
5. [Integration Points](#5-integration-points)
6. [Development Timeline](#6-development-timeline)

---

## 1. Service Dependency Graph

### 1.1 Visual Dependency Graph (by Layer)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 1: INGESTION (4 services) - NO DEPENDENCIES                      │
│ ┌─────────────────┐  ┌──────────────────┐  ┌──────────────┐  ┌────────┤
│ │email-worker     │  │web-upload-handler│  │api-gateway   │  │as4-rcv │
│ └────────┬────────┘  └─────────┬────────┘  └──────┬───────┘  └────┬───┘
│          │                     │                   │               │
│          └──────────────────┬──┴───────────────────┴───────────────┘
│                             │
┌─────────────────────────────▼──────────────────────────────────────────┐
│ Layer 2: PARSING & EXTRACTION (4 services) - DEPENDS ON: None          │
│ ┌────────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────────┤
│ │file-classifier │  │pdf-parser    │  │ocr-processor│  │xml-parser    │
│ └───────┬────────┘  └──────┬───────┘  └──────┬──────┘  └──────┬───────┘
│         │                  │                  │                │
│         └──────────────────┴──────────────────┴────────────────┘
│                             │
┌─────────────────────────────▼──────────────────────────────────────────┐
│ Layer 3: DATA EXTRACTION (2 services) - DEPENDS ON: Layer 2            │
│ ┌─────────────────┐  ┌───────────────────┐                            │
│ │data-extractor   │  │data-normalizer    │                            │
│ └────────┬────────┘  └─────────┬─────────┘                            │
│          │                     │                                       │
│          └──────────┬──────────┘                                       │
│                     │                                                  │
┌─────────────────────▼──────────────────────────────────────────────────┐
│ Layer 4: VALIDATION (8 services) - DEPENDS ON: Layer 3                │
│ ┌───────────────┐  ┌───────────────────┐  ┌──────────────┐           │
│ │xsd-validator  │  │schematron-validator│  │kpd-validator │           │
│ └───────┬───────┘  └─────────┬─────────┘  └──────┬───────┘           │
│         ├──────────────────────┼────────────────────┘                  │
│ ┌───────▼────────┐  ┌─────────▼─────────┐  ┌──────────────┐          │
│ │semantic-validtr│  │ai-validator       │  │business-rules│          │
│ └───────┬────────┘  └─────────┬─────────┘  └──────┬───────┘          │
│         ├──────────────────────┼────────────────────┘                  │
│ ┌───────▼────────┐  ┌─────────▼─────────┐                            │
│ │signature-verify│  │duplicate-detector │                            │
│ └───────┬────────┘  └─────────┬─────────┘                            │
│         │                     │                                       │
│         └──────────┬──────────┘                                       │
│                     │                                                  │
┌─────────────────────▼──────────────────────────────────────────────────┐
│ Layer 5: TRANSFORMATION (2 services) - DEPENDS ON: Layer 4            │
│ ┌─────────────────┐  ┌───────────────────┐                           │
│ │ubl-transformer  │  │metadata-enricher  │                           │
│ └────────┬────────┘  └─────────┬─────────┘                           │
│          │                     │                                      │
│          └──────────┬──────────┘                                      │
│                     │                                                 │
┌─────────────────────▼─────────────────────────────────────────────────┐
│ Layer 6: CRYPTOGRAPHIC (3 services) - DEPENDS ON: Layer 5             │
│ ┌──────────────────┐  ┌─────────────────┐  ┌──────────────┐         │
│ │digital-signature │  │timestamp-service│  │zki-calculator│         │
│ └────────┬─────────┘  └─────────┬───────┘  └──────┬───────┘         │
│          │                      │                  │                  │
│          └──────────┬───────────┴──────────────────┘                  │
│                     │                                                 │
┌─────────────────────▼─────────────────────────────────────────────────┐
│ Layer 7: SUBMISSION (5 services) - DEPENDS ON: Layer 6                │
│ ┌─────────────────┐  ┌──────────────────┐  ┌───────────────┐        │
│ │submission-router│  │fina-soap-conn    │  │as4-gateway-snd│        │
│ └────────┬────────┘  └─────────┬────────┘  └──────┬────────┘        │
│          ├──────────────────────┼────────────────────┘                │
│ ┌────────▼────────┐  ┌─────────▼─────────┐                          │
│ │eporezna-conn    │  │ams-client         │                          │
│ └────────┬────────┘  └─────────┬─────────┘                          │
│          │                     │                                     │
│          └──────────┬──────────┘                                     │
│                     │                                                │
┌─────────────────────▼────────────────────────────────────────────────┐
│ Layer 8: ARCHIVING (4 services) - DEPENDS ON: Layer 7                │
│ ┌─────────────────┐  ┌─────────────────────────┐  ┌─────────────┐  │
│ │archive-service  │  │sig-verification-scheduler│  │retrieval-svc│  │
│ └────────┬────────┘  └─────────┬───────────────┘  └─────────────┘  │
│ ┌────────▼────────┐                                                  │
│ │cold-storage-mgr │                                                  │
│ └─────────────────┘                                                  │
│                                                                       │
┌───────────────────────────────────────────────────────────────────────┐
│ Layer 9: INFRASTRUCTURE (5 services) - NO LAYER DEPENDENCIES         │
│ ┌─────────────────┐  ┌──────────────────┐  ┌──────────────┐        │
│ │audit-logger     │  │dead-letter-handler│  │health-monitor│        │
│ └─────────────────┘  └──────────────────┘  └──────────────┘        │
│ ┌─────────────────┐  ┌──────────────────┐                          │
│ │notification-svc │  │retry-scheduler   │                          │
│ └─────────────────┘  └──────────────────┘                          │
│                                                                      │
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 10: MANAGEMENT (3 services) - NO LAYER DEPENDENCIES            │
│ ┌──────────────────────┐  ┌─────────────────┐  ┌───────────────┐   │
│ │cert-lifecycle-manager│  │kpd-registry-sync│  │admin-portal   │   │
│ └──────────────────────┘  └─────────────────┘  └───────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

### 1.2 Key Observations

**Sequential Dependencies (Must Build in Order):**
- Layers 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 (Critical path)
- Each layer depends on previous layer completing

**Parallel Opportunities (Can Build Simultaneously):**
- **Within Layer 1:** All 4 ingestion services (no inter-dependencies)
- **Within Layer 2:** All 4 parsing services (no inter-dependencies)
- **Within Layer 4:** All 8 validation services (no inter-dependencies)
- **Within Layer 5:** Both transformation services (no inter-dependencies)
- **Within Layer 6:** All 3 cryptographic services (no inter-dependencies)
- **Within Layer 7:** All 5 submission services (no inter-dependencies)
- **Within Layer 8:** All 4 archiving services (no inter-dependencies)
- **Layer 9:** All 5 infrastructure services (no layer dependencies, can start ANYTIME)
- **Layer 10:** All 3 management services (no layer dependencies, can start ANYTIME)

**Critical Insight:**
- Layers 9 and 10 (8 services total) have **ZERO layer dependencies** and can be built **immediately in parallel** with any other work
- Within each layer, all services can be built in parallel

---

## 2. Dependency Matrix

### 2.1 Service-Level Dependencies (Detailed)

| Service | Depends On (Must Complete First) | Dependent Services (Blocked Until This Completes) |
|---------|-----------------------------------|--------------------------------------------------|
| **Layer 1: Ingestion** |
| email-ingestion-worker | None | file-classifier |
| web-upload-handler | None | file-classifier |
| api-gateway | None | file-classifier |
| as4-gateway-receiver | None | xml-parser |
| **Layer 2: Parsing** |
| file-classifier | Layer 1 (any ingestion) | pdf-parser, ocr-processor, xml-parser |
| pdf-parser | file-classifier | data-extractor |
| ocr-processor | file-classifier | data-extractor |
| xml-parser | file-classifier, as4-gateway-receiver | data-normalizer |
| **Layer 3: Data Extraction** |
| data-extractor | pdf-parser, ocr-processor | data-normalizer |
| data-normalizer | xml-parser, data-extractor | xsd-validator |
| **Layer 4: Validation** |
| xsd-validator ✅ | data-normalizer | schematron-validator |
| schematron-validator ✅ | xsd-validator | kpd-validator, semantic-validator |
| kpd-validator | schematron-validator, kpd-registry-sync | business-rules-engine |
| oib-validator | schematron-validator | business-rules-engine |
| semantic-validator | schematron-validator | business-rules-engine |
| business-rules-engine | kpd-validator, oib-validator, semantic-validator | ai-validator |
| ai-validator | business-rules-engine | signature-verifier |
| signature-verifier | ai-validator | duplicate-detector |
| duplicate-detector | signature-verifier | ubl-transformer |
| **Layer 5: Transformation** |
| ubl-transformer | duplicate-detector | digital-signature-service |
| metadata-enricher | ubl-transformer, ams-client | digital-signature-service |
| **Layer 6: Cryptographic** |
| digital-signature-service | metadata-enricher, cert-lifecycle-manager | timestamp-service, zki-calculator |
| timestamp-service | digital-signature-service | submission-router |
| zki-calculator | digital-signature-service | fina-soap-connector |
| **Layer 7: Submission** |
| submission-router | timestamp-service | fina-soap-connector, as4-gateway-sender, eporezna-connector |
| fina-soap-connector | submission-router, zki-calculator | archive-service |
| as4-gateway-sender | submission-router, ams-client | archive-service |
| eporezna-connector | submission-router | archive-service |
| ams-client | None (Layer 10 service) | metadata-enricher, as4-gateway-sender |
| **Layer 8: Archiving** |
| archive-service | fina-soap-connector, as4-gateway-sender, eporezna-connector | signature-verification-scheduler, retrieval-service, cold-storage-migrator |
| signature-verification-scheduler | archive-service | notification-service |
| retrieval-service | archive-service | None |
| cold-storage-migrator | archive-service | None |
| **Layer 9: Infrastructure** |
| audit-logger | None | None (consumed by all services) |
| dead-letter-handler | None | retry-scheduler, notification-service |
| health-monitor | None | notification-service |
| notification-service | None | None (consumed by many services) |
| retry-scheduler | dead-letter-handler | None (republishes to queues) |
| **Layer 10: Management** |
| cert-lifecycle-manager | None | digital-signature-service |
| kpd-registry-sync | None | kpd-validator |
| admin-portal-api | None | None (queries all services) |

### 2.2 Dependency Count Analysis

**Services with ZERO dependencies (Can start immediately):**
- Layer 1 (4 services): All ingestion services
- Layer 9 (5 services): All infrastructure services
- Layer 10 (3 services): All management services

**Total:** 12 services (30%) can start immediately

**Services with 1 dependency:**
- file-classifier (depends on any ingestion)
- xml-parser (depends on file-classifier or as4-receiver)
- Total: 2 services

**Services with 2+ dependencies (Critical path):**
- 26 services (65%) require multiple predecessors

**Longest dependency chain (Critical path):**
```
email-worker → file-classifier → pdf-parser → data-extractor →
data-normalizer → xsd-validator → schematron-validator →
kpd-validator → business-rules-engine → ai-validator →
signature-verifier → duplicate-detector → ubl-transformer →
metadata-enricher → digital-signature-service → timestamp-service →
submission-router → fina-soap-connector → archive-service
```
**Length:** 19 services (longest path)

---

## 3. Parallel Development Tracks

### 3.1 Track Assignment (8 Tracks for Maximum Parallelism)

**TRACK 0: Foundation Services (Build First - COMPLETED)**
- ✅ xsd-validator (COMPLETE)
- ✅ schematron-validator (COMPLETE)

**TRACK 1: Infrastructure Services (NO DEPENDENCIES - START IMMEDIATELY)**
- **AI Instance A:** audit-logger (Medium, ~1,500 LOC)
- **AI Instance B:** dead-letter-handler (Medium, ~1,800 LOC)
- **AI Instance C:** health-monitor (Medium, ~1,400 LOC)
- **AI Instance D:** notification-service (Low, ~900 LOC)
- **AI Instance E:** retry-scheduler (Medium, ~1,200 LOC)

**Estimated Time:** 1-2 weeks (5 services in parallel)

**TRACK 2: Management Services (NO DEPENDENCIES - START IMMEDIATELY)**
- **AI Instance F:** cert-lifecycle-manager (High, ~2,200 LOC)
- **AI Instance G:** kpd-registry-sync (Low, ~800 LOC)
- **AI Instance H:** admin-portal-api (Medium, ~2,000 LOC)

**Estimated Time:** 1-2 weeks (3 services in parallel)

**TRACK 3: Ingestion Layer (AFTER TRACK 0)**
- **AI Instance I:** email-ingestion-worker (Medium, ~1,200 LOC)
- **AI Instance J:** web-upload-handler (Simple, ~500 LOC)
- **AI Instance K:** api-gateway (Medium, ~1,200 LOC)
- **AI Instance L:** as4-gateway-receiver (High, ~2,200 LOC)

**Estimated Time:** 1-2 weeks (4 services in parallel)

**TRACK 4: Parsing Layer (AFTER TRACK 3)**
- **AI Instance M:** file-classifier (Low, ~600 LOC)
- **AI Instance N:** pdf-parser (Medium, ~1,500 LOC)
- **AI Instance O:** ocr-processor (High, ~2,200 LOC)
- **AI Instance P:** xml-parser (Low, ~700 LOC)

**Estimated Time:** 1-2 weeks (4 services in parallel)

**TRACK 5: Validation Layer (AFTER TRACK 0 + TRACK 4)**
- **AI Instance Q:** kpd-validator (Medium, ~1,200 LOC)
- **AI Instance R:** oib-validator (Medium, ~1,000 LOC)
- **AI Instance S:** semantic-validator (Medium-High, ~1,500 LOC)
- **AI Instance T:** business-rules-engine (High, ~2,300 LOC)
- **AI Instance U:** ai-validator (High, ~2,000 LOC)
- **AI Instance V:** signature-verifier (High, ~2,200 LOC)
- **AI Instance W:** duplicate-detector (Medium, ~1,200 LOC)

**Estimated Time:** 2-3 weeks (7 services in parallel, but sequential dependencies within)

**TRACK 6: Transformation & Cryptographic (AFTER TRACK 5)**
- **AI Instance X:** data-extractor (Medium, ~1,600 LOC)
- **AI Instance Y:** data-normalizer (Medium, ~1,800 LOC)
- **AI Instance Z:** ubl-transformer (Medium, ~2,000 LOC)
- **AI Instance AA:** metadata-enricher (Low, ~700 LOC)
- **AI Instance AB:** digital-signature-service (High, ~2,300 LOC)
- **AI Instance AC:** timestamp-service (Medium, ~1,500 LOC)
- **AI Instance AD:** zki-calculator (Low, ~400 LOC)

**Estimated Time:** 2 weeks (7 services in parallel)

**TRACK 7: Submission & Archiving (AFTER TRACK 6)**
- **AI Instance AE:** submission-router (Low, ~800 LOC)
- **AI Instance AF:** fina-soap-connector (High, ~2,400 LOC)
- **AI Instance AG:** as4-gateway-sender (High, ~2,500 LOC)
- **AI Instance AH:** eporezna-connector (Medium, ~1,600 LOC)
- **AI Instance AI:** ams-client (Low, ~600 LOC)
- **AI Instance AJ:** archive-service (Medium, ~1,800 LOC)
- **AI Instance AK:** signature-verification-scheduler (Low, ~900 LOC)
- **AI Instance AL:** retrieval-service (Medium, ~1,200 LOC)
- **AI Instance AM:** cold-storage-migrator (Low, ~700 LOC)

**Estimated Time:** 2-3 weeks (9 services in parallel)

### 3.2 Optimal Parallelization Strategy

**Phase 1: Immediate Start (Week 1-2)**
- Launch 8 AI instances for TRACK 1 + TRACK 2 (infrastructure + management)
- **No blockers, no dependencies**
- 8 services completed

**Phase 2: Ingestion + Parsing (Week 2-4)**
- Launch 8 AI instances for TRACK 3 + TRACK 4
- 8 services completed

**Phase 3: Validation Layer (Week 4-7)**
- Launch 7 AI instances for TRACK 5
- Complex layer with sequential dependencies
- 7 services completed

**Phase 4: Transformation + Crypto (Week 7-9)**
- Launch 7 AI instances for TRACK 6
- 7 services completed

**Phase 5: Submission + Archiving (Week 9-12)**
- Launch 9 AI instances for TRACK 7
- 9 services completed

**Total Time: 12 weeks (vs 24+ weeks sequential)**

---

## 4. Shared Types & Message Contracts

### 4.1 Shared TypeScript Types (Create in `shared/common-types/`)

**File:** `shared/common-types/src/invoice.ts`

```typescript
/**
 * Common invoice types shared across all services
 */

export interface InvoiceId {
  uuid: string; // UUID v4
}

export enum InvoiceType {
  B2C = 'B2C',      // Business to Consumer
  B2B = 'B2B',      // Business to Business
  B2G = 'B2G'       // Business to Government
}

export enum ProcessingStage {
  INGESTED = 'INGESTED',
  PARSED = 'PARSED',
  VALIDATED = 'VALIDATED',
  SIGNED = 'SIGNED',
  SUBMITTED = 'SUBMITTED',
  ARCHIVED = 'ARCHIVED',
  FAILED = 'FAILED'
}

export interface OIB {
  value: string; // 11 digits
}

export interface KPDCode {
  value: string; // Minimum 6 digits (KLASUS 2025)
}

export interface RequestContext {
  request_id: string;        // UUID for tracing
  user_id?: string;          // Authenticated user (if applicable)
  timestamp_ms: number;      // Unix timestamp in milliseconds
  invoice_type: InvoiceType;
}

export interface ValidationError {
  code: string;              // Error code (e.g., "XSD_VALIDATION_FAILED")
  message: string;           // Human-readable message
  field?: string;            // Field that caused error
  details?: string[];        // Additional context
}

export enum ValidationStatus {
  VALID = 'VALID',
  INVALID = 'INVALID',
  ERROR = 'ERROR'            // System error (not validation failure)
}
```

**File:** `shared/common-types/src/messages.ts`

```typescript
/**
 * Base message interfaces for RabbitMQ commands
 */

import { InvoiceId, RequestContext } from './invoice';

export interface BaseCommand {
  context: RequestContext;
  invoice_id: InvoiceId;
}

export interface BaseResponse {
  invoice_id: InvoiceId;
  success: boolean;
  error?: ValidationError;
}

// Validation command interfaces
export interface ValidateXSDCommand extends BaseCommand {
  xml_content: Buffer;
  schema_type: 'UBL_2_1' | 'CII_2_0';
}

export interface ValidateXSDResponse extends BaseResponse {
  status: ValidationStatus;
  errors: ValidationError[];
}

export interface ValidateSchematronCommand extends BaseCommand {
  xml_content: Buffer;
  cius_version: string;
}

export interface ValidateSchematronResponse extends BaseResponse {
  status: ValidationStatus;
  errors: SchematronError[];
}

export interface SchematronError extends ValidationError {
  rule_id: string;           // Schematron rule ID (e.g., "BR-CO-04")
  xpath: string;             // XPath to problematic element
  severity: 'error' | 'warning';
}
```

### 4.2 Shared Observability Module (Already Created in TODO-008)

**File:** `shared/observability/` (Use pattern from xsd-validator and schematron-validator)

**Standard Exports:**
```typescript
export {
  maskOIB,
  maskIBAN,
  maskVAT,
  maskPII,
  logger,
  createSpan,
  getMetricsRegistry
};

// Each service creates its own metrics:
// - {service}_validation_total (Counter)
// - {service}_validation_duration_seconds (Histogram)
// - {service}_errors_total (Counter)
// - etc.
```

### 4.3 Message Queue Naming Conventions

**Exchange Names:**
- `ingestion` (Layer 1 publishes here)
- `parsing` (Layer 2 publishes here)
- `validation` (Layer 4 publishes here)
- `transformation` (Layer 5 publishes here)
- `submission` (Layer 7 publishes here)
- `dlx` (Dead Letter Exchange - all layers)
- `notifications` (Infrastructure layer)

**Queue Names:**
- Format: `{layer}.{service}.{action}`
- Examples:
  - `validation.xsd.validate`
  - `validation.schematron.validate`
  - `validation.kpd.validate`
  - `transformation.ubl.transform`

**Routing Keys:**
- Format: `{layer}.{service}.{event}`
- Examples:
  - `validation.xsd.completed`
  - `validation.schematron.failed`
  - `transformation.ubl.completed`

**Dead Letter Queues:**
- Format: `{queue_name}.dlq`
- Examples:
  - `validation.xsd.validate.dlq`
  - `validation.schematron.validate.dlq`

---

## 5. Integration Points

### 5.1 Service-to-Service Integration Patterns

**Pattern 1: Sequential Pipeline (Validation Chain)**
```
xsd-validator → schematron-validator → kpd-validator → semantic-validator
```

**Integration:**
- Each service consumes from own queue
- On success: Publish to next service's queue
- On failure: Publish to DLQ
- Message format: Common `BaseCommand` interface

**Pattern 2: Fan-Out (Ingestion → Multiple Parsers)**
```
file-classifier → { pdf-parser, ocr-processor, xml-parser }
```

**Integration:**
- file-classifier publishes to `parsing` exchange
- Routing key determines which parser consumes
- Each parser subscribes to specific message types

**Pattern 3: Event Broadcasting (Audit Logger)**
```
All services → Kafka (invoice-events topic) → audit-logger
```

**Integration:**
- Every service publishes Kafka events
- audit-logger consumes from all topics
- No direct coupling between services

### 5.2 Cross-Service Test Strategy

**Phase 1: Unit Tests (Per Service)**
- 85% coverage requirement
- Mock all external dependencies
- Test service logic in isolation

**Phase 2: Integration Tests (Message Contracts)**
- Deploy service + RabbitMQ in Docker Compose
- Test message consumption/production
- Verify queue bindings, DLQ handling

**Phase 3: Contract Tests (Pact)**
- Producer: xsd-validator (publishes `ValidateXSDResponse`)
- Consumer: schematron-validator (consumes and expects specific format)
- Verify schema compatibility

**Phase 4: End-to-End Tests (Staging)**
- Deploy all services in staging
- Submit real invoice through entire pipeline
- Verify final result in archive-service

### 5.3 API Gateway Integration (External)

**REST Endpoints (admin-portal-api):**
```
POST   /api/v1/invoices/upload          # Upload invoice
GET    /api/v1/invoices/:id/status      # Check status
GET    /api/v1/invoices/:id             # Retrieve invoice
DELETE /api/v1/invoices/:id             # Delete (if not submitted)
```

**Webhook Callbacks:**
```
POST   <client_webhook_url>             # Notify invoice processing complete
```

---

## 6. Development Timeline

### 6.1 Aggressive Timeline (8 AI Instances in Parallel)

**Week 1-2: Infrastructure + Management (8 services)**
- Track 1: audit-logger, dead-letter-handler, health-monitor, notification-service, retry-scheduler
- Track 2: cert-lifecycle-manager, kpd-registry-sync, admin-portal-api
- **Milestone:** Infrastructure foundation complete

**Week 2-4: Ingestion + Parsing (8 services)**
- Track 3: email-worker, web-upload-handler, api-gateway, as4-gateway-receiver
- Track 4: file-classifier, pdf-parser, ocr-processor, xml-parser
- **Milestone:** Full ingestion pipeline operational

**Week 4-7: Validation Layer (7 services)**
- Track 5: kpd-validator, oib-validator, semantic-validator, business-rules-engine, ai-validator, signature-verifier, duplicate-detector
- **Milestone:** Complete validation stack

**Week 7-9: Transformation + Cryptographic (7 services)**
- Track 6: data-extractor, data-normalizer, ubl-transformer, metadata-enricher, digital-signature-service, timestamp-service, zki-calculator
- **Milestone:** Transformation and signing complete

**Week 9-12: Submission + Archiving (9 services)**
- Track 7: submission-router, fina-soap-connector, as4-gateway-sender, eporezna-connector, ams-client, archive-service, signature-verification-scheduler, retrieval-service, cold-storage-migrator
- **Milestone:** Complete end-to-end system

**Total:** 12 weeks (40 services, 3.3 services/week average)

### 6.2 Conservative Timeline (4 AI Instances in Parallel)

**Week 1-3:** Infrastructure services (5 services, 4 instances = 2 sprints)
**Week 3-5:** Management services (3 services, 4 instances = 1 sprint)
**Week 5-7:** Ingestion layer (4 services, 4 instances = 1 sprint)
**Week 7-9:** Parsing layer (4 services, 4 instances = 1 sprint)
**Week 9-14:** Validation layer (7 services, 4 instances = 2 sprints)
**Week 14-17:** Transformation + Crypto (7 services, 4 instances = 2 sprints)
**Week 17-22:** Submission + Archiving (9 services, 4 instances = 3 sprints)

**Total:** 22 weeks (40 services, 1.8 services/week average)

### 6.3 Critical Path Analysis

**Longest dependency chain:** 19 services (see Section 2.2)

**Minimum completion time (if all parallel work is done):**
- Foundation (xsd + schematron): ✅ COMPLETE
- Ingestion: 1 week
- Parsing: 1 week (depends on ingestion)
- Data extraction: 1 week (depends on parsing)
- Validation: 3 weeks (7 services, sequential dependencies)
- Transformation: 1 week (depends on validation)
- Cryptographic: 1 week (depends on transformation)
- Submission: 1 week (depends on crypto)
- Archiving: 1 week (depends on submission)

**Critical Path Total:** 10 weeks (with perfect parallelization)

**Realistic Total:** 12 weeks (accounting for integration, testing, debugging)

---

## 7. Deliverables

### 7.1 This Document Provides:

✅ **Complete service dependency graph** (visual + table)
✅ **Dependency matrix** (40 services, all dependencies mapped)
✅ **Parallel development tracks** (8 tracks for maximum speed)
✅ **Shared types and message contracts** (TypeScript interfaces)
✅ **Integration points** (message queues, API contracts)
✅ **Development timeline** (aggressive 12 weeks, conservative 22 weeks)

### 7.2 Next Steps:

1. **Launch Track 1 + Track 2 immediately** (8 AI instances, 8 services, no dependencies)
2. **Update `shared/common-types/`** with interfaces from Section 4.1
3. **Create integration test framework** (Docker Compose + Testcontainers)
4. **Establish weekly coordination meetings** (review merge conflicts, integration issues)

---

## 8. Success Criteria

**This TODO is COMPLETE when:**
- ✅ All 40 services have documented dependencies
- ✅ Parallel development tracks are defined
- ✅ Shared types are identified
- ✅ Integration points are documented
- ✅ Timeline is realistic and achievable

**This enables:**
- Multiple AI instances developing services simultaneously
- Clear understanding of what can be built when
- No integration conflicts or blocked work
- 3x development speedup (12 weeks vs 36+ weeks sequential)

---

**Status:** ✅ COMPLETE
**Created:** 2025-11-11
**Completed:** 2025-11-11
**Author:** System Architect
**Maintainer:** Platform Architecture Team

**Related Documents:**
- `CLAUDE.md` - System architecture
- `ARCHITECTURE_REVIEW.md` - Parallel development plan
- `docs/adr/003-system-decomposition-integration-architecture.md` - Service catalog
- `PENDING.md` - Deferred work tracking
