# eRacun Platform - Monorepo Folder Structure Proposal

## Structure Overview

```
eRacun-development/
├── services/
│   ├── ingestion/
│   │   ├── email-worker/
│   │   ├── web-gateway/
│   │   └── file-parser/
│   ├── validation/
│   │   ├── xsd-validator/
│   │   ├── schematron-validator/
│   │   ├── kpd-validator/
│   │   ├── business-rules-engine/
│   │   ├── ai-validator/
│   │   └── consensus-orchestrator/
│   ├── transformation/
│   │   ├── ubl-generator/
│   │   ├── signature-service/
│   │   └── ocr-processor/
│   ├── integration/
│   │   ├── fina-soap-connector/
│   │   ├── as4-gateway/
│   │   ├── ams-client/
│   │   └── ereporting-service/
│   ├── storage/
│   │   ├── document-store/
│   │   ├── archive-manager/
│   │   └── retrieval-api/
│   └── orchestration/
│       ├── invoice-workflow/
│       └── event-router/
├── shared/
│   ├── types/
│   ├── messaging/
│   ├── validation-primitives/
│   ├── crypto/
│   └── observability/
├── infrastructure/
│   ├── terraform/
│   ├── kubernetes/
│   └── systemd/
├── docs/
│   ├── adr/
│   ├── api-contracts/
│   └── diagrams/
└── scripts/
```

---

## DETAILED SERVICE BREAKDOWN

---

## 1. INGESTION LAYER (`services/ingestion/`)

### 1.1 `email-worker/` (Target: 800 LOC)

**Role:**
- Poll IMAP/POP3 mailboxes for incoming invoices
- Extract attachments (PDF, images, XML)
- Validate email authenticity (SPF, DKIM)
- Publish `InvoiceReceived` events to message bus

**Rationale for Isolation:**
- Email protocols are complex and stateful
- Independent scaling (high email volume periods)
- Failure isolation (email server downtime doesn't affect other ingestion)
- Can be developed/tested with mock IMAP servers

**External Dependencies:**
- Customer email servers (IMAP/POP3)
- Message bus (RabbitMQ/Kafka)

**Integration Contract:**
```protobuf
message InvoiceReceivedEvent {
  string request_id = 1;
  string customer_oib = 2;
  bytes raw_document = 3;
  string mime_type = 4;
  string source_channel = 5; // "email"
  google.protobuf.Timestamp received_at = 6;
}
```

**Handshake Mechanism:**
- Publishes to `invoices.received` topic
- Idempotency key: `SHA256(email_message_id + attachment_hash)`
- Retry: Exponential backoff on IMAP failures
- Health check: `/health` endpoint + can-connect-to-mailbox probe

---

### 1.2 `web-gateway/` (Target: 1200 LOC)

**Role:**
- REST API for web/mobile uploads
- Authentication/authorization (OAuth 2.0)
- Rate limiting per customer
- Multipart file upload handling
- Publish `InvoiceReceived` events

**Rationale for Isolation:**
- Public-facing attack surface (needs tight security)
- Independent deployment for UI changes
- Horizontal scaling for API traffic
- Clear API contract ownership

**External Dependencies:**
- Auth provider (Keycloak/Auth0)
- Message bus

**Integration Contract:**
```
POST /api/v1/invoices
Headers:
  Authorization: Bearer <JWT>
  Content-Type: multipart/form-data
  X-Idempotency-Key: <UUID>
Body:
  file: <binary>
  customer_oib: <string>
  metadata: <JSON>

Response 202 Accepted:
{
  "request_id": "uuid",
  "status": "received",
  "tracking_url": "/api/v1/invoices/{request_id}"
}
```

**Handshake Mechanism:**
- Publishes same `InvoiceReceivedEvent` as email-worker
- Synchronous validation (file size, MIME type)
- Async processing via message bus
- WebSocket notifications for upload progress

---

### 1.3 `file-parser/` (Target: 1000 LOC)

**Role:**
- Consume `InvoiceReceived` events
- Detect document type (PDF, PNG, JPEG, XML, CSV)
- Route to appropriate processor (OCR vs XML parser)
- Extract text/structured data
- Publish `DocumentParsed` events

**Rationale for Isolation:**
- Multiple parsing libraries (heavy dependencies)
- CPU-intensive (PDF parsing, image preprocessing)
- Independent scaling based on parsing load
- Isolation of third-party library vulnerabilities

**External Dependencies:**
- OCR processor service
- Message bus

**Integration Contract:**
```protobuf
message DocumentParsedEvent {
  string request_id = 1;
  oneof content {
    string raw_text = 2;        // OCR output
    UBLInvoice ubl_invoice = 3; // Pre-existing XML
    StructuredData csv_data = 4;
  }
  float confidence_score = 5;
  repeated string detected_fields = 6;
}
```

**Handshake Mechanism:**
- Consumes from `invoices.received` topic
- Publishes to `documents.parsed` topic
- Retries on transient failures (3 attempts)
- Dead-letter queue for unparseable documents

---

## 2. VALIDATION LAYER (`services/validation/`)

**Philosophy:** Each validator is independent, stateless, and provides single-responsibility validation. Consensus orchestrator coordinates triple redundancy.

---

### 2.1 `xsd-validator/` (Target: 600 LOC)

**Role:**
- Validate XML against UBL 2.1 XSD schema
- Syntactic correctness only (structure, types)
- Fast fail-fast validation
- Return detailed error locations (XPath)

**Rationale for Isolation:**
- Pure XML schema validation (no business logic)
- Extremely fast (<50ms per invoice)
- Reusable for multiple XML standards (UBL, CII)
- Deterministic (no external dependencies)

**External Dependencies:**
- None (embeds XSD schemas)

**Integration Contract:**
```protobuf
service XSDValidator {
  rpc Validate(XMLDocument) returns (ValidationResult);
}

message ValidationResult {
  bool is_valid = 1;
  repeated ValidationError errors = 2;
  google.protobuf.Duration processing_time = 3;
}

message ValidationError {
  string xpath = 1;
  string error_code = 2;
  string message = 3;
  Severity severity = 4; // ERROR, WARNING
}
```

**Handshake Mechanism:**
- Synchronous gRPC calls
- No state persistence
- Circuit breaker in caller
- Response time SLA: <100ms p95

---

### 2.2 `schematron-validator/` (Target: 800 LOC)

**Role:**
- Validate against Croatian CIUS business rules
- Schematron rule engine execution
- Context-aware validation (e.g., VAT rate consistency)
- Rule versioning support

**Rationale for Isolation:**
- Complex business rules (separate from schema validation)
- Rules change more frequently than XSD
- Different performance profile (heavier than XSD)
- Independent testing of business logic

**External Dependencies:**
- Schematron rule files (loaded at startup)

**Integration Contract:**
- Same gRPC interface as `xsd-validator`
- Additional rule version in request metadata
- Semantic error codes (e.g., `VAT_MISMATCH`, `INVALID_OIB_FORMAT`)

**Handshake Mechanism:**
- Synchronous gRPC calls
- Rule versioning via header: `X-CIUS-Version: 2025.1`
- Fallback to previous rule version on failure
- Response time SLA: <500ms p95

---

### 2.3 `kpd-validator/` (Target: 700 LOC)

**Role:**
- Validate KPD codes against KLASUS 2025 registry
- Verify 6-digit code validity
- Check code active status (not deprecated)
- Cache frequently used codes

**Rationale for Isolation:**
- External data source (DZS KLASUS registry)
- Caching strategy distinct from other validators
- Independent update schedule (annual KPD updates)
- Can be mocked easily for testing

**External Dependencies:**
- KLASUS API/database dump
- Redis cache (optional)

**Integration Contract:**
```protobuf
service KPDValidator {
  rpc ValidateCode(KPDCode) returns (KPDValidationResult);
  rpc BatchValidate(KPDCodeList) returns (KPDValidationResults);
}

message KPDCode {
  string code = 1; // 6+ digits
  string description = 2; // for logging
}

message KPDValidationResult {
  bool is_valid = 1;
  string canonical_description = 2; // from registry
  bool is_deprecated = 3;
  string suggested_alternative = 4; // if deprecated
}
```

**Handshake Mechanism:**
- Synchronous gRPC with batch support
- Cache TTL: 24 hours (KPD codes rarely change)
- Periodic registry sync (daily)
- Graceful degradation: Accept unknown codes with warning if registry unreachable

---

### 2.4 `business-rules-engine/` (Target: 1400 LOC)

**Role:**
- Croatian-specific tax logic validation
- VAT calculation verification
- OIB validation (checksum algorithm)
- Date range checks (invoice date, payment deadline)
- Cross-field validation (totals consistency)

**Rationale for Isolation:**
- Complex tax logic requiring tax consultant expertise
- Frequently updated (tax law changes)
- Testable independently with tax scenarios
- High code complexity (rules engine)

**External Dependencies:**
- Tax rate configuration database
- OIB validation library (shared)

**Integration Contract:**
```protobuf
service BusinessRulesEngine {
  rpc ValidateInvoice(UBLInvoice) returns (ValidationResult);
}

// Specific error codes:
// - OIB_CHECKSUM_INVALID
// - VAT_CALCULATION_MISMATCH
// - TOTAL_AMOUNT_INCONSISTENT
// - REVERSE_CHARGE_INCORRECT
```

**Handshake Mechanism:**
- Synchronous gRPC
- Rule version stamped in response
- Override capability for manual review cases
- Response time SLA: <1s p95

---

### 2.5 `ai-validator/` (Target: 1200 LOC)

**Role:**
- ML-based anomaly detection
- Pattern recognition (unusual amounts, duplicate vendors)
- OCR confidence scoring
- Fraud detection heuristics
- Explainable predictions (SHAP values)

**Rationale for Isolation:**
- Heavy ML dependencies (TensorFlow, PyTorch)
- GPU acceleration optional
- Model retraining pipeline separate from runtime
- Independent A/B testing of models

**External Dependencies:**
- Trained ML models (loaded at startup)
- Feature store (optional)

**Integration Contract:**
```protobuf
service AIValidator {
  rpc AnalyzeInvoice(InvoiceData) returns (AnomalyReport);
}

message AnomalyReport {
  float anomaly_score = 1; // 0.0 - 1.0
  repeated Anomaly detected_anomalies = 2;
  map<string, float> feature_contributions = 3; // SHAP
  string model_version = 4;
}

message Anomaly {
  string type = 1; // "duplicate", "unusual_amount", etc.
  float confidence = 2;
  string explanation = 3;
}
```

**Handshake Mechanism:**
- Asynchronous processing (can take seconds)
- Publishes to `validation.ai_complete` topic
- Model version tracking for reproducibility
- Fallback: If unavailable, skip AI validation (log warning)

---

### 2.6 `consensus-orchestrator/` (Target: 1100 LOC)

**Role:**
- Coordinate triple redundancy validation
- Aggregate results from multiple validators
- Implement majority voting algorithm
- Handle 2-1 split resolution
- Route to manual review queue if needed
- Publish final `ValidationCompleted` event

**Rationale for Isolation:**
- Central coordination point (orchestration logic)
- Implements core "fire-and-forget reliability" promise
- Complex decision tree (consensus algorithm)
- Metrics aggregation point

**External Dependencies:**
- All validator services
- Manual review queue (if consensus fails)
- Message bus

**Integration Contract:**
```protobuf
message ValidationCompleted {
  string request_id = 1;
  ValidationStatus status = 2; // VALID, INVALID, MANUAL_REVIEW
  repeated ValidationSource sources = 3;
  ConsensusDetails consensus = 4;
}

message ConsensusDetails {
  int32 validators_run = 1;
  int32 validators_passed = 2;
  bool unanimous = 3;
  string resolution_method = 4; // "majority", "manual"
}
```

**Handshake Mechanism:**
- Fan-out to all validators (parallel gRPC calls)
- Timeout: 10s total (fail-fast if validators hang)
- Quorum: 2 out of 3 minimum for VALID status
- Publishes to `validation.completed` topic
- Stores validation audit trail

---

## 3. TRANSFORMATION LAYER (`services/transformation/`)

---

### 3.1 `ubl-generator/` (Target: 1300 LOC)

**Role:**
- Transform parsed/validated data to UBL 2.1 XML
- Apply Croatian CIUS extensions
- Generate compliant invoice structure
- Insert mandatory fields (BT-1, BT-2, BT-31, etc.)
- Calculate ZKI protective code (for B2C)

**Rationale for Isolation:**
- Complex XML generation logic
- Template management (different invoice types)
- Deterministic output (testable with golden files)
- Versioned UBL standard support

**External Dependencies:**
- UBL templates
- Shared types library

**Integration Contract:**
```protobuf
service UBLGenerator {
  rpc Generate(InvoiceData) returns (UBLDocument);
}

message UBLDocument {
  string xml_content = 1;
  string ubl_version = 2; // "2.1"
  string cius_version = 3; // "HR-2025.1"
  bytes canonical_xml = 4; // for signing
}
```

**Handshake Mechanism:**
- Synchronous gRPC call
- Deterministic output (same input = same XML)
- Schema validation before return
- Response time SLA: <500ms p95

---

### 3.2 `signature-service/` (Target: 900 LOC)

**Role:**
- Apply XMLDSig digital signature
- Load FINA X.509 certificates from secure storage
- Generate SHA-256 with RSA signature
- Apply qualified timestamp (eIDAS)
- Certificate lifecycle management

**Rationale for Isolation:**
- Security-critical (private key handling)
- HSM integration (Hardware Security Module)
- Certificate rotation without service restart
- Audit logging of all signing operations

**External Dependencies:**
- HashiCorp Vault / K8s Secrets
- Timestamp Authority (TSA) API
- FINA certificate store

**Integration Contract:**
```protobuf
service SignatureService {
  rpc SignDocument(SignRequest) returns (SignedDocument);
  rpc VerifySignature(SignedDocument) returns (VerificationResult);
}

message SignRequest {
  bytes canonical_xml = 1;
  string certificate_id = 2; // which cert to use
  bool include_timestamp = 3; // for B2B
}

message SignedDocument {
  bytes signed_xml = 1;
  string signature_algorithm = 2; // "SHA256withRSA"
  google.protobuf.Timestamp signed_at = 3;
  string certificate_thumbprint = 4;
}
```

**Handshake Mechanism:**
- Synchronous gRPC (blocking on signature)
- Certificate rotation: Reload on SIGHUP
- HSM fallback: Software signing if HSM unavailable (log warning)
- All operations audited to immutable log

---

### 3.3 `ocr-processor/` (Target: 1100 LOC)

**Role:**
- Image preprocessing (deskew, denoise, contrast)
- Tesseract/Cloud Vision API integration
- Croatian language optimization
- Invoice layout detection (template matching)
- Confidence scoring per field

**Rationale for Isolation:**
- CPU/GPU intensive
- Large ML dependencies (image models)
- Independent scaling (OCR queue depth)
- Third-party API integration (Google Cloud Vision)

**External Dependencies:**
- Tesseract OCR library
- Optional: Google Cloud Vision API
- Image processing libraries (OpenCV)

**Integration Contract:**
```protobuf
service OCRProcessor {
  rpc ProcessImage(ImageDocument) returns (OCRResult);
}

message ImageDocument {
  bytes image_data = 1;
  string mime_type = 2; // "image/jpeg", "image/png"
  string language_hint = 3; // "hr"
}

message OCRResult {
  string raw_text = 1;
  map<string, ExtractedField> fields = 2; // key: field name
  float overall_confidence = 3;
  bytes annotated_image = 4; // debug overlay
}

message ExtractedField {
  string value = 1;
  float confidence = 2;
  BoundingBox location = 3;
}
```

**Handshake Mechanism:**
- Asynchronous processing (can take 5-30s)
- Publishes to `ocr.completed` topic
- Retry on transient Cloud API failures
- Fallback: Tesseract if Cloud Vision fails

---

## 4. INTEGRATION LAYER (`services/integration/`)

---

### 4.1 `fina-soap-connector/` (Target: 1000 LOC)

**Role:**
- B2C fiscalization via SOAP API
- Submit to `https://cis.porezna-uprava.hr:8449/FiskalizacijaService`
- Parse JIR (Jedinstveni Identifikator Računa) from response
- Handle offline queue (48h grace period)
- Retry logic with exponential backoff

**Rationale for Isolation:**
- External API dependency (Porezna uprava)
- SOAP protocol complexity
- Stateful (offline queue persistence)
- Independent monitoring of Tax Authority API health

**External Dependencies:**
- FINA certificate (via signature-service)
- Porezna uprava SOAP endpoint
- Offline queue (Redis/DB)

**Integration Contract:**
```protobuf
service FinaConnector {
  rpc SubmitInvoice(FiscalizationRequest) returns (FiscalizationResponse);
  rpc CheckStatus(RequestId) returns (StatusResponse);
}

message FiscalizationRequest {
  bytes signed_xml = 1;
  string customer_oib = 2;
  bool is_offline = 3; // queued from offline mode
}

message FiscalizationResponse {
  string jir = 1; // Unique Invoice Identifier
  google.protobuf.Timestamp submitted_at = 2;
  bool is_queued = 3; // if offline
}
```

**Handshake Mechanism:**
- Synchronous call with 10s timeout
- Offline fallback: Queue to Redis, retry every 5min
- Circuit breaker: Open after 5 consecutive failures
- Health check: `echo` operation every 60s

---

### 4.2 `as4-gateway/` (Target: 1400 LOC)

**Role:**
- B2B e-invoice exchange via AS4 protocol
- Four-corner model implementation
- ebMS 3.0 message handling
- Access Point certification
- Routing via AMS directory

**Rationale for Isolation:**
- Complex protocol (AS4/ebMS)
- Stateful message tracking
- Separate from B2C flow
- Can be replaced with intermediary service provider

**External Dependencies:**
- AMS client (for recipient lookup)
- AS4 intermediary OR own Access Point
- mTLS certificates

**Integration Contract:**
```protobuf
service AS4Gateway {
  rpc SendInvoice(AS4SendRequest) returns (AS4SendResponse);
  rpc ReceiveInvoice(stream AS4Message) returns (AS4ReceiptAck);
}

message AS4SendRequest {
  bytes signed_xml = 1;
  string recipient_oib = 2;
  string sender_oib = 3;
}

message AS4SendResponse {
  string message_id = 1; // ebMS message ID
  string recipient_endpoint = 2; // from AMS
  DeliveryStatus status = 3;
}
```

**Handshake Mechanism:**
- Asynchronous delivery (can take minutes)
- Receipt acknowledgment (MDN)
- Retry on network failures (3 attempts, 5min intervals)
- Publishes to `b2b.delivery_confirmed` topic

---

### 4.3 `ams-client/` (Target: 500 LOC)

**Role:**
- Query Address Metadata Service
- Find recipient Access Point endpoints
- Cache endpoint mappings
- Handle directory updates

**Rationale for Isolation:**
- Simple, focused service (directory lookup)
- Caching strategy independent
- Reusable by multiple services
- Minimal logic (API client wrapper)

**External Dependencies:**
- AMS REST/SOAP API
- Redis cache

**Integration Contract:**
```protobuf
service AMSClient {
  rpc LookupRecipient(OIB) returns (RecipientMetadata);
}

message RecipientMetadata {
  string access_point_url = 1;
  repeated string supported_formats = 2; // ["UBL2.1", "CII"]
  google.protobuf.Timestamp cached_at = 3;
}
```

**Handshake Mechanism:**
- Synchronous call with 2s timeout
- Cache TTL: 1 hour
- Fallback: Return cached data if AMS unreachable
- Invalidate cache on 404 (recipient not found)

---

### 4.4 `ereporting-service/` (Target: 1200 LOC)

**Role:**
- Aggregate monthly e-reporting data
- Generate payment reports (issuers)
- Generate rejection reports (recipients)
- Submit to ePorezna portal/API by 20th
- Track submission status

**Rationale for Isolation:**
- Batch processing (monthly schedule)
- Complex aggregation logic
- Independent of real-time invoice flow
- Regulatory reporting (separate audit requirements)

**External Dependencies:**
- Invoice database (read-only queries)
- ePorezna API
- Scheduler (Kubernetes CronJob)

**Integration Contract:**
```protobuf
service EReportingService {
  rpc GenerateReport(ReportRequest) returns (Report);
  rpc SubmitReport(Report) returns (SubmissionResult);
}

message ReportRequest {
  string customer_oib = 1;
  google.protobuf.Timestamp period_start = 2;
  google.protobuf.Timestamp period_end = 3;
  ReportType type = 4; // PAYMENT, REJECTION
}
```

**Handshake Mechanism:**
- Scheduled execution: 1st-15th of month
- Retry on submission failure (daily until 20th)
- Alert if submission fails after 18th (P1 severity)
- Publishes to `ereporting.submitted` topic

---

## 5. STORAGE LAYER (`services/storage/`)

---

### 5.1 `document-store/` (Target: 1100 LOC)

**Role:**
- Write invoices to S3-compatible storage
- Generate unique document IDs
- Store original + signed XML
- Metadata indexing (PostgreSQL)
- Enforce WORM characteristics

**Rationale for Isolation:**
- Storage abstraction (can swap S3 provider)
- Separate write path from read path
- Idempotency enforcement
- Independent scaling (storage I/O)

**External Dependencies:**
- DigitalOcean Spaces / S3
- PostgreSQL (metadata index)

**Integration Contract:**
```protobuf
service DocumentStore {
  rpc StoreDocument(StoreRequest) returns (DocumentReference);
  rpc GetDocument(DocumentReference) returns (StoredDocument);
}

message StoreRequest {
  bytes document_data = 1;
  DocumentMetadata metadata = 2;
  string idempotency_key = 3;
}

message DocumentReference {
  string document_id = 1; // UUID
  string storage_url = 2; // s3://bucket/path
  google.protobuf.Timestamp stored_at = 3;
}
```

**Handshake Mechanism:**
- Synchronous write with retry (3 attempts)
- Idempotency: Same key = same document ID
- Checksum verification (MD5)
- Immutability: No update/delete operations (only versioning)

---

### 5.2 `archive-manager/` (Target: 800 LOC)

**Role:**
- Lifecycle management (hot → warm → cold)
- Transition to Glacier after 1 year
- Scheduled signature verification
- Generate integrity reports
- Handle retrieval from cold storage

**Rationale for Isolation:**
- Background job (not in critical path)
- Storage tiering logic
- Independent execution schedule
- Cost optimization focus

**External Dependencies:**
- Document store
- S3 Glacier
- Scheduler

**Integration Contract:**
```protobuf
service ArchiveManager {
  rpc TransitionToArchive(DocumentReference) returns (ArchiveResult);
  rpc VerifyIntegrity(DocumentReference) returns (IntegrityReport);
  rpc RestoreFromArchive(DocumentReference) returns (RestorationStatus);
}
```

**Handshake Mechanism:**
- Scheduled execution: Daily at 02:00 UTC
- Batch processing (1000 documents/run)
- Signature verification: Monthly
- Alert on integrity failure (P0 severity)

---

### 5.3 `retrieval-api/` (Target: 900 LOC)

**Role:**
- Public API for document retrieval
- Authorization checks (customer can only see own docs)
- Query interface (by OIB, date range, status)
- Pagination support
- Export formats (XML, PDF preview)

**Rationale for Isolation:**
- Read-heavy workload (cache-friendly)
- Separate scaling from write path
- Public-facing (security boundary)
- Independent rate limiting

**External Dependencies:**
- Document store
- PostgreSQL metadata index
- Auth service

**Integration Contract:**
```
GET /api/v1/documents?customer_oib={oib}&start_date={date}&limit=50
Authorization: Bearer <JWT>

Response 200 OK:
{
  "documents": [
    {
      "document_id": "uuid",
      "invoice_number": "123-ZAGREB1-POS1",
      "issued_at": "2026-01-15T10:00:00Z",
      "status": "fiscalized",
      "jir": "..."
    }
  ],
  "pagination": {
    "next_cursor": "...",
    "has_more": true
  }
}
```

**Handshake Mechanism:**
- REST API (synchronous)
- Cache: Redis (TTL 5min for metadata)
- Cold storage: Async retrieval (return 202 Accepted, webhook on ready)
- Rate limit: 100 req/min per customer

---

## 6. ORCHESTRATION LAYER (`services/orchestration/`)

---

### 6.1 `invoice-workflow/` (Target: 1400 LOC)

**Role:**
- Saga orchestrator for end-to-end invoice processing
- State machine implementation
- Compensation transactions (rollback on failure)
- Progress tracking
- Timeout handling

**Rationale for Isolation:**
- Central orchestration logic
- Workflow versioning (different invoice types)
- Observability center (trace entire flow)
- Testable with mock dependencies

**External Dependencies:**
- All services (calls via gRPC/events)
- Temporal workflow engine (optional)
- State database

**Integration Contract:**
```protobuf
service InvoiceWorkflow {
  rpc StartWorkflow(InvoiceReceivedEvent) returns (WorkflowInstance);
  rpc GetWorkflowStatus(WorkflowId) returns (WorkflowStatus);
}

message WorkflowStatus {
  string workflow_id = 1;
  WorkflowState current_state = 2;
  repeated WorkflowStep completed_steps = 3;
  google.protobuf.Duration elapsed_time = 4;
}

enum WorkflowState {
  RECEIVED = 0;
  PARSING = 1;
  VALIDATING = 2;
  TRANSFORMING = 3;
  SIGNING = 4;
  FISCALIZING = 5;
  STORING = 6;
  COMPLETED = 7;
  FAILED = 8;
}
```

**Handshake Mechanism:**
- Event-driven state transitions
- Publishes state change events to `workflow.state_changed` topic
- Timeout per step: 30s (configurable)
- Compensation: Auto-retry or route to manual queue
- Distributed tracing: OpenTelemetry span per step

---

### 6.2 `event-router/` (Target: 700 LOC)

**Role:**
- Message bus abstraction layer
- Topic/queue management
- Dead-letter queue handling
- Event schema validation
- Routing rules (content-based)

**Rationale for Isolation:**
- Decouples services from specific message bus
- Centralized routing logic
- Schema registry enforcement
- Easy to swap RabbitMQ ↔ Kafka

**External Dependencies:**
- RabbitMQ/Kafka
- Schema registry (Confluent/Apicurio)

**Integration Contract:**
```protobuf
service EventRouter {
  rpc PublishEvent(Event) returns (PublishAck);
  rpc Subscribe(Subscription) returns (stream Event);
}

message Event {
  string event_id = 1;
  string event_type = 2;
  bytes payload = 3; // serialized protobuf
  map<string, string> metadata = 4;
  google.protobuf.Timestamp created_at = 5;
}
```

**Handshake Mechanism:**
- At-least-once delivery guarantee
- Idempotency enforced via `event_id`
- Schema validation before publish
- DLQ after 3 failed delivery attempts
- Circuit breaker: Stop publishing if broker unreachable

---

## 7. SHARED LIBRARIES (`shared/`)

**Philosophy:** Extract to shared ONLY after 3+ services need the same code. Keep minimal to avoid coupling.

---

### 7.1 `types/` (Target: 500 LOC)

**Contents:**
- Protocol Buffer definitions (.proto files)
- Generated code (TypeScript/Go/Rust)
- Domain models (Invoice, Customer, ValidationResult)
- Enum definitions (InvoiceType, VATCategory, WorkflowState)

**Rationale:**
- Single source of truth for data structures
- Type safety across services
- Versioning support
- Auto-generated client libraries

**Integration:**
- Imported as library in all services
- Versioned independently (semver)
- Breaking changes require major version bump

---

### 7.2 `messaging/` (Target: 400 LOC)

**Contents:**
- Event publisher/subscriber base classes
- Retry logic wrapper
- Idempotency key generation
- Message serialization helpers

**Rationale:**
- DRY principle for message bus interaction
- Consistent error handling
- Standardized retry patterns

**Performance:** < 1ms overhead, < 5KB bundle

---

### 7.3 `validation-primitives/` (Target: 600 LOC)

**Contents:**
- OIB checksum validation
- Date range validation
- Amount formatting (Croatian localization)
- XML canonicalization
- Common regex patterns (IBAN, BIC, email)

**Rationale:**
- Reusable across validators
- Unit-testable in isolation
- Croatian-specific logic centralized

**Performance:** < 0.5ms per operation

---

### 7.4 `crypto/` (Target: 500 LOC)

**Contents:**
- XMLDSig signature verification
- SHA-256 hashing helpers
- Certificate chain validation
- ZKI code generation

**Rationale:**
- Security-critical code (needs expert review)
- Reused by signature-service and document-store
- Centralized crypto dependency versions

**Performance:** < 10ms for signature verification

---

### 7.5 `observability/` (Target: 700 LOC)

**Contents:**
- Structured logging (JSON formatter)
- Request ID propagation (context injection)
- OpenTelemetry instrumentation
- Metrics helpers (Prometheus)
- Health check base class

**Rationale:**
- Consistent logging format across services
- Distributed tracing correlation
- Standard metrics naming

**Performance:** < 2ms overhead per request

---

## SUMMARY STATISTICS

| Category | Services | Total LOC Estimate |
|----------|----------|--------------------|
| Ingestion | 3 | 3,000 |
| Validation | 6 | 5,500 |
| Transformation | 3 | 3,300 |
| Integration | 4 | 4,100 |
| Storage | 3 | 2,800 |
| Orchestration | 2 | 2,100 |
| **Subtotal Services** | **21** | **20,800** |
| Shared Libraries | 5 | 2,700 |
| **GRAND TOTAL** | **26 components** | **~23,500 LOC** |

**Average per service:** ~990 LOC (well under 1500 target)
**Largest service:** `business-rules-engine` (1400 LOC)
**Smallest service:** `ams-client` (500 LOC)

---

## INTEGRATION HANDSHAKE PROTOCOLS

### 1. **Synchronous gRPC**
- Used for: Validators, signature service, document store
- Timeout: 2-10s depending on operation
- Retry: Circuit breaker pattern (3 failures = open)
- Contract: Protocol Buffers v3

### 2. **Asynchronous Events**
- Used for: Workflow orchestration, long-running processes
- Protocol: Protobuf messages over RabbitMQ/Kafka
- Guarantee: At-least-once delivery
- Idempotency: Via event_id deduplication

### 3. **REST APIs**
- Used for: Public-facing (web-gateway, retrieval-api)
- Format: JSON (OpenAPI 3.1 spec)
- Auth: OAuth 2.0 JWT
- Versioning: URL path `/api/v1/`

### 4. **File-based**
- Used for: Configuration, schemas, rule files
- Format: JSON, YAML, XML
- Validation: JSON Schema / XSD
- Versioning: Git tags

---

## DEPLOYMENT BOUNDARIES

Each service = 1 Docker container = 1 Kubernetes Deployment

**Benefits:**
- Independent scaling
- Isolated failure domains
- Gradual rollouts (canary per service)
- Resource limits per service
- Clear ownership boundaries

**Example K8s Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xsd-validator
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: xsd-validator
        image: eracun/xsd-validator:v1.2.3
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
```

---

This structure ensures AI context window efficiency (each service < 1500 LOC), clear boundaries, and robust integration while maintaining the monorepo benefits of atomic commits and shared libraries.
