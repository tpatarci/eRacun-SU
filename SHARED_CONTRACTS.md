# Shared Contracts & Interfaces

## Purpose
This document defines all shared contracts, interfaces, and message formats that enable the three development teams to work independently while ensuring seamless integration. All teams MUST adhere to these contracts.

---

## Core Domain Models

### Invoice Structure (Shared by All Teams)

```typescript
// shared/contracts/invoice.ts
export interface UBLInvoice {
  // Document identification
  id: string;                    // UUID v4
  invoiceNumber: string;          // Supplier's invoice number
  issueDate: string;              // ISO 8601 date
  dueDate?: string;               // ISO 8601 date

  // Croatian specific
  oib: {
    supplier: string;             // 11-digit OIB
    buyer: string;                // 11-digit OIB
    operator?: string;            // 11-digit OIB (if different from supplier)
  };

  // Parties
  supplier: Party;
  buyer: Party;

  // Line items
  lineItems: LineItem[];

  // Amounts
  amounts: {
    net: number;                 // Without VAT
    vat: VATBreakdown[];          // VAT by rate
    gross: number;                // Total with VAT
    currency: 'EUR' | 'HRK';      // Until Euro adoption
  };

  // Metadata
  metadata: {
    source: 'email' | 'api' | 'sftp' | 'manual';
    receivedAt: string;           // ISO 8601 timestamp
    processingId: string;         // Idempotency key
  };
}

export interface Party {
  name: string;
  address: Address;
  vatNumber: string;              // Format: HR + OIB
  email?: string;
  phone?: string;
  registrationNumber?: string;    // Company registration
}

export interface Address {
  street: string;
  city: string;
  postalCode: string;
  country: string;                // ISO 3166-1 alpha-2
}

export interface LineItem {
  id: string;                     // Line item ID
  description: string;
  quantity: number;
  unit: string;                   // UN/ECE Rec 20
  unitPrice: number;
  kpdCode: string;                // 6-digit KLASUS code (REQUIRED!)
  vatRate: 0 | 5 | 13 | 25;       // Croatian VAT rates
  vatAmount: number;
  netAmount: number;
  grossAmount: number;
}

export interface VATBreakdown {
  rate: 0 | 5 | 13 | 25;
  base: number;                   // Amount subject to this rate
  amount: number;                 // VAT amount
  category: 'STANDARD' | 'REDUCED' | 'SUPER_REDUCED' | 'EXEMPT';
}
```

### Validation Results (Team 1 → All Teams)

```typescript
// shared/contracts/validation.ts
export interface ValidationResult {
  invoiceId: string;
  timestamp: string;                // ISO 8601

  // Overall result
  valid: boolean;
  confidence: number;              // 0-1 score

  // Layer results
  layers: {
    xsd: LayerResult;
    schematron: LayerResult;
    kpd: LayerResult;
    semantic: LayerResult;
    ai: LayerResult;
    consensus: LayerResult;
  };

  // Aggregated issues
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: Suggestion[];
}

export interface LayerResult {
  passed: boolean;
  executionTime: number;           // milliseconds
  details?: any;                   // Layer-specific data
}

export interface ValidationError {
  code: string;                    // e.g., 'INVALID_OIB'
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  field: string;                   // JSONPath to field
  message: string;
  suggestion?: string;
}
```

---

## Message Bus Contracts

### RabbitMQ Command Messages

```typescript
// shared/contracts/commands.ts

// Team 2 → Team 1
export interface ProcessInvoiceCommand {
  type: 'PROCESS_INVOICE';
  correlationId: string;
  timestamp: string;
  payload: {
    source: 'email' | 'sftp' | 'api';
    sourceId: string;              // Email ID, file path, etc.
    content: string;                // Base64 encoded
    format: 'xml' | 'pdf' | 'json';
    metadata: Record<string, any>;
  };
}

// Team 1 → Team 3
export interface SubmitToFINACommand {
  type: 'SUBMIT_TO_FINA';
  correlationId: string;
  timestamp: string;
  payload: {
    invoice: UBLInvoice;
    signature?: string;             // If pre-signed
    priority: 'normal' | 'high';
    retryCount: number;
  };
}

// Team 1 → Team 2
export interface RequestOCRCommand {
  type: 'REQUEST_OCR';
  correlationId: string;
  timestamp: string;
  payload: {
    documentId: string;
    content: string;                // Base64 PDF
    options: {
      language?: string;
      enhanceImage?: boolean;
      extractTables?: boolean;
    };
  };
}

// Team 3 → Team 1
export interface SignDocumentCommand {
  type: 'SIGN_DOCUMENT';
  correlationId: string;
  timestamp: string;
  payload: {
    documentId: string;
    xml: string;
    certificateId: string;
    algorithm: 'RSA-SHA256' | 'RSA-SHA512';
  };
}
```

### Kafka Event Messages

```typescript
// shared/contracts/events.ts

// All events follow CloudEvents 1.0 spec
export interface BaseEvent {
  specversion: '1.0';
  type: string;                    // e.g., 'hr.eracun.invoice.received'
  source: string;                  // Service that emitted
  id: string;                      // Event ID (UUID)
  time: string;                    // ISO 8601
  datacontenttype: 'application/json';
  subject?: string;                // Invoice ID typically
  data: any;                       // Event-specific payload
}

// Team 2 Events
export interface InvoiceReceivedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.received';
  data: {
    invoiceId: string;
    source: 'email' | 'sftp' | 'api';
    receivedAt: string;
    size: number;                  // bytes
    format: string;
  };
}

// Team 1 Events
export interface InvoiceValidatedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.validated';
  data: {
    invoiceId: string;
    valid: boolean;
    validationResult: ValidationResult;
  };
}

export interface InvoiceTransformedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.transformed';
  data: {
    invoiceId: string;
    fromFormat: string;
    toFormat: 'UBL2.1';
    successful: boolean;
  };
}

// Team 3 Events
export interface InvoiceSubmittedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.submitted';
  data: {
    invoiceId: string;
    authority: 'FINA' | 'POREZNA';
    jir?: string;                  // If FINA submission
    confirmationNumber?: string;    // If Porezna
    timestamp: string;
  };
}

export interface CertificateExpiringEvent extends BaseEvent {
  type: 'hr.eracun.certificate.expiring';
  data: {
    certificateId: string;
    serialNumber: string;
    expiresAt: string;
    daysRemaining: number;
  };
}

export interface InvoiceArchivedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.archived';
  data: {
    invoiceId: string;
    archiveId: string;
    location: string;
    retentionUntil: string;        // 11 years from now
  };
}
```

---

## REST API Contracts

### Invoice Gateway API (Team 1)

```yaml
# services/invoice-gateway-api/openapi.yaml
openapi: 3.1.0
info:
  title: Invoice Gateway API
  version: 1.0.0

paths:
  /api/v1/invoices:
    post:
      summary: Submit invoice for processing
      requestBody:
        content:
          application/xml:
            schema:
              type: string
              format: binary
          application/json:
            schema:
              $ref: '#/components/schemas/InvoiceSubmission'
      parameters:
        - name: X-Idempotency-Key
          in: header
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '202':
          description: Accepted for processing
          content:
            application/json:
              schema:
                type: object
                properties:
                  invoiceId:
                    type: string
                    format: uuid
                  status:
                    type: string
                    enum: [QUEUED, PROCESSING]
                  trackingUrl:
                    type: string
                    format: uri

  /api/v1/invoices/{invoiceId}:
    get:
      summary: Get invoice status
      parameters:
        - name: invoiceId
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Invoice status
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/InvoiceStatus'

  /api/v1/health:
    get:
      summary: Health check
      responses:
        '200':
          description: Service healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    enum: [UP, DOWN, DEGRADED]
                  dependencies:
                    type: object
                    additionalProperties:
                      type: string
                      enum: [UP, DOWN]
```

### Admin Portal API (Team 3)

```yaml
# services/admin-portal-api/openapi.yaml
openapi: 3.1.0
info:
  title: Admin Portal API
  version: 1.0.0

paths:
  /api/v1/certificates:
    get:
      summary: List all certificates
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Certificate list
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Certificate'

  /api/v1/certificates/{certificateId}/renew:
    post:
      summary: Renew certificate
      security:
        - bearerAuth: []
        - roleAuth: [ADMIN]
      parameters:
        - name: certificateId
          in: path
          required: true
          schema:
            type: string
      responses:
        '202':
          description: Renewal initiated

  /api/v1/reports/compliance:
    post:
      summary: Generate compliance report
      security:
        - bearerAuth: []
        - roleAuth: [ADMIN, OPERATOR]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                from:
                  type: string
                  format: date
                to:
                  type: string
                  format: date
                format:
                  type: string
                  enum: [PDF, EXCEL, CSV]
      responses:
        '202':
          description: Report generation started
          content:
            application/json:
              schema:
                type: object
                properties:
                  reportId:
                    type: string
                    format: uuid
                  estimatedTime:
                    type: integer
                    description: Seconds
```

---

## gRPC Service Contracts

### Audit Logger Service (Team 3)

```protobuf
// services/audit-logger/proto/audit.proto
syntax = "proto3";

package eracun.audit;

service AuditLogger {
  rpc LogEntry(AuditLogRequest) returns (AuditLogResponse);
  rpc QueryLogs(QueryRequest) returns (stream LogEntry);
}

message AuditLogRequest {
  string correlation_id = 1;
  string service_name = 2;
  string action = 3;
  string user_id = 4;
  google.protobuf.Timestamp timestamp = 5;
  map<string, string> metadata = 6;
  string invoice_id = 7;
  Severity severity = 8;
}

message AuditLogResponse {
  string log_id = 1;
  bool success = 2;
  string error = 3;
}

message QueryRequest {
  string invoice_id = 1;
  string from_date = 2;
  string to_date = 3;
  repeated string services = 4;
  int32 limit = 5;
}

message LogEntry {
  string log_id = 1;
  string correlation_id = 2;
  string service_name = 3;
  string action = 4;
  google.protobuf.Timestamp timestamp = 5;
  map<string, string> metadata = 6;
  string hash = 7;  // For integrity verification
}

enum Severity {
  INFO = 0;
  WARN = 1;
  ERROR = 2;
  CRITICAL = 3;
}
```

---

## Feature Flags & Configuration

### Shared Feature Flags

```typescript
// shared/contracts/feature-flags.ts
export interface FeatureFlags {
  // Mock services (all teams)
  useMockFINA: boolean;
  useMockPorezna: boolean;
  useMockOCR: boolean;
  useMockAI: boolean;
  useMockEmail: boolean;

  // Processing features
  enableAIValidation: boolean;
  enableAutoRetry: boolean;
  enableBatchProcessing: boolean;

  // Performance
  parallelValidation: boolean;
  cacheValidationResults: boolean;

  // Security
  enforceDigitalSignature: boolean;
  requireCertificateValidation: boolean;

  // Monitoring
  detailedLogging: boolean;
  performanceMetrics: boolean;
}

// Default configuration for development
export const defaultFeatureFlags: FeatureFlags = {
  useMockFINA: true,
  useMockPorezna: true,
  useMockOCR: true,
  useMockAI: true,
  useMockEmail: true,
  enableAIValidation: true,
  enableAutoRetry: true,
  enableBatchProcessing: false,
  parallelValidation: true,
  cacheValidationResults: true,
  enforceDigitalSignature: false,
  requireCertificateValidation: false,
  detailedLogging: true,
  performanceMetrics: true
};
```

### Environment Variables

```bash
# .env.example (shared by all teams)

# Message Bus
RABBITMQ_URL=amqp://localhost:5672
KAFKA_BROKERS=localhost:9092

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/eracun

# Redis
REDIS_URL=redis://localhost:6379

# Feature Flags
USE_MOCK_SERVICES=true
ENVIRONMENT=development

# Service Discovery (static for now)
INVOICE_GATEWAY_URL=http://localhost:3001
FINA_CONNECTOR_URL=http://localhost:3002
OCR_SERVICE_URL=http://localhost:3003
AI_VALIDATION_URL=http://localhost:3004
ARCHIVE_SERVICE_URL=http://localhost:3005

# Monitoring
PROMETHEUS_PORT=9090
JAEGER_ENDPOINT=http://localhost:14268/api/traces

# Security
JWT_SECRET=development-secret-change-in-production
CERTIFICATE_PATH=/etc/eracun/certs
```

---

## Error Codes & Handling

### Standardized Error Codes

```typescript
// shared/contracts/errors.ts
export enum ErrorCode {
  // Validation errors (1000-1999)
  INVALID_OIB = 'ERR_1001',
  INVALID_VAT_NUMBER = 'ERR_1002',
  INVALID_KPD_CODE = 'ERR_1003',
  INVALID_VAT_RATE = 'ERR_1004',
  INVALID_XML_STRUCTURE = 'ERR_1005',
  SCHEMA_VALIDATION_FAILED = 'ERR_1006',

  // Processing errors (2000-2999)
  OCR_FAILED = 'ERR_2001',
  TRANSFORMATION_FAILED = 'ERR_2002',
  SIGNATURE_FAILED = 'ERR_2003',
  ENCRYPTION_FAILED = 'ERR_2004',

  // External service errors (3000-3999)
  FINA_UNAVAILABLE = 'ERR_3001',
  FINA_REJECTED = 'ERR_3002',
  POREZNA_UNAVAILABLE = 'ERR_3003',
  CERTIFICATE_EXPIRED = 'ERR_3004',
  CERTIFICATE_REVOKED = 'ERR_3005',

  // System errors (4000-4999)
  DATABASE_ERROR = 'ERR_4001',
  MESSAGE_BUS_ERROR = 'ERR_4002',
  STORAGE_ERROR = 'ERR_4003',
  RATE_LIMIT_EXCEEDED = 'ERR_4004',

  // Business logic errors (5000-5999)
  DUPLICATE_INVOICE = 'ERR_5001',
  INVOICE_ALREADY_PROCESSED = 'ERR_5002',
  RETENTION_PERIOD_VIOLATION = 'ERR_5003',
}

export interface StandardError {
  code: ErrorCode;
  message: string;
  details?: any;
  timestamp: string;
  service: string;
  correlationId: string;
  retryable: boolean;
  suggestedAction?: string;
}
```

---

## Testing Contracts

### Shared Test Fixtures

```typescript
// shared/test-fixtures/invoices.ts
export class TestInvoiceFactory {
  static validB2B(): UBLInvoice {
    return {
      id: '123e4567-e89b-12d3-a456-426614174000',
      invoiceNumber: 'INV-2025-001',
      issueDate: '2025-11-14',
      oib: {
        supplier: '12345678901',
        buyer: '98765432109'
      },
      // ... complete valid invoice
    };
  }

  static invalidOIB(): UBLInvoice {
    const invoice = this.validB2B();
    invoice.oib.supplier = '11111111111'; // Invalid check digit
    return invoice;
  }

  static missingKPD(): UBLInvoice {
    const invoice = this.validB2B();
    invoice.lineItems[0].kpdCode = ''; // Missing required field
    return invoice;
  }

  // ... more test cases
}

// shared/test-fixtures/certificates.ts
export const mockCertificates = {
  valid: {
    pem: '-----BEGIN CERTIFICATE-----...',
    serialNumber: 'TEST-VALID-001',
    validUntil: '2026-12-31'
  },
  expired: {
    pem: '-----BEGIN CERTIFICATE-----...',
    serialNumber: 'TEST-EXPIRED-001',
    validUntil: '2023-01-01'
  },
  revoked: {
    pem: '-----BEGIN CERTIFICATE-----...',
    serialNumber: 'TEST-REVOKED-001',
    revokedAt: '2024-06-01'
  }
};
```

### Contract Tests

```typescript
// shared/contract-tests/fina-api.contract.test.ts
export const finaContractTests = (client: IFINAClient) => {
  describe('FINA API Contract', () => {
    it('should return JIR for valid invoice', async () => {
      const invoice = TestInvoiceFactory.validB2B();
      const signed = await signWithMockCertificate(invoice);

      const response = await client.submitInvoice(signed);

      expect(response).toMatchObject({
        success: true,
        jir: expect.stringMatching(/^[A-Z0-9]{32}$/),
        zki: expect.stringMatching(/^[A-F0-9]{32}$/)
      });
    });

    it('should reject invalid OIB', async () => {
      const invoice = TestInvoiceFactory.invalidOIB();
      const signed = await signWithMockCertificate(invoice);

      const response = await client.submitInvoice(signed);

      expect(response).toMatchObject({
        success: false,
        error: expect.stringContaining('OIB')
      });
    });

    // More contract tests...
  });
};

// Each team runs these tests against their implementation
// Team 3: finaContractTests(new MockFINAService())
// Team 3: finaContractTests(new RealFINAClient())
```

---

## Integration Points Schedule

### Week 1 - Friday
**Deliverable:** Mock service libraries
- Team 3 provides mock FINA/Porezna clients
- Team 2 provides mock OCR/AI clients
- All teams validate mocks work

### Week 2 - Wednesday
**Integration Test 1:** Message flow
- Team 2 → Team 1: Invoice submission via RabbitMQ
- Team 1 → Team 3: FINA submission request
- Validate end-to-end flow with mocks

### Week 2 - Friday
**Integration Test 2:** Event propagation
- All teams subscribe to Kafka topics
- Validate event format and delivery
- Test error scenarios

### Week 3 - Wednesday
**Integration Test 3:** Full pipeline
- Real document flow from email to FINA
- All services running together
- Performance benchmarks

### Week 3 - Friday
**Final Integration:** Production readiness
- Switch from mock to real services (where available)
- Full compliance test suite
- Disaster recovery test

---

## Version Management

### Contract Versioning Rules
1. Breaking changes require major version bump (2.0.0)
2. New optional fields are minor version (1.1.0)
3. Bug fixes are patch version (1.0.1)
4. All services must support N-1 version

### Migration Strategy
```typescript
// Example: Supporting multiple versions
class InvoiceProcessor {
  async process(data: any): Promise<any> {
    const version = data.version || '1.0.0';

    switch (version) {
      case '1.0.0':
        return this.processV1(data);
      case '2.0.0':
        return this.processV2(data);
      default:
        throw new Error(`Unsupported version: ${version}`);
    }
  }
}
```

---

## Monitoring & Observability Contracts

### Standard Metrics (All Services)

```typescript
// shared/contracts/metrics.ts
export interface ServiceMetrics {
  // Latency
  http_request_duration_seconds: Histogram;
  grpc_request_duration_seconds: Histogram;
  message_processing_duration_seconds: Histogram;

  // Throughput
  http_requests_total: Counter;
  messages_processed_total: Counter;
  invoices_processed_total: Counter;

  // Errors
  errors_total: Counter;
  validation_failures_total: Counter;
  external_api_failures_total: Counter;

  // Business metrics
  invoices_by_status: Gauge;
  vat_amount_total: Counter;
  processing_queue_size: Gauge;
}
```

### Trace Context Propagation

```typescript
// All teams must propagate trace context
interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  flags: number;
}

// HTTP: Use W3C Trace Context headers
// RabbitMQ: Add to message headers
// Kafka: Add to event headers
```

---

## Compliance & Audit Requirements

### Audit Log Format (All Teams)

```typescript
// shared/contracts/audit.ts
export interface AuditEntry {
  timestamp: string;              // ISO 8601
  service: string;                // Service name
  action: string;                 // e.g., 'INVOICE_RECEIVED'
  invoiceId?: string;             // If applicable
  userId?: string;                // If user-initiated
  correlationId: string;          // Request correlation
  details: Record<string, any>;   // Action-specific
  hash: string;                   // SHA-256 of entry
}

// All teams must log:
// - Invoice receipt
// - Validation results
// - External API calls
// - Errors and failures
// - Configuration changes
```

---

## Developer Guidelines

### Using Shared Contracts

1. **Import contracts, don't duplicate:**
```typescript
import {UBLInvoice, ValidationResult} from '@eracun/shared-contracts';
```

2. **Run contract tests in CI:**
```yaml
- name: Contract Tests
  run: npm run test:contracts
```

3. **Version your APIs:**
```typescript
app.use('/api/v1', v1Routes);
app.use('/api/v2', v2Routes);
```

4. **Use feature flags for gradual rollout:**
```typescript
if (featureFlags.useMockFINA) {
  container.bind(IFINAClient).to(MockFINAService);
}
```

5. **Always validate at boundaries:**
```typescript
const invoice = validateSchema(req.body, InvoiceSchema);
```

---

**Document Version:** 1.0.0
**Created:** 2025-11-14
**Owners:** All Team Leads
**Review:** Before each integration test
**Updates:** Require approval from all teams
---

## Team 3: External Integration & Compliance Contracts

### FINA Connector API (Mock Available)

**Mock Endpoint:** Use `MockFINAService` from `@eracun/fina-connector/adapters/mock-fina`

```typescript
import { createMockFINAClient, IFINAClient } from '@eracun/fina-connector';

// Create mock client
const finaClient = createMockFINAClient();

// Submit invoice for fiscalization
const response = await finaClient.submitInvoice({
  supplierOIB: '12345678901',
  buyerOIB: '98765432109',
  invoiceNumber: 'INV-2025-001',
  issueDateTime: '2025-11-14T10:00:00Z',
  totalAmount: 1250.00,
  lineItems: [{
    description: 'Consulting services',
    quantity: 10,
    unitPrice: 100,
    vatRate: 25,
    kpdCode: '469011',
  }],
  signature: '<base64-signature>',
  certificate: {
    serialNumber: 'TEST-001',
    subject: 'CN=Test Company',
    issuer: 'CN=FINA Demo CA',
    validFrom: new Date('2024-01-01'),
    validTo: new Date('2026-12-31'),
    pem: '<certificate-pem>',
  },
  soapEnvelope: '<soap:Envelope>...</soap:Envelope>',
});

// Response structure
interface FINAResponse {
  success: boolean;
  jir?: string;          // Jedinstveni Identifikator Računa (32 hex chars)
  zki?: string;          // Zaštitni Kod Izdavatelja (32 hex chars)
  timestamp?: string;
  messageId?: string;
  soapResponse?: string;
  warnings?: string[];
  error?: { code: string; message: string };
}
```

**Test OIBs:** `12345678901`, `98765432109`, `11111111117`
**Test Certificates:** `TEST-001`, `TEST-002`

---

### Porezna Connector API (Mock Available)

**Mock Endpoint:** Use `MockPoreznaService` from `@eracun/porezna-connector/adapters/mock-porezna`

```typescript
import { createMockPoreznaClient, IPoreznaClient } from '@eracun/porezna-connector';

// Create mock client
const poreznaClient = createMockPoreznaClient();

// Submit tax report
const response = await poreznaClient.submitReport({
  period: '2025-11',
  supplierOIB: '12345678901',
  totalAmount: 100000,
  vatAmount: 25000,
  vatBreakdown: [{
    rate: 25,
    baseAmount: 100000,
    vatAmount: 25000,
  }],
  invoiceCount: 100,
});

// Validate VAT number
const validation = await poreznaClient.validateVATNumber('HR12345678901');

// Get VAT rates
const rates = await poreznaClient.getVATRates();
// Returns: [{ rate: 25, category: 'STANDARD', ... }, ...]
```

**Croatian VAT Rates (2025):**
- 25% - Standard rate
- 13% - Reduced rate (tourism, hospitality)
- 5% - Super reduced rate (essential goods)
- 0% - Exempt

---

### Digital Signature Service (Mock Available)

**Mock Endpoint:** Use `MockXMLSigner` from `@eracun/digital-signature-service/adapters/mock-signer`

```typescript
import { createMockXMLSigner, IXMLSigner } from '@eracun/digital-signature-service';

// Create mock signer
const signer = createMockXMLSigner();

// Sign XML document
const signedResult = await signer.signXML(
  '<Invoice>...</Invoice>',
  {
    referenceUri: '',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  }
);

// Verify signature
const verification = await signer.verifyXMLSignature(signedResult.xml);

interface VerificationResult {
  valid: boolean;
  signer?: string;
  timestamp?: string;
  algorithm?: string;
  error?: string;
}
```

**Performance:** 278+ signatures/second sustained throughput

---

### Reporting Service

```typescript
import { generateReport, ReportRequest } from '@eracun/reporting-service';

// Generate compliance report
const request: ReportRequest = {
  type: 'COMPLIANCE_SUMMARY',
  startDate: '2025-01-01',
  endDate: '2025-11-30',
  format: 'CSV',
};

const result = await generateReport(request);

// Available report types:
type ReportType =
  | 'COMPLIANCE_SUMMARY'    // Fiscalization success rates
  | 'FISCAL_MONTHLY'        // Monthly fiscal report
  | 'VAT_SUMMARY'           // VAT breakdown by rate
  | 'INVOICE_VOLUME'        // Volume analysis
  | 'ERROR_ANALYSIS'        // Error patterns
  | 'ARCHIVE_STATUS';       // Storage and retention status

// Available formats: 'JSON', 'CSV', 'XLSX', 'PDF'
```

---

### Message Bus (@eracun/messaging)

**PENDING-006 Resolution:** All teams can now use message bus for inter-service communication.

```typescript
import { getMessageBus } from '@eracun/messaging';

const bus = getMessageBus();

// Publish event
await bus.publish('invoice.fiscalized', {
  invoiceId: '12345',
  jir: 'ABC123...',
  timestamp: new Date().toISOString(),
});

// Subscribe to events
await bus.subscribe('invoice.validated', async (message) => {
  console.log('Validated:', message.payload);
});

// Request-response (RPC)
const result = await bus.request('signature.sign', {
  xml: '<Invoice>...</Invoice>',
}, 5000); // 5s timeout
```

**Message Topics (Team 3):**
- `invoice.fiscalized` - Published when FINA fiscalization succeeds
- `signature.sign.request` - Request XML signing
- `signature.verify.request` - Request signature verification
- `tax.report.submitted` - Tax report submitted to Porezna
- `archive.stored` - Document archived
- `compliance.report.generated` - Report generation complete

---

## Mock Service Integration Guide

### Development Setup

1. **Install mock dependencies:**
```bash
cd services/your-service
npm install @eracun/fina-connector @eracun/porezna-connector @eracun/digital-signature-service
```

2. **Enable mock mode in .env:**
```bash
USE_MOCK_FINA=true
USE_MOCK_POREZNA=true
```

3. **Use in code:**
```typescript
import { createMockFINAClient } from '@eracun/fina-connector/adapters/mock-fina';

const client = createMockFINAClient();
// Mock is ready - no network, no credentials needed
```

### Mock Behavior

**Realistic Delays:**
- FINA submission: 100-500ms
- Porezna submission: 200-500ms
- Signature generation: 20-50ms
- Signature verification: 30-60ms

**Success Rates:**
- Valid requests: 98% success
- Invalid OIB: 100% rejection
- Invalid KPD: 100% rejection
- Invalid signature: 100% rejection

**Test Data:**
All mocks include seeded test data (OIBs, certificates, companies) for consistent testing.

---

## Integration Checklist

### For Teams 1 & 2 Using Team 3 Services

- [ ] Install required npm packages
- [ ] Enable mock mode in environment
- [ ] Use provided interfaces (IFINAClient, IPoreznaClient, IXMLSigner)
- [ ] Handle both success and error responses
- [ ] Add retry logic with exponential backoff
- [ ] Use message bus for async operations
- [ ] Test with provided test OIBs and certificates

### For Team 3 

- [x] Provide mock implementations for all external APIs
- [x] Document all interfaces and contracts
- [x] Publish mock services as npm packages
- [x] Create shared certificate bundle for development
- [x] Maintain SHARED_CONTRACTS.md documentation
- [x] Provide example usage in README files
- [x] Ensure mocks behave realistically (delays, errors)

---

**Last Updated:** 2025-11-14
**Updated By:** Team 3 (External Integration & Compliance)
**Next Review:** Weekly during development
