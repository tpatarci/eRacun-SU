# TEAM 2: Ingestion & Document Processing

## Mission Statement
Build robust document ingestion capabilities supporting multiple input channels (email, API, SFTP), with intelligent classification, OCR processing, and AI-powered validation. Operate independently using mock OCR/AI services until integration phase.

## Team Composition
- 1 Senior Backend Engineer (Lead)
- 1 ML/AI Engineer
- 1 Backend Engineer
- 1 QA Engineer

## Assigned Bounded Contexts

### 1. email-ingestion-worker
**Purpose:** Process invoices received via email
**Priority:** P0 - Primary ingestion channel

### 2. sftp-ingestion-worker
**Purpose:** Handle bulk invoice uploads via SFTP
**Priority:** P1 - Enterprise integration channel

### 3. file-classifier
**Purpose:** Identify document types and formats
**Priority:** P0 - Required for routing

### 4. ocr-processing-service
**Purpose:** Extract text from scanned documents
**Priority:** P1 - Critical for paper invoices

### 5. ai-validation-service
**Purpose:** Anomaly detection and semantic validation
**Priority:** P1 - Advanced validation layer

### 6. attachment-handler
**Purpose:** Extract and process email/archive attachments
**Priority:** P1 - Required for complete processing

---

## External Dependencies & Mocking Strategy

### Mock AI/OCR Services

```typescript
// services/ocr-processing-service/src/adapters/interfaces.ts
export interface IOCREngine {
  extractText(image: Buffer, options?: OCROptions): Promise<TextResult>;
  extractTables(image: Buffer): Promise<TableResult[]>;
  detectLanguage(image: Buffer): Promise<Language>;
  getConfidence(): Promise<number>;
}

export interface IAIValidationEngine {
  detectAnomalies(invoice: StructuredInvoice): Promise<AnomalyResult[]>;
  validateSemantics(invoice: StructuredInvoice): Promise<SemanticValidation>;
  suggestCorrections(errors: ValidationError[]): Promise<Correction[]>;
  calculateRiskScore(invoice: StructuredInvoice): Promise<RiskScore>;
}

// services/ocr-processing-service/src/adapters/mock-ocr.ts
export class MockOCREngine implements IOCREngine {
  private readonly scenarios: Map<string, OCRScenario>;

  constructor() {
    this.scenarios = this.loadScenarios();
  }

  async extractText(image: Buffer, options?: OCROptions): Promise<TextResult> {
    // Simulate processing time based on image size
    const processingTime = this.calculateProcessingTime(image);
    await this.simulateProcessing(processingTime);

    // Generate realistic OCR output
    const scenario = this.detectScenario(image);

    return {
      text: scenario.text,
      confidence: scenario.confidence,
      language: scenario.language,
      blocks: this.generateTextBlocks(scenario),
      processingTime
    };
  }

  private generateTextBlocks(scenario: OCRScenario): TextBlock[] {
    // Generate realistic text blocks with bounding boxes
    const invoice = InvoiceDataGenerator.generate();

    return [
      {
        text: `RAČUN BR: ${invoice.number}`,
        boundingBox: {x: 100, y: 50, width: 200, height: 30},
        confidence: 0.98
      },
      {
        text: `Datum: ${invoice.date}`,
        boundingBox: {x: 100, y: 90, width: 150, height: 25},
        confidence: 0.95
      },
      {
        text: `OIB: ${invoice.supplierOIB}`,
        boundingBox: {x: 100, y: 120, width: 180, height: 25},
        confidence: scenario.oibConfidence || 0.92
      },
      // ... more blocks
    ];
  }

  async extractTables(image: Buffer): Promise<TableResult[]> {
    // Mock table extraction for invoice line items
    const items = this.generateLineItems();

    return [{
      headers: ['Opis', 'Količina', 'Cijena', 'PDV', 'Ukupno'],
      rows: items.map(item => [
        item.description,
        item.quantity.toString(),
        item.price.toFixed(2),
        item.vat.toFixed(2),
        item.total.toFixed(2)
      ]),
      confidence: 0.89
    }];
  }

  private generateLineItems(): LineItem[] {
    const count = Math.floor(Math.random() * 10) + 1;
    return Array.from({length: count}, (_, i) => ({
      description: `Proizvod ${i + 1}`,
      quantity: Math.floor(Math.random() * 100) + 1,
      price: Math.random() * 1000,
      vat: 0.25, // Croatian standard VAT
      total: 0 // calculated
    })).map(item => ({
      ...item,
      total: item.quantity * item.price * (1 + item.vat)
    }));
  }

  private calculateProcessingTime(image: Buffer): number {
    // Realistic processing time based on image size
    const sizeInMB = image.length / (1024 * 1024);
    return Math.min(100 + sizeInMB * 500, 5000); // 100-5000ms
  }

  private simulateProcessing(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// services/ai-validation-service/src/adapters/mock-ai.ts
export class MockAIValidationEngine implements IAIValidationEngine {
  private readonly mlModels: Map<string, MockMLModel>;

  async detectAnomalies(invoice: StructuredInvoice): Promise<AnomalyResult[]> {
    const anomalies: AnomalyResult[] = [];

    // Simulate various anomaly detection scenarios
    if (this.isPriceAnomaly(invoice)) {
      anomalies.push({
        type: 'PRICE_ANOMALY',
        severity: 'HIGH',
        field: 'totalAmount',
        expected: this.calculateExpectedPrice(invoice),
        actual: invoice.totalAmount,
        confidence: 0.87,
        explanation: 'Price significantly deviates from historical patterns'
      });
    }

    if (this.isVATAnomaly(invoice)) {
      anomalies.push({
        type: 'VAT_CALCULATION_ERROR',
        severity: 'CRITICAL',
        field: 'vatAmount',
        expected: this.calculateVAT(invoice),
        actual: invoice.vatAmount,
        confidence: 0.95,
        explanation: 'VAT calculation does not match line items'
      });
    }

    if (this.isDuplicateInvoice(invoice)) {
      anomalies.push({
        type: 'POTENTIAL_DUPLICATE',
        severity: 'MEDIUM',
        field: 'invoiceNumber',
        similarInvoices: this.findSimilarInvoices(invoice),
        confidence: 0.78,
        explanation: 'Similar invoice detected in recent history'
      });
    }

    // Simulate processing delay
    await this.simulateAIProcessing();

    return anomalies;
  }

  async validateSemantics(invoice: StructuredInvoice): Promise<SemanticValidation> {
    const errors: SemanticError[] = [];
    const warnings: SemanticWarning[] = [];

    // Business rule validations
    if (!this.isValidBusinessRelationship(invoice)) {
      errors.push({
        code: 'INVALID_BUSINESS_RELATIONSHIP',
        message: 'Supplier-buyer relationship not recognized',
        field: 'parties',
        suggestion: 'Verify business registration'
      });
    }

    if (!this.isReasonableDeliveryDate(invoice)) {
      warnings.push({
        code: 'SUSPICIOUS_DELIVERY_DATE',
        message: 'Delivery date is unusual',
        field: 'deliveryDate',
        suggestion: 'Verify delivery date is correct'
      });
    }

    // KPD classification validation
    const kpdValidation = await this.validateKPDCodes(invoice);
    if (!kpdValidation.valid) {
      errors.push(...kpdValidation.errors);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      processingTime: Date.now(),
      modelVersion: '2.1.0-mock'
    };
  }

  async calculateRiskScore(invoice: StructuredInvoice): Promise<RiskScore> {
    // Simulate risk scoring with multiple factors
    const factors: RiskFactor[] = [
      {
        name: 'supplier_history',
        weight: 0.3,
        score: Math.random() * 0.3
      },
      {
        name: 'amount_variance',
        weight: 0.25,
        score: this.calculateAmountVariance(invoice) * 0.25
      },
      {
        name: 'payment_terms',
        weight: 0.2,
        score: this.evaluatePaymentTerms(invoice) * 0.2
      },
      {
        name: 'document_quality',
        weight: 0.15,
        score: Math.random() * 0.15
      },
      {
        name: 'compliance_check',
        weight: 0.1,
        score: Math.random() * 0.1
      }
    ];

    const totalScore = factors.reduce((sum, f) => sum + f.score, 0);

    return {
      score: totalScore,
      category: this.categorizeRisk(totalScore),
      factors,
      threshold: 0.7,
      requiresManualReview: totalScore > 0.7,
      explanation: this.generateRiskExplanation(factors, totalScore)
    };
  }

  private simulateAIProcessing(): Promise<void> {
    // Realistic AI processing delay
    return new Promise(resolve =>
      setTimeout(resolve, 200 + Math.random() * 800)
    );
  }

  private isPriceAnomaly(invoice: StructuredInvoice): boolean {
    // 10% chance of price anomaly in mock
    return Math.random() < 0.1;
  }

  private isVATAnomaly(invoice: StructuredInvoice): boolean {
    // 5% chance of VAT calculation error in mock
    return Math.random() < 0.05;
  }

  private isDuplicateInvoice(invoice: StructuredInvoice): boolean {
    // 3% chance of duplicate detection in mock
    return Math.random() < 0.03;
  }
}
```

### Email Processing Mock

```typescript
// services/email-ingestion-worker/src/adapters/mock-email.ts
export class MockEmailClient implements IEmailClient {
  private mockInbox: EmailMessage[] = [];

  constructor() {
    // Generate mock emails on initialization
    this.seedMockInbox();
  }

  async connect(): Promise<void> {
    // Simulate connection delay
    await this.delay(500);
  }

  async fetchUnread(): Promise<EmailMessage[]> {
    // Return mock unread messages
    const unread = this.mockInbox.filter(m => !m.read);

    // Mark as read
    unread.forEach(m => m.read = true);

    return unread;
  }

  async fetchMessage(messageId: string): Promise<EmailMessage> {
    const message = this.mockInbox.find(m => m.id === messageId);
    if (!message) {
      throw new Error(`Message ${messageId} not found`);
    }
    return message;
  }

  async markAsProcessed(messageId: string): Promise<void> {
    const message = this.mockInbox.find(m => m.id === messageId);
    if (message) {
      message.processed = true;
      message.labels = ['PROCESSED', 'ERACUN'];
    }
  }

  async downloadAttachment(messageId: string, attachmentId: string): Promise<Buffer> {
    // Generate mock invoice attachment
    const invoiceType = Math.random() > 0.5 ? 'pdf' : 'xml';

    if (invoiceType === 'pdf') {
      return this.generateMockPDF();
    } else {
      return Buffer.from(InvoiceGenerator.generateValidUBL());
    }
  }

  private seedMockInbox(): void {
    // Generate 10-20 mock emails
    const count = Math.floor(Math.random() * 10) + 10;

    for (let i = 0; i < count; i++) {
      this.mockInbox.push(this.generateMockEmail());
    }
  }

  private generateMockEmail(): EmailMessage {
    const hasAttachment = Math.random() > 0.3; // 70% have attachments

    return {
      id: faker.string.uuid(),
      from: faker.internet.email(),
      to: 'invoices@eracun.hr',
      subject: this.generateSubject(),
      body: faker.lorem.paragraphs(2),
      date: faker.date.recent(),
      read: false,
      processed: false,
      attachments: hasAttachment ? this.generateAttachments() : [],
      labels: [],
      headers: {
        'message-id': `<${faker.string.uuid()}@${faker.internet.domainName()}>`,
        'return-path': faker.internet.email()
      }
    };
  }

  private generateSubject(): string {
    const subjects = [
      'Račun br. ${faker.number.int({min: 1000, max: 9999})}',
      'Invoice ${faker.date.recent().toISOString().split("T")[0]}',
      'Faktura - ${faker.company.name()}',
      'RE: Dostava računa',
      'Fwd: Invoice for services'
    ];
    return faker.helpers.arrayElement(subjects);
  }

  private generateAttachments(): Attachment[] {
    const count = Math.floor(Math.random() * 3) + 1;
    const attachments: Attachment[] = [];

    for (let i = 0; i < count; i++) {
      const type = faker.helpers.arrayElement(['pdf', 'xml', 'zip', 'jpg']);
      attachments.push({
        id: faker.string.uuid(),
        filename: `invoice_${faker.number.int({min: 1000, max: 9999})}.${type}`,
        mimeType: this.getMimeType(type),
        size: faker.number.int({min: 10000, max: 5000000})
      });
    }

    return attachments;
  }

  private getMimeType(extension: string): string {
    const mimeTypes: Record<string, string> = {
      pdf: 'application/pdf',
      xml: 'application/xml',
      zip: 'application/zip',
      jpg: 'image/jpeg'
    };
    return mimeTypes[extension] || 'application/octet-stream';
  }

  private generateMockPDF(): Buffer {
    // Generate a simple mock PDF buffer
    // In real implementation, could use pdf-lib to generate actual PDF
    const mockContent = `Mock PDF Invoice Content
    Invoice Number: ${faker.number.int({min: 1000, max: 9999})}
    Date: ${faker.date.recent().toISOString()}
    Amount: ${faker.number.float({min: 100, max: 10000, precision: 0.01})}`;

    return Buffer.from(mockContent);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

---

## Implementation Roadmap

### Week 1: Foundation & Mock Infrastructure
**Owner:** Senior Backend Engineer + ML/AI Engineer

#### Day 1-2: Mock Service Implementation
- [ ] Implement MockOCREngine with realistic scenarios
- [ ] Implement MockAIValidationEngine with ML model simulations
- [ ] Create MockEmailClient with IMAP simulation
- [ ] Setup mock SFTP server for testing
- [ ] Generate comprehensive test data sets

#### Day 3-4: file-classifier Service
- [ ] MIME type detection
- [ ] Magic number file identification
- [ ] Content-based classification (invoice vs. non-invoice)
- [ ] Language detection for multi-language support
- [ ] Confidence scoring for classification

#### Day 5: attachment-handler Service
- [ ] ZIP/RAR/7z extraction
- [ ] Nested archive handling
- [ ] Password-protected archive support (with config)
- [ ] Virus scanning simulation
- [ ] File size and type validation

### Week 2: Core Ingestion Services
**Owner:** Backend Engineer + ML/AI Engineer

#### Day 6-7: email-ingestion-worker
- [ ] IMAP client implementation with mock fallback
- [ ] Email parsing (headers, body, attachments)
- [ ] Duplicate detection (Message-ID tracking)
- [ ] Auto-reply detection and filtering
- [ ] Attachment extraction and queuing

#### Day 8-9: sftp-ingestion-worker
- [ ] SFTP server setup (mock and real)
- [ ] File watcher implementation
- [ ] Batch processing logic
- [ ] File movement (inbox → processing → archive)
- [ ] Error handling and retry logic

#### Day 10: ocr-processing-service
- [ ] Image preprocessing (deskew, denoise)
- [ ] Multi-page document handling
- [ ] Table extraction for line items
- [ ] Barcode/QR code detection
- [ ] Output structuring to JSON

### Week 3: AI Validation & Integration
**Owner:** ML/AI Engineer + Full Team

#### Day 11-12: ai-validation-service
- [ ] Anomaly detection models (mock)
- [ ] Semantic validation rules engine
- [ ] Risk scoring algorithm
- [ ] Historical pattern analysis (mock)
- [ ] Fraud detection patterns

#### Day 13-14: Integration & Orchestration
- [ ] RabbitMQ message handlers for all services
- [ ] Kafka event publishing
- [ ] End-to-end processing pipeline
- [ ] Error recovery and compensation
- [ ] Performance optimization

#### Day 15: Testing & Documentation
- [ ] 100% unit test coverage
- [ ] Integration test suite
- [ ] Load testing (1000 emails/hour)
- [ ] Chaos testing scenarios
- [ ] Complete documentation

---

## Testing Strategy

### Unit Testing Approach

```typescript
// services/ai-validation-service/tests/unit/anomaly-detector.test.ts
describe('AnomalyDetector', () => {
  let detector: AnomalyDetector;
  let mockEngine: MockAIValidationEngine;

  beforeEach(() => {
    mockEngine = new MockAIValidationEngine();
    detector = new AnomalyDetector(mockEngine);
  });

  describe('detectPriceAnomalies', () => {
    it('should detect significant price deviations', async () => {
      const invoice = InvoiceBuilder.create()
        .withAmount(1000000) // Unusually high
        .withSupplier('12345678901')
        .build();

      const anomalies = await detector.detect(invoice);

      expect(anomalies).toContainEqual(
        expect.objectContaining({
          type: 'PRICE_ANOMALY',
          severity: 'HIGH'
        })
      );
    });

    it('should calculate confidence scores correctly', async () => {
      const invoice = InvoiceBuilder.createValid().build();
      const anomalies = await detector.detect(invoice);

      anomalies.forEach(anomaly => {
        expect(anomaly.confidence).toBeGreaterThanOrEqual(0);
        expect(anomaly.confidence).toBeLessThanOrEqual(1);
      });
    });
  });

  describe('property-based testing', () => {
    it('should handle any valid OIB in supplier field', () => {
      fc.assert(
        fc.property(
          fc.string().filter(s => /^\d{11}$/.test(s)),
          async (oib) => {
            const invoice = InvoiceBuilder.create()
              .withSupplier(oib)
              .build();

            const result = await detector.detect(invoice);
            // Should not throw, should return array
            expect(Array.isArray(result)).toBe(true);
          }
        )
      );
    });
  });
});
```

### Integration Testing

```typescript
// services/email-ingestion-worker/tests/integration/email-pipeline.test.ts
describe('Email Ingestion Pipeline', () => {
  let worker: EmailIngestionWorker;
  let mockEmailClient: MockEmailClient;
  let rabbitMQ: RabbitMQTestContainer;

  beforeAll(async () => {
    rabbitMQ = await new RabbitMQTestContainer().start();
    process.env.RABBITMQ_URL = rabbitMQ.getConnectionString();

    mockEmailClient = new MockEmailClient();
    worker = new EmailIngestionWorker(mockEmailClient);
  });

  it('should process email with PDF attachment end-to-end', async () => {
    // Arrange
    const messageId = await mockEmailClient.seedInvoiceEmail({
      type: 'pdf',
      supplierOIB: '12345678901'
    });

    // Act
    await worker.processNewEmails();

    // Assert
    const events = await rabbitMQ.getPublishedEvents('invoice.received');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      source: 'email',
      messageId,
      attachmentCount: 1,
      requiresOCR: true
    });
  });

  it('should handle email processing failures gracefully', async () => {
    // Simulate OCR failure
    mockEmailClient.seedCorruptedEmail();

    await worker.processNewEmails();

    const dlq = await rabbitMQ.getDeadLetterQueue();
    expect(dlq).toHaveLength(1);
    expect(dlq[0].error).toContain('OCR_PROCESSING_FAILED');
  });
});
```

### Load Testing

```javascript
// tests/load/email-ingestion.js
import http from 'k6/http';
import {check, sleep} from 'k6';

export let options = {
  stages: [
    {duration: '5m', target: 100},  // Ramp up
    {duration: '10m', target: 100}, // Sustain
    {duration: '5m', target: 0},    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'], // 95% of requests under 2s
    http_req_failed: ['rate<0.05'],    // Error rate under 5%
  },
};

export default function() {
  const email = generateMockEmail();

  const response = http.post(
    'http://localhost:3000/api/v1/email/webhook',
    JSON.stringify(email),
    {
      headers: {'Content-Type': 'application/json'},
    }
  );

  check(response, {
    'status is 202': (r) => r.status === 202,
    'has message id': (r) => JSON.parse(r.body).messageId !== undefined,
  });

  sleep(1);
}

function generateMockEmail() {
  return {
    from: `supplier${Math.random()}@example.com`,
    subject: `Invoice ${Date.now()}`,
    attachments: [{
      filename: 'invoice.pdf',
      content: generateBase64PDF(),
    }],
  };
}
```

---

## Performance Requirements

### Processing Targets
- Email processing: 1000 emails/hour
- OCR processing: 200 documents/hour
- AI validation: 500 invoices/hour
- File classification: <100ms per file
- Attachment extraction: <500ms per archive

### Resource Allocation
- email-ingestion-worker: 512MB RAM, 0.5 CPU
- ocr-processing-service: 1GB RAM, 2 CPU (heavy processing)
- ai-validation-service: 1GB RAM, 1 CPU
- Others: 256MB RAM, 0.25 CPU

---

## Deliverables

### Services (6 total)
- [ ] email-ingestion-worker (complete with tests)
- [ ] sftp-ingestion-worker (complete with tests)
- [ ] file-classifier (complete with tests)
- [ ] ocr-processing-service (complete with tests)
- [ ] ai-validation-service (complete with tests)
- [ ] attachment-handler (complete with tests)

### Mock Implementations
- [ ] MockOCREngine with 10+ scenarios
- [ ] MockAIValidationEngine with ML simulations
- [ ] MockEmailClient with IMAP behavior
- [ ] Mock SFTP server
- [ ] Test data generators

### Documentation
- [ ] Service README files
- [ ] API specifications
- [ ] Integration guides
- [ ] Performance benchmarks
- [ ] Runbooks

### Testing Artifacts
- [ ] Unit tests (100% coverage)
- [ ] Integration test suite
- [ ] Load test scripts
- [ ] Chaos test scenarios
- [ ] Contract tests

---

## Risk Management

### Risk: OCR accuracy in production
**Mitigation:**
- Create comprehensive test dataset with real invoice scans
- Implement confidence thresholds
- Human-in-the-loop for low confidence
- A/B testing with multiple OCR engines

### Risk: AI model drift
**Mitigation:**
- Version all models explicitly
- Monitor prediction accuracy metrics
- Implement feedback loop for corrections
- Regular model retraining schedule

### Risk: Email service reliability
**Mitigation:**
- Implement retry logic with exponential backoff
- Dead letter queue for failed messages
- Multiple email account support
- Webhook fallback option

---

## Communication & Coordination

### Sync Points with Other Teams
- **Team 1:** Invoice format specifications (Week 1)
- **Team 3:** External API contracts (Week 2)
- **All Teams:** Integration testing (Week 3)

### Deliverable Handoffs
- Week 1: Mock service library to all teams
- Week 2: Ingestion API specifications
- Week 3: Complete services ready for integration

---

**Document Version:** 1.0.0
**Created:** 2025-11-14
**Owner:** Team 2 Lead
**Review:** Daily standup, weekly retrospective