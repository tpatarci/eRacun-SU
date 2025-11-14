# @eracun/team2-mocks

Shared mock implementations for Team 2 services, enabling independent development and testing without external dependencies.

## Features

- **MockOCREngine**: Simulates OCR text extraction with realistic confidence scores and processing delays
- **MockAIValidationEngine**: Simulates AI-powered validation including anomaly detection, risk scoring, and semantic validation
- **MockEmailClient**: Simulates IMAP email client with realistic email generation and attachment handling
- **Invoice Generator**: Generates realistic Croatian invoice data with valid OIB numbers and KPD codes

## Installation

```bash
cd shared/team2-mocks
npm install
npm run build
```

## Usage

### Mock OCR Engine

```typescript
import { MockOCREngine } from '@eracun/team2-mocks';

const ocrEngine = new MockOCREngine();

// Extract text from image
const result = await ocrEngine.extractText(imageBuffer);
console.log(result.text);
console.log(`Confidence: ${result.confidence}`);

// Extract tables
const tables = await ocrEngine.extractTables(imageBuffer);
console.log(tables[0].headers);
```

### Mock AI Validation Engine

```typescript
import { MockAIValidationEngine, InvoiceBuilder } from '@eracun/team2-mocks';

const aiEngine = new MockAIValidationEngine();

// Create test invoice
const invoice = InvoiceBuilder.createValid().build();

// Detect anomalies
const anomalies = await aiEngine.detectAnomalies(invoice);
console.log(`Found ${anomalies.length} anomalies`);

// Validate semantics
const validation = await aiEngine.validateSemantics(invoice);
console.log(`Valid: ${validation.valid}`);

// Calculate risk score
const riskScore = await aiEngine.calculateRiskScore(invoice);
console.log(`Risk: ${riskScore.category} (${riskScore.score.toFixed(2)})`);
```

### Mock Email Client

```typescript
import { MockEmailClient } from '@eracun/team2-mocks';

const emailClient = new MockEmailClient();

// Connect to mock server
await emailClient.connect();

// Fetch unread emails
const unreadEmails = await emailClient.fetchUnread({ limit: 10 });
console.log(`Found ${unreadEmails.length} unread emails`);

// Download attachment
for (const email of unreadEmails) {
  for (const attachment of email.attachments) {
    const content = await emailClient.downloadAttachment(email.id, attachment.id);
    console.log(`Downloaded: ${attachment.filename} (${content.length} bytes)`);
  }
}

// Mark as processed
await emailClient.markAsProcessed(unreadEmails[0].id);
```

### Invoice Data Generator

```typescript
import { generateInvoice, generateOIB, InvoiceBuilder } from '@eracun/team2-mocks';

// Generate random invoice
const invoice = generateInvoice();
console.log(invoice);

// Generate valid OIB
const oib = generateOIB();
console.log(`OIB: ${oib}`); // 11-digit number with valid check digit

// Use builder pattern
const customInvoice = InvoiceBuilder.create()
  .withAmount(10000)
  .withSupplier('12345678901')
  .withDate('2025-11-14')
  .build();
```

## Architecture

### Interfaces

All mock implementations follow defined interfaces:
- `IOCREngine`: Contract for OCR functionality
- `IAIValidationEngine`: Contract for AI validation
- `IEmailClient`: Contract for email operations

This allows easy swapping between mock and production implementations.

### Realistic Behavior

Mocks simulate realistic behavior including:
- **Processing delays**: Based on input size (OCR) or complexity (AI)
- **Confidence scores**: Varied based on scenario quality
- **Errors**: Occasional anomalies and validation errors
- **Data variation**: Randomized but realistic test data

### Croatian Compliance

Generated data adheres to Croatian standards:
- **OIB numbers**: Valid 11-digit identification with ISO 7064 check digit
- **KPD codes**: KLASUS 2025 6-digit classification codes
- **VAT rates**: Croatian rates (25%, 13%, 5%, 0%)
- **Currency**: EUR (Croatia's currency since 2023)
- **UBL 2.1**: Valid XML invoice structure

## Testing with Mocks

### Unit Testing Example

```typescript
import { MockOCREngine, InvoiceBuilder } from '@eracun/team2-mocks';

describe('OCR Processing Service', () => {
  let ocrEngine: MockOCREngine;

  beforeEach(() => {
    ocrEngine = new MockOCREngine();
  });

  it('should extract text from invoice image', async () => {
    const mockImage = Buffer.from('mock-image-data');
    const result = await ocrEngine.extractText(mockImage);

    expect(result.confidence).toBeGreaterThan(0.6);
    expect(result.blocks.length).toBeGreaterThan(0);
  });

  it('should extract tables with line items', async () => {
    const mockImage = Buffer.from('mock-image-data');
    const tables = await ocrEngine.extractTables(mockImage);

    expect(tables).toHaveLength(1);
    expect(tables[0].headers).toContain('Opis');
    expect(tables[0].rows.length).toBeGreaterThan(0);
  });
});
```

### Property-Based Testing

The library supports property-based testing with fast-check:

```typescript
import * as fc from 'fast-check';
import { InvoiceBuilder } from '@eracun/team2-mocks';

it('should handle any valid OIB', () => {
  fc.assert(
    fc.property(
      fc.string().filter(s => /^\d{11}$/.test(s)),
      async (oib) => {
        const invoice = InvoiceBuilder.create()
          .withSupplier(oib)
          .build();

        // Should not throw
        expect(invoice.supplierOIB).toBe(oib);
      }
    )
  );
});
```

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run type checking
npm run typecheck

# Run linting
npm run lint
```

## Integration with Services

Services can use these mocks by adding a dependency:

```json
{
  "dependencies": {
    "@eracun/team2-mocks": "file:../../shared/team2-mocks"
  }
}
```

Then configure the service to use mocks in test/development mode:

```typescript
import { IOCREngine, MockOCREngine } from '@eracun/team2-mocks';

// Production
const ocrEngine: IOCREngine = process.env.NODE_ENV === 'production'
  ? new ProductionOCREngine()
  : new MockOCREngine();
```

## Scenarios

### OCR Scenarios

The MockOCREngine supports different quality scenarios:
- **high-quality**: 98% confidence, clear text, all features
- **medium-quality**: 87% confidence, some blur
- **low-quality**: 65% confidence, poor resolution
- **skewed**: 75% confidence, document at angle
- **multilingual**: 82% confidence, mixed languages

Scenarios are auto-selected based on input buffer size, or can be manually configured.

### AI Validation Scenarios

The MockAIValidationEngine simulates various validation scenarios:
- **Price anomalies**: 10% occurrence rate
- **VAT errors**: 5% occurrence rate
- **Duplicates**: 3% occurrence rate
- **Suspicious amounts**: 2% occurrence rate

These rates can be customized for specific test scenarios.

## Performance Characteristics

Mock implementations simulate realistic performance:

| Operation | Simulated Time |
|-----------|----------------|
| OCR text extraction | 100-5000ms (size-dependent) |
| OCR table extraction | ~500ms |
| AI anomaly detection | 200-1000ms |
| AI semantic validation | 200-1000ms |
| AI risk scoring | 200-1000ms |
| Email fetch | ~200ms |
| Attachment download | 100-2000ms (size-dependent) |

## License

UNLICENSED - Internal use only

## Maintainer

eRacun Team 2 (Ingestion & Document Processing)
