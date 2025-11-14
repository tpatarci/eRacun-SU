# @eracun/mocks

Mock service implementations for eRačun development.

## Purpose

Provides realistic mock implementations of all adapter interfaces with:
- **Realistic Network Delays** - Simulates actual service latency (50-2000ms)
- **Success/Failure Rates** - Configurable success rates (85-99%)
- **Edge Cases** - Invalid data, timeouts, errors
- **Stateful Behavior** - Maintains state for subsequent calls

## Installation

```bash
npm install @eracun/mocks
```

## Usage

### Direct Usage

```typescript
import { MockValidationService, MockFINAService, MockOCRService } from '@eracun/mocks';

// Create instance
const validationService = new MockValidationService();

// Use like real service
const result = await validationService.validateXSD(xml);
console.log(result.passed); // true/false based on mock logic
```

### With Dependency Injection

```typescript
import 'reflect-metadata';
import { Container } from 'inversify';
import { TYPES } from '@eracun/di-container';
import { IValidationService } from '@eracun/adapters';
import { MockValidationService } from '@eracun/mocks';

const container = new Container();
container.bind<IValidationService>(TYPES.ValidationService).to(MockValidationService);

const service = container.get<IValidationService>(TYPES.ValidationService);
```

## Mock Services

### MockValidationService

**Success Rates:**
- XSD Validation: 90%
- Schematron Validation: 85%
- KPD Validation: 95%
- Semantic Validation: 95%
- AI Validation: 95%

**Network Delays:**
- XSD: 50-150ms
- Schematron: 100-200ms
- KPD: 30-80ms
- Semantic: 50-100ms
- AI: 200-400ms

**Behavior:**
- Validates XML format
- Checks OIB format (11 digits)
- Validates KPD codes (6 digits)
- Simulates consensus voting

### MockFINAService

**Success Rate:** 95%

**Network Delays:**
- Submit: 500-1500ms
- Status Check: 100-300ms
- JIR Verify: 200-400ms

**Behavior:**
- Generates realistic JIR (32 chars)
- Maintains submission state
- Simulates rejection (5% rate)

**Common Errors:**
- Invalid signature
- Certificate validation failed

### MockPoreznaService

**Success Rate:** 97%

**Network Delays:**
- Submit Invoice: 300-800ms
- Submit Report: 500-1200ms

**Behavior:**
- Generates confirmation numbers
- Simulates duplicate detection
- Validates monthly reports

### MockOCRService

**Success Rates:**
- Text Extraction: 92%
- Structured Data: 85%
- Table Extraction: 88%

**Network Delays:**
- Text: 500-1500ms
- Structured: 800-2000ms
- Tables: 600-1800ms

**Behavior:**
- Generates Croatian invoice text
- Extracts realistic structured data
- Generates valid OIB numbers
- Simulates low-quality scans (failure cases)

### MockAIValidationService

**Anomaly Detection:** 10% chance
**Validation Pass Rate:** 97%

**Network Delays:**
- Anomaly Detection: 300-800ms
- Cross Validation: 200-600ms
- Suggestions: 200-500ms

**Behavior:**
- Detects outliers in amounts
- Validates VAT calculations
- Suggests KPD code corrections

## Behavior Characteristics

### Network Simulation

All mocks use `simulateNetworkDelay()` to add realistic latency:

```typescript
private async simulateNetworkDelay(min: number = 100, max: number = 500): Promise<void> {
  const delay = Math.random() * (max - min) + min;
  return new Promise(resolve => setTimeout(resolve, delay));
}
```

### Success Rate Configuration

Success rates are hardcoded but realistic:

```typescript
// 90% success rate
const passed = Math.random() > 0.1;
```

**Future Enhancement:** Make success rates configurable via constructor.

### Stateful Behavior

Some mocks maintain state:

```typescript
// MockFINAService stores submissions
private submissions = new Map<string, FINAStatusResponse>();

// Later retrieved with getStatus()
const status = this.submissions.get(invoiceId);
```

## Testing Scenarios

### Valid Invoice Flow

```typescript
const invoice = InvoiceGenerator.generateValidInvoice();
const xml = XMLGenerator.generateUBL21XML(invoice);

const result = await mockValidation.validateFull(xml);
expect(result.valid).toBe(true); // ~80% chance

if (result.valid) {
  const submission = await mockFINA.submitInvoice({
    invoice,
    signature: '...',
    zki: '...',
    certificateId: '...'
  });
  expect(submission.success).toBe(true); // ~95% chance
  expect(submission.jir).toMatch(/^[A-Z0-9]{32}$/);
}
```

### Error Handling

```typescript
// Simulate failures
for (let i = 0; i < 100; i++) {
  const result = await mockFINA.submitInvoice(request);

  if (!result.success) {
    console.log(result.error);
    // {
    //   code: 'FINA_001',
    //   message: 'Invalid signature',
    //   details: 'Certificate validation failed'
    // }
  }
}
```

### Network Timeout Simulation

```typescript
// Mock takes 500-1500ms
const startTime = Date.now();
await mockFINA.submitInvoice(request);
const duration = Date.now() - startTime;

expect(duration).toBeGreaterThan(500);
expect(duration).toBeLessThan(1500);
```

## Contract Compliance

All mocks implement the same interfaces as real services:

```typescript
// Both MockFINAService and RealFINAService implement IFINAService
const finaContractTests = (service: IFINAService) => {
  it('should return JIR for valid invoice', async () => {
    const result = await service.submitInvoice(validRequest);
    expect(result.jir).toMatch(/^[A-Z0-9]{32}$/);
  });
};

// Run against both
finaContractTests(new MockFINAService());
finaContractTests(new RealFINAService());
```

## Limitations

1. **Not 100% Accurate** - Mocks approximate real behavior but may differ
2. **No Real Validation** - XML/data validation is simulated, not real
3. **No Network Errors** - Doesn't simulate connection failures, timeouts
4. **Fixed Success Rates** - Not configurable per instance

**Solution:** Use contract tests to ensure compatibility when switching to real services.

## Development

```bash
# Build
npm run build

# Watch mode
npm run watch

# Type checking
npm run typecheck
```

---

**Version:** 1.0.0
**Maintained by:** Team 1
**Dependencies:** @eracun/contracts, @eracun/adapters, inversify, reflect-metadata
