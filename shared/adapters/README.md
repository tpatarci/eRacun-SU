# @eracun/adapters

Service adapter interfaces and dependency injection contracts for eRačun.

## Purpose

This module provides abstract interfaces for all external dependencies, enabling:
- **Dependency Injection** with Inversify
- **Mock implementations** for independent development
- **Contract-based testing** to ensure compatibility
- **Easy service replacement** without changing business logic

## Installation

```bash
npm install @eracun/adapters
```

## Usage

```typescript
import { IValidationService, IFINAService, IOCRService } from '@eracun/adapters';

// Use in your service with dependency injection
class InvoiceProcessor {
  constructor(
    private validationService: IValidationService,
    private finaService: IFINAService
  ) {}

  async process(invoice: UBLInvoice) {
    const result = await this.validationService.validateFull(invoice.xml);
    if (result.valid) {
      await this.finaService.submitInvoice({
        invoice,
        signature: '...',
        zki: '...',
        certificateId: '...'
      });
    }
  }
}
```

## Adapter Interfaces

### Validation Adapters
- `IValidationService` - Full validation pipeline (all 6 layers)
- `IXSDValidatorService` - XSD schema validation
- `ISchematronValidatorService` - Schematron rules validation
- `IKPDValidatorService` - KPD code validation
- `IOIBValidatorService` - OIB format validation

### External Service Adapters
- `IFINAService` - FINA submission (B2C fiscalization)
- `IPoreznaService` - Porezna submission (B2B + reporting)
- `IOCRService` - OCR text extraction
- `IAIValidationService` - AI anomaly detection
- `IDigitalSignatureService` - XMLDSig signing
- `ICertificateService` - Certificate management
- `IStorageService` - Document storage
- `IArchiveService` - 11-year archival

## Mock Implementations

Mock implementations are provided in the `@eracun/mocks` package:

```typescript
import { MockFINAService, MockOCRService } from '@eracun/mocks';

// Use mocks for development
container.bind<IFINAService>(TYPES.FINAService).to(MockFINAService);
```

## Dependency Injection Pattern

```typescript
// Define dependency types
export const TYPES = {
  ValidationService: Symbol.for('IValidationService'),
  FINAService: Symbol.for('IFINAService'),
  OCRService: Symbol.for('IOCRService'),
  // ... more types
};

// Configure container with feature flags
import { Container } from 'inversify';
import { config } from './config';

const container = new Container();

if (config.featureFlags.useMockFINA) {
  container.bind<IFINAService>(TYPES.FINAService).to(MockFINAService);
} else {
  container.bind<IFINAService>(TYPES.FINAService).to(RealFINAService);
}
```

## Contract Testing

All adapter implementations (mock or real) must pass contract tests:

```typescript
import { finaContractTests } from '@eracun/contract-tests';

describe('MockFINAService Contract', () => {
  const service = new MockFINAService();
  finaContractTests(service);
});

describe('RealFINAService Contract', () => {
  const service = new RealFINAService();
  finaContractTests(service);
});
```

## Development

```bash
# Build
npm run build

# Type checking
npm run typecheck

# Watch mode
npm run watch
```

---

**Version:** 1.0.0
**Maintained by:** Team 1
**Dependencies:** @eracun/contracts
