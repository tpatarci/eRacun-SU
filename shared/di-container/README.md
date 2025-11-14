# @eracun/di-container

Dependency injection container configuration for eRačun services.

## Purpose

This module provides centralized dependency injection configuration using Inversify, with feature flag support for switching between mock and real service implementations.

## Installation

```bash
npm install @eracun/di-container
```

## Usage

### Basic Setup

```typescript
import 'reflect-metadata';
import { createContainer, TYPES } from '@eracun/di-container';
import { IValidationService, IFINAService } from '@eracun/adapters';

// Create container
const container = createContainer();

// Get services
const validationService = container.get<IValidationService>(TYPES.ValidationService);
const finaService = container.get<IFINAService>(TYPES.FINAService);

// Use services
const result = await validationService.validateFull(xml);
await finaService.submitInvoice(request);
```

### Service Class with Dependency Injection

```typescript
import { injectable, inject } from 'inversify';
import { TYPES } from '@eracun/di-container';
import { IValidationService, IFINAService } from '@eracun/adapters';

@injectable()
export class InvoiceProcessor {
  constructor(
    @inject(TYPES.ValidationService) private validationService: IValidationService,
    @inject(TYPES.FINAService) private finaService: IFINAService
  ) {}

  async process(invoice: UBLInvoice): Promise<void> {
    const validationResult = await this.validationService.validateFull(invoice.xml);

    if (validationResult.valid) {
      await this.finaService.submitInvoice({
        invoice,
        signature: '...',
        zki: '...',
        certificateId: '...'
      });
    }
  }
}

// Register in container
container.bind<InvoiceProcessor>(InvoiceProcessor).toSelf();

// Use
const processor = container.get<InvoiceProcessor>(InvoiceProcessor);
await processor.process(invoice);
```

### Configuration

Configuration is loaded from environment variables:

```bash
# Environment
ENVIRONMENT=development   # development, staging, production

# Message Bus
RABBITMQ_URL=amqp://localhost:5672
KAFKA_BROKERS=localhost:9092

# Database
DATABASE_URL=postgresql://localhost:5432/eracun

# Redis
REDIS_URL=redis://localhost:6379

# Feature Flags (overrides)
USE_MOCK_FINA=true
USE_MOCK_OCR=true
```

### Feature Flags

Feature flags control which implementations are used:

```typescript
import { loadConfig } from '@eracun/di-container';

const config = loadConfig();

console.log(config.featureFlags);
// {
//   useMockFINA: true,
//   useMockPorezna: true,
//   useMockOCR: true,
//   useMockAI: true,
//   enableAIValidation: true,
//   parallelValidation: true,
//   ...
// }
```

**Development:** All mocks enabled by default
**Production:** All mocks disabled, real services used

### Available Service Types

```typescript
import { TYPES } from '@eracun/di-container';

// Validation services
TYPES.ValidationService
TYPES.XSDValidatorService
TYPES.SchematronValidatorService
TYPES.KPDValidatorService
TYPES.OIBValidatorService

// External services
TYPES.FINAService
TYPES.PoreznaService
TYPES.OCRService
TYPES.AIValidationService
TYPES.DigitalSignatureService
TYPES.CertificateService
TYPES.StorageService
TYPES.ArchiveService

// Configuration
TYPES.Config
TYPES.FeatureFlags
```

## Adding New Services

1. Define interface in `@eracun/adapters`
2. Create mock implementation in `@eracun/mocks`
3. Add type symbol to `src/types.ts`
4. Configure binding in `src/container.ts`

```typescript
// 1. Add to types.ts
export const TYPES = {
  // ...
  MyNewService: Symbol.for('IMyNewService'),
};

// 2. Configure in container.ts
function configureExternalServices(container: Container, config: Config): void {
  if (config.featureFlags.useMockMyService) {
    container.bind<IMyNewService>(TYPES.MyNewService).to(MockMyService);
  } else {
    container.bind<IMyNewService>(TYPES.MyNewService).to(RealMyService);
  }
}
```

## Testing

```typescript
import { Container } from 'inversify';
import { TYPES } from '@eracun/di-container';
import { MockValidationService } from '@eracun/mocks';

describe('InvoiceProcessor', () => {
  let container: Container;

  beforeEach(() => {
    container = new Container();
    container.bind(TYPES.ValidationService).to(MockValidationService);
    container.bind(InvoiceProcessor).toSelf();
  });

  it('should process valid invoice', async () => {
    const processor = container.get<InvoiceProcessor>(InvoiceProcessor);
    await processor.process(validInvoice);
    // assertions...
  });
});
```

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
**Dependencies:** inversify, reflect-metadata, @eracun/contracts, @eracun/adapters, @eracun/mocks
