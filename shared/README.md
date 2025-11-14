# Shared Modules

This directory contains shared libraries and utilities used across all eRačun services.

## Philosophy

**"Share code carefully."** - Premature abstraction creates coupling.

Code is only extracted to `shared/` after a pattern appears in **3+ services**. All shared libraries are versioned independently and support tree-shaking for optimal bundle sizes.

## Modules

### [@eracun/contracts](./contracts)
**Purpose:** Core domain models and message contracts
**Status:** ✅ Complete

Domain models, message formats, error codes, and feature flags used across all services.

```typescript
import { UBLInvoice, ValidationResult, ProcessInvoiceCommand } from '@eracun/contracts';
```

### [@eracun/adapters](./adapters)
**Purpose:** Service adapter interfaces
**Status:** ✅ Complete

Abstract interfaces for external dependencies, enabling dependency injection and mock implementations.

```typescript
import { IValidationService, IFINAService, IOCRService } from '@eracun/adapters';
```

### [@eracun/mocks](./mocks)
**Purpose:** Mock service implementations
**Status:** ✅ Complete

Realistic mock implementations with network delays, success/failure rates, and edge cases.

```typescript
import { MockFINAService, MockValidationService } from '@eracun/mocks';
```

### [@eracun/test-fixtures](./test-fixtures)
**Purpose:** Test data generators
**Status:** ✅ Complete

Generate valid and invalid invoices, XML documents, and OIB numbers for testing.

```typescript
import { InvoiceGenerator, XMLGenerator } from '@eracun/test-fixtures';
```

### [@eracun/di-container](./di-container)
**Purpose:** Dependency injection configuration
**Status:** ✅ Complete

Inversify container configuration with feature flag support for switching between mock and real services.

```typescript
import { createContainer, TYPES } from '@eracun/di-container';
```

### [@eracun/jest-config](./jest-config)
**Purpose:** Shared Jest configuration
**Status:** ⚠️ Existing (needs review)

Common Jest configuration for consistent testing across services.

## Usage Example

```typescript
// Service using dependency injection
import 'reflect-metadata';
import { injectable, inject } from 'inversify';
import { createContainer, TYPES } from '@eracun/di-container';
import { IValidationService, IFINAService } from '@eracun/adapters';
import { UBLInvoice } from '@eracun/contracts';

@injectable()
class InvoiceProcessor {
  constructor(
    @inject(TYPES.ValidationService) private validationService: IValidationService,
    @inject(TYPES.FINAService) private finaService: IFINAService
  ) {}

  async process(invoice: UBLInvoice): Promise<void> {
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

// Bootstrap
const container = createContainer();
container.bind<InvoiceProcessor>(InvoiceProcessor).toSelf();

const processor = container.get<InvoiceProcessor>(InvoiceProcessor);
await processor.process(invoice);
```

## Development Workflow

### Building All Modules

```bash
# From repository root
cd shared

# Build all modules in order
for dir in contracts adapters mocks test-fixtures di-container; do
  cd $dir
  npm install
  npm run build
  cd ..
done
```

### Testing with Mocks

```bash
# Set environment to use mocks
export ENVIRONMENT=development
export USE_MOCK_SERVICES=true

# Run your service
npm run dev
```

### Switching to Real Services

```bash
# Set environment to use real services
export ENVIRONMENT=production
export USE_MOCK_SERVICES=false

# Ensure real service implementations are available
# (will be added by Team 2 and Team 3)
```

## Guidelines for Adding New Shared Code

1. **Wait for 3+ Usage Pattern**
   - Don't extract code prematurely
   - Document pattern in service READMEs first
   - Discuss with team before extracting

2. **Measure Performance Impact**
   - Bundle size increase < 10KB
   - Runtime overhead < 1ms
   - Document in `PERFORMANCE.md`

3. **Version Independently**
   - Use semantic versioning
   - All services must support N-1 version
   - Breaking changes require major version bump

4. **Support Tree-Shaking**
   - Use named exports (not default exports)
   - No side effects in module initialization
   - Document tree-shaking compatibility

5. **Zero or Minimal Dependencies**
   - Avoid transitive dependencies
   - Use peer dependencies when possible
   - Document all dependencies in README

## Module Dependencies

```
contracts (no deps)
  ↓
adapters (depends on contracts)
  ↓
mocks (depends on contracts + adapters)
  ↓
test-fixtures (depends on contracts)
  ↓
di-container (depends on all above)
```

## CI/CD Integration

All shared modules are:
- ✅ Type-checked with strict TypeScript
- ✅ Linted with ESLint
- ✅ Built and published to local registry
- ✅ Versioned independently

## Team Responsibilities

- **Team 1 (Core Pipeline):** Maintains contracts, adapters, mocks, test-fixtures, di-container
- **Team 2 (Ingestion):** Contributes to test-fixtures, uses all modules
- **Team 3 (Integration):** Contributes to adapters (real implementations), uses all modules

## License

UNLICENSED - Internal use only

---

**Last Updated:** 2025-11-14
**Maintained By:** Team 1 Lead
**Review Cadence:** Weekly
