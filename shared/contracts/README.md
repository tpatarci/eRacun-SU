# @eracun/contracts

Shared contracts and interfaces for eRačun invoice processing platform.

## Purpose

This module contains all shared domain models, message contracts, and interfaces used across all eRačun services. It enables independent development while ensuring seamless integration.

## Installation

```bash
npm install @eracun/contracts
```

## Usage

```typescript
import {
  UBLInvoice,
  ValidationResult,
  ProcessInvoiceCommand,
  InvoiceValidatedEvent,
  ErrorCode,
  FeatureFlags
} from '@eracun/contracts';

// Use in your service
const invoice: UBLInvoice = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  invoiceNumber: 'INV-2025-001',
  // ... rest of invoice data
};
```

## Contracts Included

### Domain Models
- `UBLInvoice` - Core invoice structure (UBL 2.1 compliant)
- `Party` - Supplier/Buyer information
- `LineItem` - Invoice line items with KPD codes
- `VATBreakdown` - VAT calculations by rate

### Validation
- `ValidationResult` - 6-layer validation results
- `LayerResult` - Individual layer results
- `ValidationError` - Structured validation errors

### Message Bus
- **Commands** (RabbitMQ): ProcessInvoiceCommand, SubmitToFINACommand, RequestOCRCommand, SignDocumentCommand
- **Events** (Kafka): InvoiceReceivedEvent, InvoiceValidatedEvent, InvoiceTransformedEvent, InvoiceSubmittedEvent

### Error Handling
- `ErrorCode` - Standardized error codes (ERR_1001 - ERR_5999)
- `StandardError` - Error structure with retryability info

### Configuration
- `FeatureFlags` - Feature flag configuration for gradual rollout
- `defaultFeatureFlags` - Development defaults (mocks enabled)
- `productionFeatureFlags` - Production configuration

## Versioning

All contracts follow semantic versioning:
- **Major version** (2.0.0): Breaking changes
- **Minor version** (1.1.0): New optional fields
- **Patch version** (1.0.1): Bug fixes

All services must support N-1 version compatibility.

## Development

```bash
# Build
npm run build

# Type checking
npm run typecheck

# Watch mode
npm run watch

# Clean
npm run clean
```

## Team Integration

- **Team 1**: Uses all contracts for core pipeline
- **Team 2**: Uses ProcessInvoiceCommand, InvoiceReceivedEvent
- **Team 3**: Uses SubmitToFINACommand, InvoiceSubmittedEvent, certificate events

## Contract Changes

All contract changes require approval from all team leads. See `SHARED_CONTRACTS.md` for governance process.

---

**Version:** 1.0.0
**Maintained by:** All Teams
**Review Cadence:** Before each integration test
