# validation-coordinator

**Orchestrate 6-layer validation pipeline with consensus mechanism for invoice compliance.**

## Purpose

The Validation Coordinator orchestrates a comprehensive 6-layer validation pipeline to ensure invoice compliance with UBL 2.1, Croatian CIUS, and regulatory requirements. Uses consensus mechanism (majority voting) for final decision.

## 6 Validation Layers

### Layer 1: XSD Schema Validation
- Validates against UBL 2.1 XSD schema
- Ensures structural correctness
- Fast fail for malformed XML

### Layer 2: Schematron Validation
- Croatian CIUS business rules
- EN 16931 compliance checks
- Context-specific validations

### Layer 3: KPD Code Validation
- Validates against KLASUS 2025 registry
- 6-digit code format check
- Product/service classification verification

### Layer 4: Semantic Validation
- VAT calculations
- Line item totals
- OIB format validation
- Cross-field consistency

### Layer 5: AI Validation (Optional)
- Anomaly detection
- Historical pattern matching
- Outlier identification
- Cross-reference validation

### Layer 6: Consensus Mechanism
- Majority voting (default: 3/5 votes required)
- Configurable threshold
- Final approval/rejection decision

## Features

- ✅ **Parallel Validation** - Layers 1-4 run concurrently
- ✅ **Consensus Voting** - Democratic decision-making
- ✅ **Error Aggregation** - Deduplicates and prioritizes errors
- ✅ **Performance Metrics** - Tracks execution time per layer
- ✅ **Configurable** - Enable/disable individual layers

## Usage

```typescript
import { ValidationCoordinator } from './coordinators/validation-coordinator';

const coordinator = container.get<ValidationCoordinator>(ValidationCoordinator);

// Run full validation
const result = await coordinator.validate(xml, invoiceId, {
  enableParallelValidation: true,
  enableAIValidation: true,
  consensusThreshold: 3,
});

console.log('Valid:', result.valid);
console.log('Confidence:', result.confidence);
console.log('Errors:', result.errors);
console.log('Layer Results:', result.layers);
```

## Validation Result

```typescript
{
  invoiceId: "123e4567...",
  timestamp: "2025-11-14T10:30:00Z",
  valid: true,
  confidence: 0.83,  // 5/6 layers passed
  layers: {
    xsd: { passed: true, executionTime: 50 },
    schematron: { passed: true, executionTime: 120 },
    kpd: { passed: true, executionTime: 30 },
    semantic: { passed: true, executionTime: 80 },
    ai: { passed: true, executionTime: 300 },
    consensus: { passed: true, votes: 5, threshold: 3 }
  },
  errors: [],
  warnings: [],
  suggestions: []
}
```

## Consensus Algorithm

**Majority Voting:**
- Each layer votes (pass/fail)
- Minimum threshold required (default: 3 votes)
- Configurable per validation request
- Ties resolved by XSD validation (mandatory)

**Example:**
- XSD: ✅ Pass
- Schematron: ✅ Pass
- KPD: ❌ Fail
- Semantic: ✅ Pass
- AI: ✅ Pass
- **Result:** 4/5 passed → ✅ APPROVED (threshold: 3)

## Performance

- **Target:** <5s (p99) for full pipeline
- **Parallel execution:** Layers 1-4 run concurrently
- **Sequential execution:** Option for debugging
- **Metrics collection:** Per-layer timing

## Error Aggregation

- **Deduplication** - Removes duplicate errors by code + field
- **Severity Sorting** - CRITICAL → HIGH → MEDIUM
- **Layer Attribution** - Shows which layer detected error
- **Suggestions** - Provides correction guidance

## Architecture

**Bounded Context:** Validation Orchestration
**Priority:** P1 - Critical for compliance
**Service Limit:** 2,500 LOC

### Components

- **ValidationCoordinator** - Main orchestration logic
- **ErrorAggregator** - Error deduplication and prioritization
- **Consensus Engine** - Majority voting mechanism

## Dependencies

- **Validation Services** - XSD, Schematron, KPD, Semantic, AI validators
- **Upstream:** ubl-transformer (provides XML to validate)
- **Downstream:** invoice-orchestrator (receives validation results)

---

**Version:** 1.0.0
**Status:** ✅ Week 2 Day 10 Implementation Complete
**Maintained by:** Team 1
