# Property-Based Testing Guide

## Overview

Property-based testing is a testing approach where you define **properties** that should hold true for all inputs, and the test framework generates hundreds or thousands of random test cases to verify those properties.

Unlike example-based tests that check specific inputs ("Is 2 + 2 equal to 4?"), property-based tests verify general rules ("For any two numbers x and y, x + y should equal y + x").

## Why Property-Based Testing?

**Mission-Critical Systems:** This platform handles legally binding financial documents with zero error tolerance. Failures result in:
- €66,360 penalties for non-compliance
- Loss of VAT deduction rights
- 11-year audit liability
- Criminal prosecution for data destruction

**Benefits:**
- Catches edge cases example-based tests miss
- Tests hundreds of scenarios with minimal code
- Verifies correctness properties rather than specific outputs
- Finds boundary conditions and overflow issues
- Documents expected behavior as testable properties

## When to Use Property-Based Tests

✅ **Use for:**
- Validators (OIB, KPD, VAT, schema validation)
- Transformers (UBL conversion, XML generation)
- Hash calculations and cryptographic operations
- File parsers and data extractors
- Idempotency checks
- Serialization/deserialization
- Security-critical validation logic

❌ **Don't use for:**
- Integration tests with external systems
- UI interaction tests
- Tests requiring specific fixtures
- Performance benchmarking

## Fast-Check Library

We use [fast-check](https://github.com/dubzzz/fast-check) for property-based testing.

### Installation

```bash
npm install --save-dev fast-check
```

### Basic Structure

```typescript
import * as fc from 'fast-check';

describe('Property-Based Tests', () => {
  it('should verify property X for all inputs', () => {
    fc.assert(
      fc.property(
        fc.string(),        // Generator for random strings
        fc.integer(),       // Generator for random integers
        (str, num) => {
          // Test your property here
          const result = myFunction(str, num);
          expect(result).toBeSomething();
        }
      ),
      { numRuns: 100 }    // Run 100 random test cases
    );
  });
});
```

## Common Generators

```typescript
// Primitive types
fc.string()                    // Random strings
fc.integer()                   // Random integers
fc.float()                     // Random floats
fc.boolean()                   // Random booleans
fc.uint8Array()                // Random byte arrays

// Constrained generators
fc.string({ minLength: 1, maxLength: 255 })
fc.integer({ min: 0, max: 100 })
fc.array(fc.string(), { minLength: 1, maxLength: 10 })

// Custom generators
fc.constantFrom('pdf', 'xml', 'zip')  // Pick from specific values
fc.record({                            // Generate objects
  filename: fc.string(),
  size: fc.integer({ min: 0 })
})

// Derived generators
fc.string().filter(s => s.length > 0)  // Non-empty strings
fc.integer().map(n => n * 2)           // Even numbers
```

## Property Patterns

### 1. Determinism (Idempotency)

**Property:** Calling the same function with the same input should always produce the same output.

```typescript
it('should be deterministic', () => {
  fc.assert(
    fc.property(
      fc.string(),
      (input) => {
        const result1 = myFunction(input);
        const result2 = myFunction(input);
        expect(result1).toEqual(result2);
      }
    )
  );
});
```

### 2. Invariants

**Property:** Certain relationships must always hold.

```typescript
it('should maintain invariant: hash length is always 64 hex chars', () => {
  fc.assert(
    fc.property(
      fc.uint8Array(),
      (data) => {
        const hash = calculateSHA256(data);
        expect(hash).toMatch(/^[0-9a-f]{64}$/);
      }
    )
  );
});
```

### 3. Inverse Functions (Round-trip)

**Property:** Encode then decode should return original value.

```typescript
it('should round-trip correctly', () => {
  fc.assert(
    fc.property(
      fc.string(),
      (original) => {
        const encoded = base64Encode(original);
        const decoded = base64Decode(encoded);
        expect(decoded).toBe(original);
      }
    )
  );
});
```

### 4. Boundary Conditions

**Property:** Function should handle edge cases correctly.

```typescript
it('should reject oversized inputs', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 10 * 1024 * 1024 + 1, max: 100 * 1024 * 1024 }),
      async (size) => {
        const buffer = Buffer.alloc(size);
        await expect(validateFileSize(buffer)).rejects.toThrow();
      }
    )
  );
});
```

### 5. Commutativity

**Property:** Order of operations doesn't matter.

```typescript
it('should be commutative', () => {
  fc.assert(
    fc.property(
      fc.integer(), fc.integer(),
      (a, b) => {
        expect(add(a, b)).toBe(add(b, a));
      }
    )
  );
});
```

### 6. Consistency Across Variations

**Property:** Different valid inputs should produce consistent output format.

```typescript
it('should always return valid MIME type format', () => {
  fc.assert(
    fc.property(
      fc.uint8Array({ minLength: 10, maxLength: 1000 }),
      async (data) => {
        const result = detectMimeType(Buffer.from(data));
        expect(result).toMatch(/^[a-z]+\/[a-z0-9\-\+\.]+$/i);
      }
    )
  );
});
```

## Real-World Examples from eRačun

### File Size Validation (file-classifier)

```typescript
it('should accept any file within size limits', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 10 * 1024 * 1024 }), // Valid size range
      fc.string({ minLength: 1, maxLength: 255 }),   // Filename
      async (size, filename) => {
        const buffer = Buffer.alloc(size, 'a');
        const result = await detector.detectFileType(buffer, filename);

        // Should not fail due to size
        expect(result.size).toBe(size);
        expect(result.size).toBeGreaterThanOrEqual(1);
        expect(result.size).toBeLessThanOrEqual(10 * 1024 * 1024);
      }
    ),
    { numRuns: 100 }
  );
});
```

### Hash Consistency (attachment-handler)

```typescript
it('should calculate consistent SHA-256 hashes for file contents', () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 1, maxLength: 50 }),
      fc.uint8Array({ minLength: 10, maxLength: 5000 }),
      async (filename, content) => {
        const zip = new AdmZip();
        zip.addFile(filename, Buffer.from(content));
        const zipBuffer = zip.toBuffer();

        const result = await extractor.extract(zipBuffer, 'test.zip');

        expect(result.success).toBe(true);
        expect(result.files.length).toBe(1);

        // Calculate expected hash
        const expectedHash = crypto
          .createHash('sha256')
          .update(Buffer.from(content))
          .digest('hex');

        // Extracted file should have correct hash
        expect(result.files[0].hash).toBe(expectedHash);
      }
    ),
    { numRuns: 100 }
  );
});
```

### OIB Validation (Croatian Tax Number)

```typescript
it('should accept all valid 11-digit OIB numbers with correct check digit', () => {
  fc.assert(
    fc.property(
      fc.array(fc.integer({ min: 0, max: 9 }), { minLength: 10, maxLength: 10 }),
      (digits) => {
        // Calculate ISO 7064 check digit
        const checkDigit = calculateOIBCheckDigit(digits);
        const oib = [...digits, checkDigit].join('');

        // All properly formatted OIBs should pass validation
        expect(validateOIB(oib)).toBe(true);
      }
    ),
    { numRuns: 500 }
  );
});

it('should reject all invalid OIB numbers', () => {
  fc.assert(
    fc.property(
      fc.string().filter(s => !/^\d{11}$/.test(s) || !hasValidOIBCheckDigit(s)),
      (invalidOib) => {
        expect(validateOIB(invalidOib)).toBe(false);
      }
    ),
    { numRuns: 200 }
  );
});
```

## Configuration Options

### Number of Runs

```typescript
{ numRuns: 100 }    // Default: good for most tests
{ numRuns: 500 }    // High confidence: cryptographic operations
{ numRuns: 1000 }   // Very high confidence: security-critical validators
{ numRuns: 20 }     // Quick: expensive operations (nested archives)
```

### Timeout

```typescript
{ timeout: 5000 }   // 5 seconds for slow operations
```

### Seed for Reproducibility

```typescript
{ seed: 42 }        // Fixed seed for reproducible failures
```

### Preconditions (Filtering)

```typescript
fc.property(
  fc.string(),
  (str) => {
    fc.pre(str.length > 0);  // Only test non-empty strings
    // Test code here
  }
);
```

## Best Practices

### 1. Start with Simple Properties

Don't try to test everything at once. Start with basic properties:
- Determinism (same input = same output)
- Type safety (output is always correct type)
- No crashes (function doesn't throw for any input)

### 2. Use Preconditions Sparingly

Filtering too many inputs can make tests slow:

```typescript
// ❌ Bad: Discards most inputs
fc.property(
  fc.string(),
  (str) => {
    fc.pre(str.length === 11 && /^\d+$/.test(str));
    // ...
  }
);

// ✅ Good: Generate exactly what you need
fc.property(
  fc.array(fc.integer({ min: 0, max: 9 }), { minLength: 11, maxLength: 11 }),
  (digits) => {
    const oib = digits.join('');
    // ...
  }
);
```

### 3. Balance numRuns with Test Speed

- Fast operations (<1ms): 100-500 runs
- Medium operations (1-100ms): 50-100 runs
- Slow operations (>100ms): 10-20 runs

### 4. Document Properties Clearly

```typescript
// ✅ Good: Clear property description
it('should maintain hash consistency: same content = same hash', () => {
  fc.assert(/* ... */);
});

// ❌ Bad: Vague description
it('should work correctly', () => {
  fc.assert(/* ... */);
});
```

### 5. Combine with Example-Based Tests

Property-based tests complement example-based tests:
- Use example-based tests for specific known edge cases
- Use property-based tests for general correctness properties

## Debugging Failures

When a property test fails, fast-check provides a **minimal failing example**:

```
Property failed after 23 runs with seed 1234567890:
  - Input: ["invalid@@oib", 123]
  - Error: Expected true but got false
```

To reproduce the failure:

```typescript
fc.assert(
  fc.property(/* ... */),
  { seed: 1234567890 }  // Use the seed from failure output
);
```

## Integration with CI/CD

Property-based tests run in CI like any other Jest test:

```bash
npm test                  # Runs all tests including property tests
npm run test:coverage     # Coverage includes property tests
```

**CI Performance:** Property-based tests may be slower. Consider:
- Reducing `numRuns` in CI (50 instead of 500)
- Running full property tests nightly instead of on every commit
- Using test sharding for parallel execution

## References

- **fast-check Documentation:** https://github.com/dubzzz/fast-check
- **Property-Based Testing Book:** https://propertesting.com/
- **CLAUDE.md §3.3:** Property-Based Testing requirements
- **PENDING-005:** Property-Based Testing Implementation tracker

## Examples in Codebase

- `services/file-classifier/tests/unit/file-detector.property.test.ts`
- `services/attachment-handler/tests/unit/archive-extractor.property.test.ts`
- `shared/team2-mocks/tests/unit/invoice-generator.property.test.ts` (to be added)

---

**Created:** 2025-11-14
**Owner:** Engineering Team
**Status:** Living Document - Update as patterns emerge
