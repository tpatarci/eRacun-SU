# PENDING-005: Property-Based Testing Implementation

**Priority:** 🟢 P2 (Medium)
**Created:** 2025-11-12
**Estimated Effort:** 2 days
**Owner:** Backend Engineering Lead

---

## Problem Statement

CLAUDE.md §3.3 mandates property-based testing for validators and transformers using `fast-check`. Current archive-service test suite (to be implemented) lacks property-based tests, relying solely on example-based unit tests.

**Why This Matters:**
- Archive-service validates invoice payloads (schema, size limits, base64 encoding)
- Signature validation involves complex certificate chain verification
- Example-based tests may miss edge cases (malformed XML, invalid signatures, boundary conditions)
- Property-based testing generates thousands of random inputs to uncover unexpected failures

**Risk if not addressed:**
- Unhandled edge cases may cause production failures (invoice rejection, data corruption)
- Regulatory compliance risk (incorrectly validated invoices archived)

---

## Scope

### Services Requiring Property-Based Tests

1. **archive-service** (this service)
   - Payload validation (ArchiveInvoiceCommand schema)
   - SHA-512 hash computation
   - Base64 encoding/decoding
   - Invoice ID generation (UUIDv7 format)

2. **digital-signature-service** (dependency)
   - XMLDSig signature verification
   - Certificate chain validation
   - ZKI code generation (MD5 + RSA)

3. **ubl-transformer** (upstream producer)
   - UBL 2.1 XML schema validation
   - Croatian CIUS business rule validation
   - KPD classification code validation

---

## Open Questions Requiring Decisions

1. **Coverage target:** Should property-based tests count toward 100% coverage requirement or supplement it?
2. **Test duration:** How many random inputs per property (100, 1000, 10000)?
3. **Seed management:** Should we use fixed seeds for reproducible CI builds?
4. **Integration vs unit:** Should property-based tests run in integration or unit test suite?

---

## Deliverables Required to Close

### Phase 1: Library Setup (0.5 days)
- [ ] Install `fast-check` as devDependency in archive-service
- [ ] Configure Jest to run property-based tests (separate test suite or mixed?)
- [ ] Create example property-based test for simple validator (e.g., SHA-512 hash)

### Phase 2: archive-service Property Tests (1 day)
- [ ] Payload validation properties:
  - `∀ valid ArchiveInvoiceCommand: schema validation passes`
  - `∀ oversized payload (>100MB): validation rejects with 413`
  - `∀ malformed base64: decoding fails gracefully`
  - `∀ valid UUIDv7: invoice_id format validation passes`
- [ ] Hash computation properties:
  - `∀ XML input: SHA-512 hash is 128 hex chars`
  - `∀ identical XML: hash is deterministic`
  - `∀ different XML: hash collision probability negligible`
- [ ] Idempotency properties:
  - `∀ duplicate invoice_id: second archive attempt is idempotent (no duplication)`

### Phase 3: digital-signature-service Property Tests (0.5 days)
- [ ] Signature verification properties:
  - `∀ valid signed XML: verification succeeds with VALID status`
  - `∀ tampered XML: verification fails with INVALID status`
  - `∀ expired certificate: verification returns EXPIRED status`
- [ ] Certificate chain properties:
  - `∀ valid chain: verification traces to trusted root CA`
  - `∀ broken chain: verification fails with specific error`

### Phase 4: Documentation (0.5 days)
- [ ] Update `services/archive-service/README.md` with property-based testing examples
- [ ] Document property test patterns in `docs/testing/property-based-testing.md`
- [ ] Add property test guidelines to CLAUDE.md §3.3 (reference for future services)

---

## What It Blocks

- **Nothing immediately:** Property-based tests are quality enhancement, not blocking deployment
- **Long-term:** Improves confidence in validator correctness, reduces production bugs

---

## Why Deferred

**Reason:** Higher priority work (service skeleton, database migrations, runbooks) takes precedence. Property-based tests can be added incrementally after core functionality implemented.

**Higher Priority Work:**
- ADR-004 architecture design (completed)
- Service skeleton (completed)
- Database migrations (in progress)
- Performance benchmarking (PENDING-004, P1)

---

## Estimated Effort

**Total:** 2 days (1 backend engineer)

**Breakdown:**
- Phase 1 (setup): 0.5 days
- Phase 2 (archive-service): 1 day
- Phase 3 (digital-signature-service): 0.5 days
- Phase 4 (documentation): 0.5 days (overlap with Phase 2-3)

---

## Dependencies

- **fast-check library:** Install and configure
- **Archive-service implementation:** Core validation logic must exist before property tests can be written
- **Test fixtures:** Sample XMLDSig signatures for property test generators

---

## Success Criteria

✅ **Property-based testing complete when:**
1. `fast-check` integrated into archive-service test suite
2. Minimum 5 properties tested per validation function
3. Property tests run in CI/CD pipeline (jest + fast-check)
4. Documentation created for future service implementations
5. digital-signature-service enhanced with property tests (if capacity allows)

---

## References

- **CLAUDE.md §3.3:** "Property-Based Testing: For validators and transformers (use fast-check)"
- **Archive Service README §95:** Testing strategy (70% unit, 25% integration, 5% E2E)
- **fast-check documentation:** https://github.com/dubzzz/fast-check

---

## Example Property Test (Reference)

```typescript
import fc from 'fast-check';
import { validateInvoiceId } from './validators';

describe('Invoice ID Validation (Property-Based)', () => {
  it('should accept all valid UUIDv7 strings', () => {
    fc.assert(
      fc.property(fc.uuid(), (uuid) => {
        expect(validateInvoiceId(uuid)).toBe(true);
      })
    );
  });

  it('should reject all non-UUID strings', () => {
    fc.assert(
      fc.property(fc.string(), (str) => {
        fc.pre(!isValidUuid(str)); // Precondition: string is NOT a UUID
        expect(validateInvoiceId(str)).toBe(false);
      })
    );
  });

  it('should be deterministic', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const result1 = validateInvoiceId(input);
        const result2 = validateInvoiceId(input);
        expect(result1).toEqual(result2); // Same input = same output
      })
    );
  });
});
```

---

**Created:** 2025-11-12
**Target Resolution:** After M3 milestone (2025-12-20)
**Status:** Active
