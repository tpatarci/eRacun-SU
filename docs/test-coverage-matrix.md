# Test Coverage Matrix

**Total Test Files:** 24
**Last Updated:** 2025-02-19

## Overview

This document maps all features against their corresponding tests to provide a complete view of test coverage across the eRačun-SU application.

---

## Test Files by Category

| Category | Test Files | Count |
|----------|-----------|-------|
| **Compliance** | `croatian-fiskalizacija.test.ts` | 1 |
| **E2E** | `invoice-flow-mocked.test.ts`, `comprehensive-api.test.ts`, `multi-user-invoice-flow.test.ts` | 3 |
| **Integration** | `auth-flow.test.ts` | 1 |
| **Unit - API** | `schemas.test.ts`, `middleware.test.ts`, `app.test.ts` | 3 |
| **Unit - Archive** | `invoice-repository.test.ts` | 1 |
| **Unit - FINA** | `fina-client.test.ts`, `soap-envelope-builder.test.ts` | 2 |
| **Unit - Ingestion** | `email-poller.test.ts` | 1 |
| **Unit - Jobs** | `invoice-submission.test.ts`, `queue.test.ts` | 2 |
| **Unit - Repositories** | `user-config-repository.test.ts`, `user-repository.test.ts` | 2 |
| **Unit - Shared** | `config.test.ts`, `logger.test.ts`, `tenant-config.test.ts`, `types.test.ts` | 4 |
| **Unit - Signing** | `xmldsig-signer.test.ts`, `certificate-parser.test.ts`, `zki-generator.test.ts` | 3 |
| **Unit - Validation** | `oib-validator.test.ts` | 1 |

---

## Feature Coverage Matrix

### 1. Authentication & Authorization

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| User Login | `auth-flow.test.ts`, `comprehensive-api.test.ts`, `invoice-flow-mocked.test.ts` | Valid credentials, invalid email, invalid password, missing fields, invalid email format, session creation | ✅ Covered |
| User Logout | `auth-flow.test.ts`, `comprehensive-api.test.ts` | Successful logout, unauthenticated logout, session invalidation | ✅ Covered |
| Get Current User | `auth-flow.test.ts`, `comprehensive-api.test.ts` | Authenticated user info, unauthenticated rejection | ✅ Covered |
| Session Management | `auth-flow.test.ts` | Multiple requests, concurrent sessions, session persistence | ✅ Covered |
| Password Validation | `auth-flow.test.ts` | Minimum length, format requirements | ✅ Covered |
| Auth Middleware | `auth-flow.test.ts`, `comprehensive-api.test.ts` | Protected routes, session validation, unauthorized access | ✅ Covered |
| Session Token Generation | `auth-flow.test.ts` | Unique token generation, format validation | ✅ Covered |

### 2. Invoice Management

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| Invoice Submission | `invoice-flow-mocked.test.ts`, `comprehensive-api.test.ts`, `multi-user-invoice-flow.test.ts` | Valid invoice, all payment methods, VAT breakdown, concurrent submissions | ✅ Covered |
| Invoice Retrieval | `invoice-flow-mocked.test.ts`, `comprehensive-api.test.ts` | By ID, by status, non-existent invoices | ✅ Covered |
| Invoice List | `comprehensive-api.test.ts`, `multi-user-invoice-flow.test.ts` | User-specific filtering, pagination | ✅ Covered |
| Invoice Status Updates | `invoice-repository.test.ts` | Status transitions, JIR assignment | ✅ Covered |
| Invoice Creation | `invoice-repository.test.ts` | Parameterized queries, SQL injection safety | ✅ Covered |
| Multi-User Invoice Isolation | `multi-user-invoice-flow.test.ts`, `comprehensive-api.test.ts` | Cross-user access prevention, same invoice number for different users | ✅ Covered |

### 3. FINA Integration

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| SOAP Request Building | `soap-envelope-builder.test.ts` | RacuniRequest, ProveraRequest, EchoRequest, required fields, XML escaping | ✅ Covered |
| SOAP Response Parsing | `fina-client.test.ts` | Success response with JIR, error response, empty response | ✅ Covered |
| SOAP Fault Handling | `fina-client.test.ts` | Fault codes, network errors | ✅ Covered |
| FINA Client Initialization | `fina-client.test.ts` | Constructor, default timeout, uninitialized client error | ✅ Covered |
| Invoice XML Structure | `fina-client.test.ts`, `soap-envelope-builder.test.ts` | VAT breakdown, non-taxable items, other taxes | ✅ Covered |
| Network Error Handling | `fina-client.test.ts` | Timeouts, connection errors | ✅ Covered |

### 4. Digital Signature & Cryptography

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| XML Document Signing | `xmldsig-signer.test.ts` | ds:Signature element, required signature elements, parseable XML | ✅ Covered |
| UBL Invoice Signing | `xmldsig-signer.test.ts` | UBL namespace, non-UBL error handling | ✅ Covered |
| Detached Signatures | `xmldsig-signer.test.ts` | Signature without original content | ✅ Covered |
| Certificate Loading | `certificate-parser.test.ts` | PKCS#12 format, wrong passphrase, file errors | ✅ Covered |
| Certificate Parsing | `certificate-parser.test.ts` | Subject DN, issuer, serial number, validity period | ✅ Covered |
| Certificate Validation | `certificate-parser.test.ts` | Expired certificates, near-expiry warnings | ✅ Covered |
| ZKI Generation | `zki-generator.test.ts` | Hex format, determinism, parameter validation | ✅ Covered |
| ZKI Verification | `zki-generator.test.ts` | Valid ZKI, tampered ZKI detection | ✅ Covered |
| ZKI Formatting | `zki-generator.test.ts` | Dash formatting, edge cases | ✅ Covered |

### 5. OIB Validation

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| OIB Format Validation | `oib-validator.test.ts` | 11 digits, numeric only, first digit not zero | ✅ Covered |
| OIB Checksum Validation | `oib-validator.test.ts` | Valid checksum, invalid checksum, ISO 7064 MOD 11-10 | ✅ Covered |
| OIB Batch Validation | `oib-validator.test.ts` | Multiple OIBs, result mapping | ✅ Covered |
| OIB Generation | `oib-validator.test.ts` | Random generation, deterministic with prefix, zero dependencies | ✅ Covered |
| Edge Cases | `oib-validator.test.ts` | Empty string, null/undefined, whitespace trimming | ✅ Covered |

### 6. Configuration Management

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| FINA Configuration | `tenant-config.test.ts`, `user-config-repository.test.ts` | WSDL URL, cert path, passphrase validation | ✅ Covered |
| IMAP Configuration | `tenant-config.test.ts`, `user-config-repository.test.ts` | Host, port, user, password validation | ✅ Covered |
| Config CRUD | `user-config-repository.test.ts`, `comprehensive-api.test.ts` | Create, read, update, delete operations | ✅ Covered |
| Config Serialization | `user-config-repository.test.ts` | JSON encoding, nested objects | ✅ Covered |
| Multi-User Config Isolation | `comprehensive-api.test.ts`, `multi-user-invoice-flow.test.ts` | Cross-user access prevention | ✅ Covered |
| Environment Config | `config.test.ts` | Required fields, defaults, validation | ✅ Covered |

### 7. User Management

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| User Creation | `user-repository.test.ts` | With name, without name, parameterized queries | ✅ Covered |
| User Retrieval | `user-repository.test.ts`, `comprehensive-api.test.ts` | By ID, by email, non-existent users | ✅ Covered |
| User Updates | `user-repository.test.ts` | Email, password, name, multiple fields | ✅ Covered |
| SQL Injection Safety | `user-repository.test.ts`, `user-config-repository.test.ts`, `invoice-repository.test.ts` | Malicious input handling | ✅ Covered |

### 8. Job Queue & Background Processing

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| Queue Creation | `queue.test.ts` | Queue name, Redis URL parsing | ✅ Covered |
| Job Submission | `invoice-submission.test.ts`, `queue.test.ts` | Submit to queue, job ID generation | ✅ Covered |
| Job Processing | `queue.test.ts` | FINA submission, status updates, error handling | ✅ Covered |
| Service Lifecycle | `invoice-submission.test.ts` | Initialize, shutdown, double-init prevention | ✅ Covered |
| Job Counts | `invoice-submission.test.ts` | Active, waiting, completed, failed | ✅ Covered |
| Missing Config Handling | `queue.test.ts` | FINA config not found | ✅ Covered |

### 9. Email Ingestion

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| Poller Lifecycle | `email-poller.test.ts` | Start, stop, double-start prevention | ✅ Covered |
| Configuration | `email-poller.test.ts` | Host, port, credentials, mailbox | ✅ Covered |
| Message Processing | `email-poller.test.ts` | Message fetch, seen flagging | ✅ Covered |

### 10. API Validation & Middleware

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| Request Validation | `schemas.test.ts`, `middleware.test.ts` | OIB validation, payment method enum, amount format, datetime format | ✅ Covered |
| Invoice Schema | `schemas.test.ts` | All required fields, VAT breakdown, optional fields | ✅ Covered |
| Login Schema | `schemas.test.ts`, `auth-flow.test.ts` | Email format, password length | ✅ Covered |
| User Creation Schema | `schemas.test.ts`, `auth-flow.test.ts` | Email, password, optional name | ✅ Covered |
| Request ID Middleware | `app.test.ts`, `invoice-flow-mocked.test.ts` | UUID generation, custom request ID | ✅ Covered |
| Error Handler | `app.test.ts` | 500 errors, request ID in response | ✅ Covered |

### 11. Croatian Fiscalization Compliance

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| UBL 2.1 Format | `croatian-fiskalizacija.test.ts` | Namespace, version, customization ID, invoice type code | ✅ Covered |
| EN 16931 Semantic Model | `croatian-fiskalizacija.test.ts` | Mandatory BT fields, currency code | ✅ Covered |
| Croatian CIUS Extensions | `croatian-fiskalizacija.test.ts` | HR-BT-* fields, operator OIB | ✅ Covered |
| OIB in Invoices | `croatian-fiskalizacija.test.ts` | Format, scheme ID, issuer/recipient validation | ✅ Covered |
| KPD Classification | `croatian-fiskalizacija.test.ts` | KLASUS 2025 codes, format validation, list ID | ✅ Covered |
| VAT Breakdown | `croatian-fiskalizacija.test.ts` | Valid rates (25%, 13%, 5%, 0%), category codes, scheme ID | ✅ Covered |
| XMLDSig Signature | `croatian-fiskalizacija.test.ts` | RSA-SHA256, signature value, cryptographic validation | ✅ Covered |
| X.509 Certificate | `croatian-fiskalizacija.test.ts` | FINA issuer, validity period | ✅ Covered |
| Qualified Timestamp | `croatian-fiskalizacija.test.ts` | B2B invoices, eIDAS-compliant TSA, time drift | ✅ Covered |
| 11-Year Retention | `croatian-fiskalizacija.test.ts` | Original XML preservation, signature validity, metadata | ✅ Covered |
| WORM Storage | `croatian-fiskalizacija.test.ts` | Modification prevention, checksum verification, access logging | ✅ Covered |
| JIR/UUID Confirmation | `croatian-fiskalizacija.test.ts` | B2C JIR format, B2B UUID format | ✅ Covered |
| Monthly Signature Validation | `croatian-fiskalizacija.test.ts` | Tamper detection, validation logging | ✅ Covered |
| Compliance Reporting | `croatian-fiskalizacija.test.ts` | Monthly reports, non-compliant invoice identification | ✅ Covered |

### 12. Security & Data Privacy

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| SQL Injection Prevention | `user-repository.test.ts`, `user-config-repository.test.ts`, `invoice-repository.test.ts` | Parameterized queries, malicious input handling | ✅ Covered |
| Multi-User Data Isolation | `multi-user-invoice-flow.test.ts`, `comprehensive-api.test.ts` | Cross-user invoice access, cross-user config access | ✅ Covered |
| Authentication Required | `comprehensive-api.test.ts` | User enumeration prevention, protected endpoints | ✅ Covered |
| XML Special Characters | `soap-envelope-builder.test.ts` | Escaping XSS attempts | ✅ Covered |
| Certificate Expiry | `certificate-parser.test.ts` | Expired cert rejection, near-expiry warnings | ✅ Covered |
| ZKI Tamper Detection | `zki-generator.test.ts` | Modified ZKI rejection | ✅ Covered |

### 13. Logging & Observability

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| Structured Logging | `logger.test.ts` | JSON output, message, level, custom fields | ✅ Covered |
| Request Tracing | `app.test.ts`, `invoice-flow-mocked.test.ts` | X-Request-ID header | ✅ Covered |

### 14. Type Safety

| Feature | Test File | Test Cases | Status |
|---------|-----------|-----------|--------|
| FINA Types | `types.test.ts` | FINAInvoice, VAT breakdown, non-taxable, other taxes, request/response | ✅ Covered |
| Domain Types | `types.test.ts` | Invoice, ArchiveRecord, JobPayload | ✅ Covered |
| Payment Method Enum | `schemas.test.ts` | G, K, C, T, O validation | ✅ Covered |

---

## Test Execution Summary

### Quick Test Commands

```bash
# Run all tests
npm test

# Run specific test category
npm test -- tests/compliance/
npm test -- tests/unit/
npm test -- tests/integration/
npm test -- tests/e2e/

# Run with coverage
npm test -- --coverage

# Run specific test file
npm test -- tests/unit/oib-validator.test.ts
```

### Expected Test Count: 24

✅ All 24 test files are present and accounted for.

---

## Coverage Gaps

### Potentially Missing Areas

Based on the analysis, the following areas may need additional coverage:

1. **Error Recovery Scenarios**
   - Database connection failure recovery
   - Redis connection failure handling
   - FINA service timeout retry logic

2. **Performance Testing**
   - Load testing for concurrent invoice submissions
   - Database query performance under load
   - Memory usage monitoring

3. **Edge Cases**
   - Extremely large XML documents
   - Concurrent modifications to same invoice
   - Certificate chain validation (intermediate certificates)

4. **Integration Testing**
   - Real FINA service integration (currently mocked)
   - Real email server integration (currently mocked)
   - Database migration testing

5. **Security Testing**
   - Brute force password attack prevention
   - Session hijacking prevention
   - CSRF token validation (if applicable)

---

## Test Maintenance Notes

### Test File Locations

- **Compliance Tests:** `tests/compliance/`
- **E2E Tests:** `tests/e2e/`
- **Integration Tests:** `tests/integration/`
- **Unit Tests:** `tests/unit/` (organized by module)

### Test Naming Conventions

- Test files: `*.test.ts`
- Test descriptions: Clear, descriptive strings starting with "should"
- Test categories: Logical grouping using `describe` blocks

### Mock Usage

All unit tests use Jest mocks for:
- Database queries (`src/shared/db`)
- Logger (`src/shared/logger`)
- External dependencies (bcrypt, imapflow, bullmq, uuid)

---

## Compliance Test References

The `croatian-fiskalizacija.test.ts` file specifically validates:

- **UBL 2.1 Invoice Format** (EN 16931)
- **Croatian CIUS Extensions**
- **FINA Fiscalization Requirements**
- **XMLDSig Signature Standards**
- **11-Year Retention Compliance**
- **WORM Storage Requirements**

This test suite is critical for legal compliance with Croatian Fiscalization Law (NN 89/25).
