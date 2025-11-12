# Service: audit-logger

## Purpose
Immutable audit trail for all eRacun operations.
Captures all system events for compliance, forensics, and regulatory reporting.

## Status
**Coverage:** Infrastructure service (append-only logging)
**Tests:** Integration tests for audit trail
**Implementation:** ✅ Complete

## Dependencies
- PostgreSQL: Audit log storage (append-only table)
- RabbitMQ: Audit event consumption from all services
- Cryptographic signing: HMAC-SHA256 for audit integrity

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests
npm run build            # Build service
npm run audit:verify     # Verify audit trail integrity
```

## Audit Events
- Certificate operations (upload, revoke, renewal)
- Invoice submissions and validations
- User authentication and authorization
- Configuration changes
- System errors and failures

## Service Constraints
- Storage retention: **11 years** (Croatian legal requirement)
- Immutability: Append-only, no updates or deletes
- Integrity: HMAC-SHA256 signatures on all entries
- Performance: <10ms write latency (p95)

## Key Features
- Immutable append-only logging
- Cryptographic integrity verification
- Structured event schema (who, what, when, where, why)
- Full-text search capabilities
- Long-term archival to cold storage

## Related Services
- Consumes from: All eRacun services (audit events)
- Used by: Compliance reporting tools
- Used by: Forensic analysis during incidents

## Compliance
- Retention: 11 years (Croatian Fiskalizacija 2.0)
- Integrity: Cryptographic signatures prevent tampering
- Access control: Read-only for auditors, no deletions

---

See `README.md` for complete implementation details.
See `@docs/COMPLIANCE_REQUIREMENTS.md` for audit requirements.
