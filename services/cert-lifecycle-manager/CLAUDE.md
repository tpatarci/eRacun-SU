# Service: cert-lifecycle-manager

## Purpose
Manages X.509 certificate lifecycle for FINA fiscalization integration.
Tracks expiration, alerts admins, and distributes certificates to signature services.

## Status
**Coverage:** 92.41% statements, 94.44% branches, 100% functions
**Tests:** 68 tests passing
**Implementation:** ✅ Complete

## Dependencies
- PostgreSQL: Certificate inventory storage
- RabbitMQ: Certificate update notifications
- node-forge: PKCS#12 certificate parsing
- FINA X.509 certificates: .p12 format with password

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests (68 tests)
npm run build            # Build service
npm run lint             # Run linter
```

## API Endpoints
- `POST /api/v1/certificates` - Upload new .p12 certificate
- `GET /api/v1/certificates` - List all certificates
- `GET /api/v1/certificates/:id` - Get certificate details
- `DELETE /api/v1/certificates/:id` - Revoke certificate

## Service Constraints
- Max certificate size: 1MB (.p12 files)
- Expiration check: Daily at 02:00 UTC
- Alert thresholds: 30 days (warning), 7 days (critical), 1 day (urgent)
- Retention: Revoked certificates kept for audit (11 years)

## Key Features
- Parse PKCS#12 certificates (node-forge)
- SHA-256 fingerprint calculation
- Certificate type detection (production/demo/test)
- Multi-level expiration alerts
- Automated certificate distribution

## Related Services
- Publishes to: `digital-signature-service` (certificate updates)
- Consumes from: `admin-portal-api` (certificate uploads)
- Alerts: `notification-service` (email/SMS for expiration)

## Compliance
- FINA certificates: 5-year validity (production), 1-year (demo)
- Encryption: SOPS + age for .p12 file storage
- Audit trail: All certificate operations logged

---

See `README.md` for complete implementation details.
See `@docs/COMPLIANCE_REQUIREMENTS.md` for FINA certificate requirements.
