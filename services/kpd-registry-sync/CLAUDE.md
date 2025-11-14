# Service: kpd-registry-sync

## Purpose
Synchronizes KLASUS 2025 product classification codes (KPD) from official Croatian registry.
Maintains up-to-date product taxonomy for invoice validation.

## Status
**Coverage:** Synchronization service (scheduled daily)
**Tests:** Integration tests with mock registry
**Implementation:** ✅ Complete

## Dependencies
- PostgreSQL: KPD code storage (6-digit codes)
- Croatian Tax Authority: KPD registry API (official source)
- RabbitMQ: KPD update notifications

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests
npm run build            # Build service
npm run sync:now         # Manual sync trigger
```

## Synchronization
- Frequency: Daily at 03:00 UTC
- Source: Croatian Tax Authority KPD registry
- Update detection: Hash-based change detection
- Incremental sync: Only changed codes downloaded

## Service Constraints
- Sync window: 03:00-04:00 UTC
- Timeout: 30 minutes (full sync)
- Retry: 3 attempts with exponential backoff
- Fallback: Continue with last known good dataset

## Key Features
- Automated daily synchronization
- Incremental updates (hash-based)
- Version tracking (historical codes)
- Validation cache warming
- Sync status monitoring

## Related Services
- Updates: `validation` service (KPD code cache)
- Publishes to: `audit-logger` (sync events)
- Publishes to: `notification-service` (sync failures)

## Data Format
- 6-digit codes: KLASUS 2025 taxonomy
- Hierarchical structure: 2-digit sections → 6-digit codes
- Descriptions: Croatian language (primary)

---

See `README.md` for complete implementation details.
See `@docs/COMPLIANCE_REQUIREMENTS.md` for KPD requirements.
