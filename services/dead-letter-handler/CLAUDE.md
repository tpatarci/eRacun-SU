# Service: dead-letter-handler

## Purpose
Processes messages that failed after maximum retry attempts.
Provides manual review, reprocessing, and poisonous message quarantine.

## Status
**Coverage:** Infrastructure service (manual intervention required)
**Tests:** Integration tests for message handling
**Implementation:** ✅ Complete

## Dependencies
- PostgreSQL: Dead letter storage and audit trail
- RabbitMQ: Dead letter queue consumption
- Admin portal: Manual review and reprocessing UI

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests
npm run build            # Build service
npm run dlq:inspect      # Inspect dead letter queue
```

## Dead Letter Processing
- Automatic categorization (validation errors, timeouts, exceptions)
- Root cause analysis (pattern detection)
- Manual reprocessing workflow
- Poisonous message quarantine
- Alert on DLQ depth >10 messages

## Service Constraints
- Storage retention: 90 days (configurable)
- Reprocessing: Manual approval required
- Alert threshold: >10 messages in DLQ
- Quarantine: Automatic for repeated failures (>5x same error)

## Key Features
- Automatic error categorization
- Pattern detection for systemic issues
- Manual review and reprocessing
- Poisonous message identification
- Comprehensive audit trail

## Related Services
- Consumes from: `retry-scheduler` (exhausted retries)
- Consumes from: All services (direct DLQ messages)
- Publishes to: `audit-logger` (DLQ events)
- Publishes to: `notification-service` (DLQ depth alerts)

## Admin Actions
- Review message: View error details and payload
- Reprocess: Re-send to original queue
- Quarantine: Mark as poisonous (prevent reprocessing)
- Archive: Move to long-term storage

---

See `README.md` for complete implementation details.
See `@docs/OPERATIONS.md` for DLQ procedures.
