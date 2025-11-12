# Service: retry-scheduler

## Purpose
Intelligent retry scheduling for failed operations with exponential backoff.
Manages transient failure recovery across all eRacun services.

## Status
**Coverage:** 93.82% statements, 100% functions
**Tests:** Integration tests for retry logic
**Implementation:** ✅ Complete

## Dependencies
- PostgreSQL: Retry queue and attempt history
- RabbitMQ: Failed message consumption and republishing
- Redis: Distributed locks for retry coordination

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests
npm run build            # Build service
npm run retry:process    # Manual retry processing
```

## Retry Strategies
- Exponential backoff: `delay = base * (2^attempt) + jitter`
- Max retry limits: 3 attempts (default), configurable per operation
- Backoff base: 1 second (configurable)
- Jitter: 0-1000ms random to prevent thundering herd

## Service Constraints
- Max retry attempts: 3 (configurable)
- Max backoff delay: 5 minutes
- Dead letter queue: After max retries exhausted
- Retry window: 24 hours (operations expire after)

## Key Features
- Exponential backoff with jitter
- Per-operation retry policies
- Dead letter queue management
- Retry attempt tracking and metrics
- Automatic cleanup of expired retries

## Related Services
- Consumes from: All services (failed operations)
- Republishes to: Originating service queues
- Publishes to: `dead-letter-handler` (exhausted retries)
- Publishes to: `audit-logger` (retry events)

## Configuration
- Policies: `config/retry-policies.json` (per-operation config)
- Defaults: `MAX_RETRIES=3`, `BASE_DELAY=1000`, `MAX_DELAY=300000`

---

See `README.md` for complete implementation details.
See `@docs/ARCHITECTURE.md` for retry patterns.
