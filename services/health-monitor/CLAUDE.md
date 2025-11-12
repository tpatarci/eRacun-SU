# Service: health-monitor

## Purpose
System-wide health monitoring and alerting for all eRacun services.
Performs health checks, tracks service availability, and triggers alerts.

## Status
**Coverage:** 85% statements, 87% functions, 68% branches
**Tests:** Integration tests via health endpoints
**Implementation:** ✅ Complete

## Dependencies
- PostgreSQL: Health check history storage
- RabbitMQ: Service health status events
- Prometheus: Metrics collection
- All eRacun services: HTTP health endpoints

## Commands
```bash
npm run dev              # Start development server
npm test                 # Run all tests
npm run build            # Build service
npm run health:check     # Manual health check run
```

## Health Checks
- Service availability (HTTP GET /health endpoints)
- Database connectivity (PostgreSQL connection pool)
- Message queue status (RabbitMQ queue depths)
- Certificate expiration (via cert-lifecycle-manager)
- Disk space and memory usage

## Service Constraints
- Check interval: 60 seconds (configurable)
- Timeout: 5 seconds per service
- Alert thresholds: 3 consecutive failures triggers alert
- History retention: 30 days of health check results

## Key Features
- Multi-service health aggregation
- Configurable check intervals
- Alert escalation (P0/P1/P2 severity)
- Health check history and trends
- Prometheus metrics export

## Related Services
- Monitors: All eRacun services (20+ services)
- Publishes to: `notification-service` (alerts)
- Publishes to: `audit-logger` (health events)

## Configuration
- Services: `config/services.json` (service registry)
- Thresholds: `HEALTH_CHECK_INTERVAL`, `FAILURE_THRESHOLD`
- Alerts: `ALERT_ON_FAILURE`, `ALERT_CHANNELS`

---

See `README.md` for complete implementation details.
See `@docs/OPERATIONS.md` for monitoring configuration.
