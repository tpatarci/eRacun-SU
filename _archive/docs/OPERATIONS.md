# Operations Guide

## Observability - The Three Pillars

### Metrics (Prometheus + Grafana)
- Request latency (p50, p95, p99)
- Error rates by service
- Queue depths (RabbitMQ/Kafka)
- Database connection pool utilization

### Logs (Loki)
- Structured JSON logs
- Request ID correlation
- Error context preservation

### Traces (Jaeger)
- End-to-end request flow
- Performance bottleneck identification
- Cross-service dependency visualization

---

## Alerting

### On-Call Severity Levels
- **P0 (Page immediately):** Service down, data loss risk
- **P1 (Page in 15min):** Degraded performance, SLA breach risk
- **P2 (Ticket next day):** Non-critical errors, capacity warnings

### Alert Principles
- Every alert must be actionable
- No noisy alerts (max 1 false positive per week)
- Runbooks linked in alert descriptions

---

## Disaster Recovery

### Backup Strategy
**RTO (Recovery Time Objective):** 1 hour
**RPO (Recovery Point Objective):** 5 minutes

**Backup Scope:**
- Database: Continuous WAL archiving + daily snapshots
- Object storage: Cross-region replication
- Configuration: Git-versioned IaC

### Incident Response
**Runbook Requirements:**
- Every service has failure mode documentation
- Recovery procedures tested quarterly
- Incident commander rotation schedule

---

**Last Updated:** 2025-11-12
