# Health Monitor Service - Specification

**Service Name:** `health-monitor`
**Layer:** Infrastructure (Layer 9)
**Complexity:** Medium (~1,400 LOC)
**Status:** 🔴 Specification Only (Ready for Implementation)

---

## 1. Purpose and Single Responsibility

**Monitor system-wide health of all services, dependencies, and circuit breaker states.**

This service performs **active health checks** on all 40 bounded contexts and external dependencies (RabbitMQ, PostgreSQL, Kafka, FINA API, AS4 gateways). It:
- Polls health endpoints (`/health`, `/ready`) of all services
- Checks external dependency availability
- Tracks circuit breaker states
- Publishes health status to notification-service for alerting
- Provides centralized health dashboard data

---

## 2. Integration Architecture

### 2.1 Dependencies

**Consumes:**
- HTTP health endpoints from all 40 services (`GET /health`, `GET /ready`)
- RabbitMQ management API (queue depths, connection counts)
- PostgreSQL connection health
- Kafka broker health
- External API health (FINA, AS4, DZS)

**Produces:**
- Kafka events: `system-health` topic (health status changes)
- HTTP API: Health dashboard data for admin-portal
- Notifications: POST to notification-service for critical alerts

**No RabbitMQ queues** (pull-based HTTP polling, not message-driven)

### 2.2 Service Health Check Targets

**Layer 1 - Ingestion (4 services):**
- email-ingestion-worker:8080/health
- web-upload-handler:8081/health
- api-gateway:8082/health
- as4-gateway-receiver:8083/health

**Layer 2 - Parsing (4 services):**
- file-classifier:8084/health
- pdf-parser:8085/health
- ocr-processor:8086/health
- xml-parser:8087/health

**Layer 4 - Validation (8 services):**
- xsd-validator:8088/health
- schematron-validator:8089/health
- kpd-validator:8090/health
- ... (40 services total)

**External Dependencies:**
- RabbitMQ: http://rabbitmq:15672/api/healthchecks/node
- PostgreSQL: `SELECT 1` query
- Kafka: broker metadata request
- FINA API: https://cistest.apis-it.hr:8449/health (if available)

### 2.3 Health Check Response Schema

**Expected from each service:**

```json
{
  "status": "healthy" | "degraded" | "unhealthy",
  "checks": {
    "database": { "status": "healthy", "latency_ms": 5 },
    "message_queue": { "status": "healthy", "latency_ms": 3 },
    "circuit_breaker": { "status": "closed", "failure_rate": 0.01 }
  },
  "uptime_seconds": 86400,
  "version": "1.0.0"
}
```

---

## 3. Health Check Logic

### 3.1 Polling Strategy

**Frequency:**
- Critical services: Every 15 seconds
- Standard services: Every 30 seconds
- External APIs: Every 60 seconds (rate limit consideration)

**Timeout:**
- Health endpoint: 5 seconds
- Database query: 2 seconds
- Message queue check: 3 seconds

**Retry:**
- 3 failed checks → mark as UNHEALTHY
- 2 consecutive successful → mark as HEALTHY

### 3.2 Health Status Calculation

```typescript
enum HealthStatus {
  HEALTHY = 'healthy',       // All checks pass
  DEGRADED = 'degraded',     // Some checks fail, service operational
  UNHEALTHY = 'unhealthy'    // Critical checks fail, service down
}

function calculateServiceHealth(service: Service): HealthStatus {
  const checks = performHealthChecks(service);

  // Critical check failures → UNHEALTHY
  if (checks.database?.status === 'unhealthy' ||
      checks.message_queue?.status === 'unhealthy') {
    return HealthStatus.UNHEALTHY;
  }

  // Some checks fail → DEGRADED
  if (checks.circuit_breaker?.status === 'open' ||
      checks.external_api?.status === 'unhealthy') {
    return HealthStatus.DEGRADED;
  }

  // All checks pass → HEALTHY
  return HealthStatus.HEALTHY;
}
```

---

## 4. Circuit Breaker Monitoring

### 4.1 Circuit Breaker States

**Services expose circuit breaker state in health endpoint:**

```json
{
  "circuit_breakers": {
    "fina_api": {
      "state": "closed",        // closed, open, half-open
      "failure_rate": 0.05,     // 5% failures
      "last_state_change": 1699999999000,
      "consecutive_failures": 0
    }
  }
}
```

**Monitoring Logic:**
- CLOSED → All requests allowed
- OPEN → All requests blocked (service in failure mode)
- HALF_OPEN → Testing recovery (limited requests)

**Alert Triggers:**
- Circuit breaker opens → P1 alert (service degraded)
- Circuit breaker stays open > 5 minutes → P0 alert (extended outage)

---

## 5. Technology Stack

**Core:**
- Node.js 20+ / TypeScript 5.3+
- `axios` - HTTP client for health checks
- `pg` - PostgreSQL health checks
- `kafkajs` - Kafka health checks
- `amqplib` - RabbitMQ management API

**Observability:**
- `prom-client` - Prometheus metrics
- `pino` - Structured logging
- `express` - HTTP API for dashboard data

---

## 6. Performance Requirements

**Polling Overhead:**
- 40 services × 30 second intervals = 1.33 requests/second (negligible)
- Health check latency: <100ms per service

**Dashboard Response:**
- GET /health/dashboard → <500ms (aggregate all service health)

**Alerting Latency:**
- Health status change → notification sent within 10 seconds

---

## 7. Observability (TODO-008 Compliance)

**Required Metrics:**

```typescript
// Service health status
const serviceHealthStatus = new Gauge({
  name: 'service_health_status',
  help: 'Service health (1=healthy, 0.5=degraded, 0=unhealthy)',
  labelNames: ['service']
});

// Health check success rate
const healthCheckSuccess = new Counter({
  name: 'health_check_success_total',
  help: 'Successful health checks',
  labelNames: ['service']
});

// Health check failures
const healthCheckFailures = new Counter({
  name: 'health_check_failures_total',
  help: 'Failed health checks',
  labelNames: ['service', 'reason']
});

// Circuit breaker states
const circuitBreakerState = new Gauge({
  name: 'circuit_breaker_state',
  help: 'Circuit breaker state (0=closed, 1=open, 0.5=half-open)',
  labelNames: ['service', 'breaker']
});

// Health check latency
const healthCheckDuration = new Histogram({
  name: 'health_check_duration_seconds',
  help: 'Health check latency',
  labelNames: ['service'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 5]
});
```

---

## 8. HTTP API (for Admin Portal Dashboard)

```
GET /health/dashboard           # All services health status
GET /health/services/:name      # Specific service health details
GET /health/external            # External dependency health
GET /health/circuit-breakers    # All circuit breaker states
GET /health/history/:service    # Historical health (last 24h)
```

**Response Example (`GET /health/dashboard`):**

```json
{
  "system_health": "degraded",
  "healthy_services": 38,
  "degraded_services": 2,
  "unhealthy_services": 0,
  "services": [
    {
      "name": "xsd-validator",
      "status": "healthy",
      "last_check": "2025-11-11T12:00:00Z",
      "uptime_seconds": 86400
    },
    {
      "name": "fina-soap-connector",
      "status": "degraded",
      "reason": "Circuit breaker open for FINA API",
      "last_check": "2025-11-11T12:00:05Z"
    }
  ]
}
```

---

## 9. Failure Modes

**Scenario 1: Health Monitor Service Down**
- **Impact:** No centralized health monitoring, delayed incident detection
- **Detection:** health-monitor stops reporting to Prometheus
- **Recovery:** systemd auto-restart, alert sent via external monitoring

**Scenario 2: Many Services Unhealthy**
- **Impact:** System-wide outage
- **Detection:** `unhealthy_services` > 10
- **Recovery:** Page on-call (P0), incident response procedure

**Scenario 3: False Positive Health Check Failures**
- **Impact:** Unnecessary alerts
- **Mitigation:** 3 consecutive failures required before UNHEALTHY status

---

## 10. Deployment Configuration

```bash
# .env.example
SERVICE_NAME=health-monitor
HTTP_PORT=8084
PROMETHEUS_PORT=9092

# Health Check Configuration
HEALTH_CHECK_INTERVAL_MS=30000
HEALTH_CHECK_TIMEOUT_MS=5000
FAILURE_THRESHOLD=3

# Service Discovery
SERVICE_REGISTRY_URL=http://consul:8500  # Or static config file
STATIC_SERVICE_CONFIG=/etc/eracun/services.json

# Notification Service
NOTIFICATION_SERVICE_URL=http://notification-service:8080

# External Dependencies
RABBITMQ_MANAGEMENT_URL=http://rabbitmq:15672
DATABASE_URL=postgresql://health_user:password@localhost:5432/eracun
KAFKA_BROKERS=localhost:9092

# Observability
LOG_LEVEL=info
JAEGER_AGENT_HOST=localhost
```

---

## 11. Acceptance Criteria

- [ ] Polls all 40 service health endpoints
- [ ] Checks external dependency health (RabbitMQ, PostgreSQL, Kafka)
- [ ] Monitors circuit breaker states
- [ ] Publishes health events to Kafka
- [ ] Sends notifications for critical health changes
- [ ] HTTP API for dashboard data (6 endpoints)
- [ ] Test coverage 85%+
- [ ] 6+ Prometheus metrics

---

**Status:** 🔴 Specification Complete, Ready for Implementation
**Estimate:** 3-4 days | **Complexity:** Medium (~1,400 LOC)
**Dependencies:** None (can start immediately)

---

**Last Updated:** 2025-11-11
**Author:** System Architect
**Implementer:** [AI Instance TBD]
