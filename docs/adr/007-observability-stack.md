# ADR-007: Observability Stack (OpenTelemetry + Prometheus)

**Status:** ✅ Accepted

**Date:** 2025-11-14

**Context:** Team 1 - Core Processing Pipeline

---

## Context and Problem Statement

The eRačun platform requires comprehensive observability to:
1. **Debug production issues** - Trace requests across microservices
2. **Monitor performance** - Track SLAs (p95 < 200ms for invoice submission)
3. **Alert on failures** - Detect issues before users report them
4. **Ensure compliance** - Audit all invoice processing operations

We need to implement the **three pillars of observability:**
- **Metrics** - Quantitative measurements (request rate, error rate, latency)
- **Logs** - Discrete events with timestamps
- **Traces** - Request flow across distributed services

We evaluated several observability solutions:
- OpenTelemetry + Prometheus + Loki + Jaeger
- Datadog (SaaS)
- New Relic (SaaS)
- Elastic APM
- Application Insights (Azure)

## Decision

**We will use OpenTelemetry for tracing, Prometheus for metrics, Pino for logging, and Jaeger for trace visualization.**

### Architecture

```
┌─────────────────────────────────────────┐
│          Services (4 services)          │
│  - invoice-gateway-api                  │
│  - invoice-orchestrator                 │
│  - ubl-transformer                      │
│  - validation-coordinator               │
└────────┬────────────┬────────────┬──────┘
         │            │            │
    ┌────▼────┐  ┌───▼───┐   ┌───▼────┐
    │  Pino   │  │ Prom  │   │OpenTel │
    │  Logs   │  │Metrics│   │ Traces │
    └────┬────┘  └───┬───┘   └───┬────┘
         │           │            │
    ┌────▼────┐  ┌───▼───┐   ┌───▼────┐
    │  Loki   │  │Grafana│   │ Jaeger │
    │(Agg Log)│  │(Dash) │   │(TraceUI)│
    └─────────┘  └───────┘   └────────┘
```

## Rationale

### OpenTelemetry for Tracing

**Why OpenTelemetry:**
- **Vendor-neutral** - Not locked into proprietary formats
- **Auto-instrumentation** - Automatic HTTP/Express/Database tracing
- **W3C Standard** - Industry-standard trace context propagation
- **Active ecosystem** - Growing library of integrations

**Implementation:**
```typescript
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';

const sdk = new NodeSDK({
  resource,
  spanProcessor: new BatchSpanProcessor(traceExporter),
  instrumentations: [getNodeAutoInstrumentations()],
});

await sdk.start();
```

**Features:**
- Automatic HTTP request tracing
- Express route instrumentation
- PostgreSQL query tracing
- Custom span creation for business logic
- Context propagation across RabbitMQ/Kafka

**Benefits:**
- **End-to-end visibility:** See full request flow from gateway → orchestrator → transformer → validator
- **Performance profiling:** Identify slow database queries or external API calls
- **Error attribution:** Pinpoint exact service/line causing failures

### Prometheus for Metrics

**Why Prometheus:**
- **Pull-based model** - Services expose `/metrics`, Prometheus scrapes
- **Powerful querying** - PromQL for aggregations and alerts
- **Time-series database** - Efficient storage for metrics
- **Battle-tested** - Used by Netflix, SoundCloud, Uber

**Implementation:**
```typescript
import { Registry, Counter, Histogram } from 'prom-client';

export const httpRequestDuration = new Histogram({
  name: 'invoice_gateway_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5],
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

**Custom Metrics by Service:**
- **invoice-gateway-api:** Request rate, idempotent requests, rate limits
- **invoice-orchestrator:** Saga duration, state transitions, compensations
- **ubl-transformer:** Transformation duration, format detections, CIUS elements
- **validation-coordinator:** Pipeline duration, layer results, confidence scores

**Benefits:**
- **SLA monitoring:** Alert if p95 > 200ms
- **Capacity planning:** Track resource utilization trends
- **Anomaly detection:** Spot unusual patterns (sudden error spike)

### Pino for Structured Logging

**Why Pino:**
- **Fastest JSON logger** - Low overhead (~10x faster than Winston)
- **Structured output** - JSON format for machine parsing
- **Request ID propagation** - Correlation across services
- **Automatic fields** - Timestamp, level, hostname

**Implementation:**
```typescript
import pino from 'pino';

const logger = pino({
  name: 'invoice-gateway-api',
  level: process.env.LOG_LEVEL || 'info',
});

logger.info({ invoiceId, requestId }, 'Invoice submission received');
```

**Log Format:**
```json
{
  "level": "info",
  "time": "2025-11-14T12:34:56.789Z",
  "msg": "Invoice submission received",
  "invoiceId": "550e8400-e29b-41d4-a716-446655440000",
  "requestId": "req_abc123",
  "hostname": "eracun-api-01",
  "pid": 1234
}
```

**Benefits:**
- **Fast parsing:** Loki can index JSON fields
- **Correlation:** Link logs to traces via request ID
- **Debugging:** Structured data easier to search/filter

### Jaeger for Trace Visualization

**Why Jaeger:**
- **Open source** - No vendor lock-in
- **OpenTelemetry compatible** - Native OTLP support
- **Service dependency graph** - Visual service map
- **Detailed timeline view** - See exact timing of each operation

**Benefits:**
- **Root cause analysis:** Drill down to exact slow query
- **Service dependencies:** Understand service call patterns
- **Performance optimization:** Identify bottlenecks visually

## Implementation Details

### Service Instrumentation

**All 4 services include:**
```typescript
// services/*/src/tracing.ts
import { startTracing, stopTracing } from './tracing';

async function start() {
  await startTracing(); // MUST be before other imports
  // ... rest of service startup
}
```

**Automatic instrumentation covers:**
- HTTP requests (client and server)
- Express route handling
- PostgreSQL queries
- RabbitMQ message sending/receiving
- Kafka event publishing

**Custom spans for business logic:**
```typescript
import { trace } from '@opentelemetry/api';

const tracer = trace.getTracer('invoice-orchestrator');
const span = tracer.startSpan('execute-saga-step');

try {
  await executeSagaStep();
  span.setStatus({ code: SpanStatusCode.OK });
} catch (error) {
  span.recordException(error);
  span.setStatus({ code: SpanStatusCode.ERROR });
} finally {
  span.end();
}
```

### Prometheus Metrics

**Metrics endpoints:**
- invoice-gateway-api: `http://localhost:3000/metrics`
- invoice-orchestrator: `http://localhost:9101/metrics`
- ubl-transformer: `http://localhost:9102/metrics`
- validation-coordinator: `http://localhost:9103/metrics`

**Scrape configuration (prometheus.yml):**
```yaml
scrape_configs:
  - job_name: 'eracun-services'
    scrape_interval: 15s
    static_configs:
      - targets:
        - 'localhost:3000'  # invoice-gateway-api
        - 'localhost:9101'  # invoice-orchestrator
        - 'localhost:9102'  # ubl-transformer
        - 'localhost:9103'  # validation-coordinator
```

### Grafana Dashboards

**Dashboards created:**
1. **Service Overview** - All 4 services in one view
2. **Invoice Gateway API** - Request rate, latency, errors
3. **Invoice Orchestrator** - Saga metrics, state transitions
4. **Validation Pipeline** - Layer execution times, consensus decisions

**Example PromQL queries:**
```promql
# p95 request latency
histogram_quantile(0.95, rate(invoice_gateway_http_request_duration_seconds_bucket[5m]))

# Error rate
rate(invoice_gateway_errors_total[5m]) / rate(invoice_gateway_http_requests_total[5m])

# Active sagas
invoice_orchestrator_active_sagas
```

## Consequences

### Positive

✅ **Complete visibility:** Traces, metrics, and logs work together
✅ **Fast debugging:** Correlation IDs link all three pillars
✅ **Vendor-neutral:** Open source, self-hosted, no lock-in
✅ **Low overhead:** Pino is fastest, Prometheus is efficient
✅ **Industry standard:** OpenTelemetry is W3C standard
✅ **Cost-effective:** No SaaS fees (€0 per month)

### Negative

❌ **Operational burden:** Need to run Prometheus, Jaeger, Loki, Grafana
❌ **Storage costs:** Time-series data grows over time
❌ **No turnkey solution:** Must configure dashboards manually
❌ **Learning curve:** Team must learn PromQL, Jaeger UI

### Mitigation Strategies

**Operational Burden:**
- Use managed Prometheus (DigitalOcean Monitoring)
- Run Jaeger/Loki on dedicated infrastructure server
- Automate deployment with systemd/Docker Compose

**Storage Costs:**
- 15-day retention for metrics (configurable)
- 7-day retention for traces
- 30-day retention for logs
- Archive to S3 for long-term storage

**Learning Curve:**
- Pre-built Grafana dashboards (import from library)
- Documentation with example PromQL queries
- Team training sessions

## Alternatives Considered

### Alternative 1: Datadog (SaaS)

**Pros:**
- Turnkey solution (no infrastructure)
- Beautiful UI out of the box
- AI-powered anomaly detection

**Cons:**
- **Cost:** ~€120/month per host (4 services = €480/month)
- **Vendor lock-in:** Proprietary agent and APIs
- **Data sovereignty:** Logs sent to US servers (GDPR concerns)

**Decision:** Rejected - too expensive for initial launch

### Alternative 2: Elastic APM

**Pros:**
- Integrated with Elasticsearch (if already using)
- Good search capabilities
- Open source

**Cons:**
- Heavy resource usage (Elasticsearch + Kibana + APM Server)
- Complex to operate
- Slower than Prometheus for metrics

**Decision:** Rejected - operational complexity too high

### Alternative 3: Application Insights (Azure)

**Pros:**
- Native Azure integration
- Good for .NET services

**Cons:**
- Not optimized for Node.js
- Vendor lock-in (Microsoft)
- Higher cost than self-hosted

**Decision:** Rejected - not running on Azure

## Related Decisions

- **ADR-006:** Message Bus Architecture (traces span RabbitMQ/Kafka)
- **ADR-003:** System Decomposition (defines service boundaries to monitor)

## References

- [OpenTelemetry Docs](https://opentelemetry.io/docs/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [Pino Documentation](https://getpino.io/)
- [Jaeger Architecture](https://www.jaegertracing.io/docs/1.51/architecture/)

---

**Author:** Team 1 Lead
**Reviewers:** System Architect, SRE Team
**Implementation:** services/*/src/tracing.ts, services/*/src/metrics.ts
