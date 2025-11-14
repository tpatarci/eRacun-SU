# invoice-orchestrator

Workflow coordination and saga management for invoice processing pipeline.

## Purpose

The Invoice Orchestrator coordinates the multi-step processing workflow for invoices using the Saga pattern. It ensures reliable, distributed transactions across microservices with automatic compensation (rollback) on failures.

## Architecture

### Service Boundaries
- **Bounded Context:** Workflow Coordination
- **Priority:** P0 - Required for pipeline coordination
- **Port:** 3001 (HTTP), 9101 (Metrics)

### Design Patterns
- **Saga Pattern:** State machine-based workflow coordination with XState v5
- **Event Sourcing:** All state transitions recorded for audit trail
- **Compensation Logic:** Automatic rollback on failures
- **Fire-and-Forget:** Async processing with guaranteed delivery

## Saga State Machine

### Workflow States

```
IDLE → VALIDATING → TRANSFORMING → SIGNING → SUBMITTING → COMPLETED
        ↓              ↓             ↓          ↓
     ROLLBACK ← ROLLBACK ← ROLLBACK ← ROLLBACK
```

### State Transitions

1. **IDLE → VALIDATING**
   - Trigger: Invoice received
   - Action: Send validation command to validation-coordinator
   - Compensation: None

2. **VALIDATING → TRANSFORMING**
   - Trigger: Validation successful
   - Action: Send transformation command to ubl-transformer
   - Compensation: Mark validation as canceled

3. **TRANSFORMING → SIGNING**
   - Trigger: Transformation successful
   - Action: Send signing request to digital-signature-service
   - Compensation: Delete transformed document

4. **SIGNING → SUBMITTING**
   - Trigger: Signing successful
   - Action: Submit to FINA via fina-connector
   - Compensation: Revoke signature

5. **SUBMITTING → COMPLETED**
   - Trigger: FINA acceptance
   - Action: Archive invoice, emit completion event
   - Compensation: Retry submission

6. **ANY → ROLLBACK**
   - Trigger: Step failure or timeout
   - Action: Execute compensation actions in reverse order

## API Contract

### Commands (RabbitMQ)

#### ProcessInvoiceCommand
Start invoice processing workflow.

```json
{
  "id": "cmd_123",
  "type": "ProcessInvoice",
  "payload": {
    "invoiceId": "550e8400-e29b-41d4-a716-446655440000",
    "xml": "<Invoice>...</Invoice>",
    "submittedBy": "user@example.com"
  },
  "timestamp": "2025-11-14T12:34:56.789Z",
  "correlationId": "req_abc123"
}
```

### Events (Kafka)

#### InvoiceProcessingStarted
```json
{
  "id": "evt_123",
  "type": "InvoiceProcessingStarted",
  "source": "invoice-orchestrator",
  "data": {
    "invoiceId": "550e8400-e29b-41d4-a716-446655440000",
    "workflowId": "wf_456",
    "initiatedBy": "user@example.com"
  },
  "timestamp": "2025-11-14T12:34:56.789Z",
  "version": "1.0"
}
```

#### InvoiceProcessingCompleted
```json
{
  "id": "evt_124",
  "type": "InvoiceProcessingCompleted",
  "source": "invoice-orchestrator",
  "data": {
    "invoiceId": "550e8400-e29b-41d4-a716-446655440000",
    "workflowId": "wf_456",
    "finaSubmissionId": "FINA_789",
    "processingTime": "4.523s"
  },
  "timestamp": "2025-11-14T12:35:01.312Z",
  "version": "1.0"
}
```

#### InvoiceProcessingFailed
```json
{
  "id": "evt_125",
  "type": "InvoiceProcessingFailed",
  "source": "invoice-orchestrator",
  "data": {
    "invoiceId": "550e8400-e29b-41d4-a716-446655440000",
    "workflowId": "wf_456",
    "failedStep": "VALIDATING",
    "error": {
      "code": "VALIDATION_FAILED",
      "message": "Invalid OIB check digit"
    },
    "compensationsExecuted": ["CancelValidation"]
  },
  "timestamp": "2025-11-14T12:34:58.123Z",
  "version": "1.0"
}
```

## Dependencies

### External Services
- **RabbitMQ** - Command queue for orchestration
- **Kafka** - Event publishing for workflow events

### Internal Services (via Commands)
- **validation-coordinator** - Invoice validation
- **ubl-transformer** - Format transformation
- **digital-signature-service** - XML digital signing
- **fina-connector** - FINA submission
- **archive-service** - Long-term storage

### Shared Libraries
- `@eracun/contracts` - Domain models and interfaces
- `@eracun/adapters` - Service adapter interfaces
- `@eracun/di-container` - Dependency injection container

## Configuration

### Environment Variables

```bash
# Server Configuration
PORT=3001                                    # HTTP server port (optional)
METRICS_PORT=9101                            # Prometheus metrics port
NODE_ENV=production                          # Environment

# Message Bus
RABBITMQ_URL=amqp://localhost:5672
KAFKA_BROKER=localhost:9092

# Saga Configuration
SAGA_TIMEOUT_MS=300000                       # 5 minutes per workflow
MAX_RETRY_ATTEMPTS=3                         # Max retries per step
RETRY_BACKOFF_MS=2000                        # Initial retry delay

# Observability
LOG_LEVEL=info
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces
SERVICE_NAME=invoice-orchestrator
SERVICE_VERSION=1.0.0
```

## Development

### Prerequisites
- Node.js 20.x LTS
- RabbitMQ 3.12+
- Kafka 3.x

### Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Server running (consuming RabbitMQ commands)
```

### Testing

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## Deployment

### systemd Service

```bash
# Start service
sudo systemctl start eracun-invoice-orchestrator

# Check status
sudo systemctl status eracun-invoice-orchestrator

# View logs
sudo journalctl -u eracun-invoice-orchestrator -f
```

## Performance

### SLAs
- **Saga Completion:** <10s (p95) for standard workflow
- **State Transition:** <100ms per transition
- **Throughput:** 10,000 workflows/hour minimum

### Resource Limits
- **Memory:** 512MB baseline, 1GB burst
- **CPU:** 0.5 cores baseline, 2 cores burst

### Monitoring

**Key Metrics:**
- `invoice_orchestrator_saga_duration_seconds` - End-to-end workflow time
- `invoice_orchestrator_state_transitions_total` - State machine transitions
- `invoice_orchestrator_saga_completions_total{status}` - Success/failure count
- `invoice_orchestrator_compensations_total` - Rollback executions
- `invoice_orchestrator_active_sagas` - In-flight workflows

**Grafana Dashboard:** [Invoice Orchestrator Metrics](http://grafana.eracun.internal/d/invoice-orchestrator)

## Troubleshooting

### Common Issues

**Issue: Workflow stuck in state**
```bash
# Check active sagas metric
curl http://localhost:9101/metrics | grep active_sagas

# Review state machine logs
sudo journalctl -u eracun-invoice-orchestrator | grep -A 5 "State transition"

# Check downstream service health
curl http://validation-coordinator:9103/health
```

**Issue: High compensation rate**
```bash
# Check compensation metrics
curl http://localhost:9101/metrics | grep compensations_total

# Identify failing step
sudo journalctl -u eracun-invoice-orchestrator | grep "Compensation executed"

# Review error patterns
sudo journalctl -u eracun-invoice-orchestrator | grep ERROR | tail -50
```

## Saga Design Principles

### Atomicity
Each saga step is atomic - either fully completes or fully rolls back.

### Consistency
Compensating transactions restore system to consistent state.

### Isolation
Sagas use semantic locking (workflow IDs) to prevent concurrent modifications.

### Durability
All state transitions persisted to event store before proceeding.

## Compliance

### Audit Requirements
- All workflow executions logged with timestamps
- State transitions recorded in event store
- Compensation actions auditable
- Supports 11-year retention requirement

## Support

### Documentation
- **Architecture:** [System Architecture](../../docs/ARCHITECTURE.md)
- **ADRs:** [Architecture Decisions](../../docs/adr/)
- **Deployment:** [Deployment Runbook](../../deployment/DEPLOYMENT_RUNBOOK.md)

### Contact
- **Team:** Team 1 - Core Processing Pipeline
- **Slack:** #team-1-core-pipeline

---

**Version:** 1.0.0
**Last Updated:** 2025-11-14
**Maintained By:** Team 1 - Core Processing Pipeline
