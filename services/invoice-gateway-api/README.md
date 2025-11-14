# invoice-gateway-api

**Central entry point for all invoice submissions to the eRačun platform.**

## Purpose

The Invoice Gateway API is the primary interface for submitting invoices for validation and processing. It handles:
- REST API for invoice submission (JSON, XML, PDF)
- Request validation and sanitization
- Rate limiting (100 requests/minute per client)
- Idempotency key handling for duplicate prevention
- Async processing queue management
- Status tracking and retrieval

## Architecture

**Bounded Context:** Invoice Ingestion
**Priority:** P0 - Must be completed first
**Service Limit:** 2,500 LOC (excluding tests)

### Technology Stack

- **Runtime:** Node.js 20+ with TypeScript (strict mode)
- **Framework:** Express 4.x
- **Validation:** Zod (schema validation)
- **DI Container:** Inversify
- **Logging:** Pino (structured JSON logs)
- **Testing:** Jest (100% coverage required)

### Dependencies

- **Upstream:** None (entry point)
- **Downstream:**
  - invoice-orchestrator (via RabbitMQ)
  - validation-coordinator (via commands)

## API Specification

See [openapi.yaml](./openapi.yaml) for complete API specification.

### Key Endpoints

#### POST /api/v1/invoices
Submit invoice for processing.

**Headers:**
- `X-Idempotency-Key` (required): UUID for duplicate prevention
- `X-Request-ID` (optional): Correlation ID for tracing

**Content Types:**
- `application/json` - JSON invoice
- `application/xml` - UBL 2.1 XML
- `application/pdf` - PDF invoice (requires OCR)

**Response:** 202 Accepted
```json
{
  "invoiceId": "123e4567-e89b-12d3-a456-426614174000",
  "status": "QUEUED",
  "trackingUrl": "https://api.eracun.hr/api/v1/invoices/123e4567...",
  "acceptedAt": "2025-11-14T10:30:00Z"
}
```

#### GET /api/v1/invoices/:invoiceId
Get invoice processing status.

**Response:** 200 OK
```json
{
  "invoiceId": "123e4567-e89b-12d3-a456-426614174000",
  "invoiceNumber": "INV-2025-001",
  "status": "VALIDATING",
  "progress": {
    "currentStep": "Running validation",
    "totalSteps": 6,
    "percentage": 50
  },
  "submittedAt": "2025-11-14T10:30:00Z",
  "updatedAt": "2025-11-14T10:31:00Z"
}
```

#### GET /api/v1/health
Full health check with dependency status.

**Response:** 200 OK / 503 Service Unavailable
```json
{
  "status": "UP",
  "timestamp": "2025-11-14T10:30:00Z",
  "dependencies": {
    "database": "UP",
    "rabbitmq": "UP",
    "redis": "UP"
  },
  "version": "1.0.0"
}
```

## Installation

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Build
npm run build
```

## Development

```bash
# Start in development mode (hot reload)
npm run dev

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint
npm run lint

# Type check
npm run typecheck
```

## Production

```bash
# Build
npm run build

# Start
npm start
```

## Configuration

All configuration is via environment variables. See [.env.example](./.env.example) for available options.

### Required Environment Variables

- `PORT` - HTTP port (default: 3001)
- `RABBITMQ_URL` - RabbitMQ connection string
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string

### Optional Environment Variables

- `LOG_LEVEL` - Log level (default: info)
- `CORS_ORIGIN` - CORS allowed origin (default: *)
- `USE_MOCK_SERVICES` - Use mock services (default: true)

## Rate Limiting

- **Limit:** 100 requests per minute per client IP
- **Response:** 429 Too Many Requests with `Retry-After` header

## Idempotency

All POST requests require an `X-Idempotency-Key` header with a UUID value. Duplicate requests with the same idempotency key return the same response (cached for 24 hours).

## Error Handling

All errors follow a standardized format:

```json
{
  "error": {
    "code": "ERR_1001",
    "message": "Invalid OIB format",
    "details": { ... },
    "timestamp": "2025-11-14T10:30:00Z",
    "correlationId": "123e4567-e89b-12d3-a456-426614174000"
  }
}
```

See [@eracun/contracts](../../shared/contracts) for complete error code list.

## Monitoring

### Health Checks

- `/api/v1/health` - Full health check with dependencies
- `/api/v1/health/ready` - Readiness check (Kubernetes)
- `/api/v1/health/live` - Liveness check (Kubernetes)

### Metrics (Prometheus)

- `http_request_duration_seconds` - Request latency histogram
- `http_requests_total` - Total HTTP requests counter
- `invoice_submissions_total` - Total invoice submissions
- `validation_failures_total` - Validation failure count

### Structured Logging

All logs are in JSON format with correlation IDs:

```json
{
  "level": "info",
  "time": "2025-11-14T10:30:00Z",
  "msg": "Invoice submission received",
  "invoiceId": "123e4567...",
  "requestId": "abc123...",
  "idempotencyKey": "xyz789..."
}
```

## Testing

```bash
# Run all tests
npm test

# Run unit tests only
npm test -- tests/unit

# Run integration tests only
npm test -- tests/integration

# Generate coverage report
npm run test:coverage
```

**Coverage Requirement:** 100% (enforced in CI)

## Performance Requirements

- **Document upload:** <200ms (p95)
- **Status check:** <50ms (p95)
- **Throughput:** 10,000 invoices/hour minimum
- **Resource limits:** 512MB RAM baseline, 1GB burst

## Security

- **Helmet.js** - Security headers
- **CORS** - Configurable origin restrictions
- **Rate limiting** - Protection against abuse
- **Input validation** - Zod schema validation at API boundary
- **XML security** - XXE prevention (disabled external entities)

## Deployment

### systemd Service

```ini
[Unit]
Description=eRačun Invoice Gateway API
After=network.target rabbitmq-server.service postgresql.service

[Service]
Type=simple
User=eracun
WorkingDirectory=/opt/eracun/services/invoice-gateway-api
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=10s

# Environment
Environment=NODE_ENV=production
EnvironmentFile=/etc/eracun/invoice-gateway-api.env

# Resource limits
MemoryMax=1G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
```

### Docker (Optional)

```bash
# Build
docker build -t eracun/invoice-gateway-api:latest .

# Run
docker run -p 3001:3001 \
  --env-file .env \
  eracun/invoice-gateway-api:latest
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u eracun-invoice-gateway-api -n 100 -f

# Verify configuration
npm run typecheck

# Test dependencies
curl http://localhost:3001/api/v1/health
```

### High Error Rate

```bash
# Check validation failures
curl http://localhost:3001/api/v1/health

# Review logs for specific errors
journalctl -u eracun-invoice-gateway-api | grep ERROR
```

### Rate Limit Issues

Rate limits can be adjusted in `src/middleware/rate-limiter.ts`:

```typescript
max: 100, // Requests per window
windowMs: 60 * 1000, // Window in milliseconds
```

## Related Documentation

- **OpenAPI Spec:** [openapi.yaml](./openapi.yaml)
- **Architecture:** [../../docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)
- **Shared Contracts:** [../../shared/contracts](../../shared/contracts)
- **Team Instructions:** [../../TEAM_1.md](../../TEAM_1.md)

---

**Version:** 1.0.0
**Status:** ✅ Week 1 Day 3-4 Implementation Complete
**Maintained by:** Team 1 (Core Processing Pipeline)
**Service Limit:** 2,500 LOC (currently: ~800 LOC)
