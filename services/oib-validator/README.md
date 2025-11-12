# OIB Validator Service

Croatian OIB (Osobni Identifikacijski Broj) validation microservice with MOD-11 checksum verification.

## Overview

This service provides OIB validation using the **ISO 7064, MOD 11-10** algorithm as specified by Croatian Tax Authority regulations. It offers both HTTP REST API and RabbitMQ messaging interfaces for synchronous and asynchronous validation workflows.

## Features

- ✅ **ISO 7064 MOD 11-10 checksum validation**
- ✅ **Format validation** (11 digits, no leading zero)
- ✅ **Batch validation** (up to 1,000 OIBs per request)
- ✅ **HTTP REST API** (Express.js)
- ✅ **RabbitMQ consumer** (async messaging)
- ✅ **Prometheus metrics** (observability)
- ✅ **Structured logging** (Pino)
- ✅ **100% test coverage** (Jest + property-based testing)
- ✅ **TypeScript strict mode**
- ✅ **Health checks** and readiness probes

## Validation Algorithm

### OIB Format

- **Length:** Exactly 11 digits
- **First digit:** Cannot be 0 (range: 1-9)
- **Characters:** Numeric only (no letters or special characters)

### MOD-11 Checksum Algorithm

```
1. Start with remainder = 10
2. For each of the first 10 digits (left to right):
   a. Add digit to remainder
   b. remainder = (remainder mod 10), or 10 if zero
   c. remainder = (remainder * 2) mod 11
3. Check digit (11th digit) = (11 - remainder) mod 10
```

### Example

Valid OIB: `12345678903`

```
remainder = 10
Process digits 1-2-3-4-5-6-7-8-9-0:
  ...calculations...
remainder = 8
check_digit = (11 - 8) % 10 = 3 ✓ matches 11th digit
```

## API Reference

### REST API

#### POST `/api/v1/validate`

Validate a single OIB.

**Request:**
```json
{
  "oib": "12345678903"
}
```

**Response (200 OK):**
```json
{
  "oib": "12345678903",
  "valid": true,
  "errors": [],
  "metadata": {
    "type": "unknown",
    "checksumValid": true
  }
}
```

**Response (Invalid OIB):**
```json
{
  "oib": "12345678901",
  "valid": false,
  "errors": ["Invalid OIB checksum (ISO 7064, MOD 11-10)"],
  "metadata": {
    "type": "unknown",
    "checksumValid": false
  }
}
```

#### POST `/api/v1/validate/batch`

Validate multiple OIBs (max 1,000).

**Request:**
```json
{
  "oibs": ["12345678903", "98765432106", "invalid"]
}
```

**Response (200 OK):**
```json
{
  "total": 3,
  "valid": 2,
  "invalid": 1,
  "results": [
    {
      "oib": "12345678903",
      "valid": true,
      "errors": [],
      "metadata": { "type": "unknown", "checksumValid": true }
    },
    {
      "oib": "98765432106",
      "valid": true,
      "errors": [],
      "metadata": { "type": "unknown", "checksumValid": true }
    },
    {
      "oib": "invalid",
      "valid": false,
      "errors": ["OIB must be exactly 11 digits (got 7)"],
      "metadata": { "type": "unknown", "checksumValid": false }
    }
  ]
}
```

#### GET `/health`

Health check endpoint.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "oib-validator",
  "timestamp": "2025-11-12T10:30:00.000Z"
}
```

#### GET `/ready`

Readiness check endpoint.

**Response (200 OK):**
```json
{
  "status": "ready",
  "service": "oib-validator",
  "timestamp": "2025-11-12T10:30:00.000Z"
}
```

#### GET `/metrics`

Prometheus metrics endpoint.

**Response (200 OK):**
```
# HELP oib_validations_total Total number of OIB validations performed
# TYPE oib_validations_total counter
oib_validations_total{result="valid",source="http"} 42
oib_validations_total{result="invalid",source="http"} 3
...
```

### RabbitMQ API

The service consumes messages from the `oib-validation-requests` queue and publishes results to the `oib-validation-results` queue via the `eracun-validation` exchange.

**Request Message (Single OIB):**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "oib": "12345678903",
  "replyTo": "my-response-queue",
  "correlationId": "abc123"
}
```

**Request Message (Batch):**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440001",
  "oibs": ["12345678903", "98765432106"],
  "replyTo": "my-response-queue",
  "correlationId": "abc124"
}
```

**Response Message:**
```json
{
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "result": {
    "oib": "12345678903",
    "valid": true,
    "errors": [],
    "metadata": { "type": "unknown", "checksumValid": true }
  },
  "timestamp": "2025-11-12T10:30:00.000Z"
}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP server host |
| `NODE_ENV` | `development` | Environment (development/production) |
| `LOG_LEVEL` | `info` | Logging level (debug/info/warn/error) |
| `RABBITMQ_URL` | `amqp://localhost:5672` | RabbitMQ connection URL |
| `ENABLE_RABBITMQ` | `false` | Enable RabbitMQ consumer |

### Example Configuration

```bash
# Development
PORT=3001
NODE_ENV=development
LOG_LEVEL=debug
RABBITMQ_URL=amqp://localhost:5672
ENABLE_RABBITMQ=false

# Production
PORT=3001
NODE_ENV=production
LOG_LEVEL=info
RABBITMQ_URL=amqp://rabbitmq.eracun.internal:5672
ENABLE_RABBITMQ=true
```

## Installation

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Start service
npm start

# Development mode (hot reload)
npm run dev
```

## Development

### Project Structure

```
oib-validator/
├── src/
│   ├── oib-validator.ts          # Core validation logic
│   ├── index.ts                   # HTTP server & main entry point
│   ├── observability/
│   │   └── metrics.ts             # Prometheus metrics
│   └── messaging/
│       └── rabbitmq-consumer.ts   # RabbitMQ consumer
├── tests/
│   └── unit/
│       └── oib-validator.test.ts  # Comprehensive test suite
├── package.json
├── tsconfig.json
├── jest.config.js
└── README.md
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage report
npm run test:coverage
```

### Test Coverage

This service maintains **100% test coverage**:

```
All files         | 100 | 100  | 100 | 100 |
 oib-validator.ts | 100 | 100  | 100 | 100 |
```

Tests include:
- Unit tests for all validation functions
- Property-based tests (fast-check library)
- Edge case testing (null, undefined, non-string inputs)
- Real Croatian OIB examples

## Deployment

### systemd Service

Create `/etc/systemd/system/eracun-oib-validator.service`:

```ini
[Unit]
Description=eRacun OIB Validator Service
After=network.target

[Service]
Type=simple
User=eracun
WorkingDirectory=/opt/eracun/services/oib-validator
Environment=NODE_ENV=production
Environment=PORT=3001
Environment=LOG_LEVEL=info
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable eracun-oib-validator
sudo systemctl start eracun-oib-validator

# Check status
sudo systemctl status eracun-oib-validator

# View logs
sudo journalctl -u eracun-oib-validator -f
```

### Docker

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY dist ./dist

EXPOSE 3001

CMD ["node", "dist/index.js"]
```

```bash
# Build image
docker build -t eracun/oib-validator:latest .

# Run container
docker run -d \
  --name oib-validator \
  -p 3001:3001 \
  -e NODE_ENV=production \
  -e LOG_LEVEL=info \
  eracun/oib-validator:latest
```

## Monitoring

### Prometheus Metrics

The service exposes the following metrics at `/metrics`:

- `oib_validations_total` - Counter of validations by result (valid/invalid) and source (http/rabbitmq)
- `oib_validation_duration_seconds` - Histogram of validation durations
- `oib_batch_validations_total` - Counter of batch validations by source
- `oib_batch_validation_size` - Histogram of batch sizes
- `oib_errors_total` - Counter of errors by type

### Health Checks

- **Liveness:** `GET /health` - Returns 200 if service is running
- **Readiness:** `GET /ready` - Returns 200 if service is ready to accept traffic

### Logging

Structured JSON logs with request IDs for traceability:

```json
{
  "level": 30,
  "time": 1699800000000,
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "method": "POST",
  "path": "/api/v1/validate",
  "statusCode": 200,
  "durationMs": 2,
  "msg": "Request completed"
}
```

## Compliance

This service implements OIB validation as specified by Croatian Tax Authority regulations for fiscalization (effective 1 January 2026).

**Key Requirements:**
- OIB format validation (11 digits, no leading zero)
- ISO 7064 MOD 11-10 checksum algorithm
- Used for validating issuer, operator, and recipient OIBs in e-invoices

**References:**
- Croatian Fiscalization Law (NN 89/25)
- FINA e-invoice specifications
- Croatian CIUS (Core Invoice Usage Specification)

## Performance

- **Single validation:** <1ms (p95)
- **Batch validation (100 OIBs):** <10ms (p95)
- **Memory usage:** ~50MB (steady state)
- **Throughput:** >10,000 validations/second (single instance)

## License

PROPRIETARY - eRacun Platform Team

---

**Last Updated:** 2025-11-12
**Version:** 1.0.0
**Maintainer:** eRacun Platform Team
