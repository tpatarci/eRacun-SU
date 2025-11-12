# FINA Connector Service

**B2C Invoice Fiscalization Service** for Croatian Tax Authority (FINA) integration.

## Overview

The FINA Connector Service is responsible for submitting B2C invoices to the Croatian Tax Authority (FINA) for fiscalization. It implements the complete B2C fiscalization workflow including:

- SOAP API integration with FINA fiscalization service
- XMLDSig signature generation via digital-signature-service
- ZKI (Zaštitni kod izdavatelja) code generation
- Retry logic with exponential backoff
- Offline queue for 48-hour grace period (Croatian regulation)
- Full observability (Prometheus metrics, structured logging, distributed tracing)

## Architecture

```
┌─────────────────┐
│  RabbitMQ       │  Fiscalization requests
│  Consumer       │◄──────────────────────────
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  Fiscalization Service (Orchestrator)   │
├─────────────────────────────────────────┤
│  1. Generate ZKI code                   │
│  2. Sign SOAP envelope (XMLDSig)        │
│  3. Submit to FINA (retry logic)        │
│  4. Handle offline queueing             │
└───┬─────────────┬──────────────┬────────┘
    │             │              │
    ▼             ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────────┐
│Signature │  │   SOAP   │  │   Offline    │
│ Service  │  │  Client  │  │    Queue     │
│Integration│  │  (FINA)  │  │ (PostgreSQL) │
└──────────┘  └──────────┘  └──────────────┘
```

## Components

### 1. SOAP Client (`src/soap-client.ts`)
- Loads FINA WSDL and initializes SOAP client
- Implements FINA operations:
  - `racuni` - Submit B2C invoice for fiscalization
  - `echo` - Health check
  - `provjera` - Validation (test only)
- Parses SOAP faults and extracts JIR (Unique Invoice Identifier)
- Handles HTTPS connection with SSL certificate validation

### 2. Signature Integration (`src/signature-integration.ts`)
- HTTP client for digital-signature-service
- Generates ZKI codes for B2C invoices
- Signs SOAP envelopes with XMLDSig
- Retry logic with exponential backoff

### 3. Fiscalization Service (`src/fiscalization.ts`)
- Main orchestrator for B2C fiscalization workflow
- Coordinates ZKI generation, signing, and FINA submission
- Implements retry policy (max 3 attempts, exponential backoff)
- Handles transient errors and offline queueing

### 4. Offline Queue (`src/offline-queue.ts`)
- PostgreSQL-backed queue for failed submissions
- Provides 48-hour grace period per Croatian regulations
- Automatic cleanup of expired entries
- Queue metrics for monitoring

### 5. Main Entry Point (`src/index.ts`)
- RabbitMQ consumer for fiscalization requests
- HTTP server for health checks and metrics
- Graceful shutdown handling
- Configuration management

### 6. Observability (`src/observability.ts`)
- **Prometheus Metrics:**
  - `fina_fiscalization_total` - Total fiscalization operations
  - `fina_fiscalization_duration_seconds` - Operation duration
  - `fina_errors_total` - FINA API errors by error code
  - `fina_retry_attempts_total` - Retry attempts
  - `fina_offline_queue_depth` - Offline queue size
  - `fina_offline_queue_max_age_seconds` - Oldest entry age
  - `fina_jir_received_total` - Successful fiscalizations
- **Structured Logging:** JSON logs with PII masking (OIB numbers)
- **Distributed Tracing:** OpenTelemetry integration

## Configuration

All configuration via environment variables (see `.env.example`):

### Service Configuration
```bash
PORT=3003                    # HTTP server port
NODE_ENV=development         # Environment (development, production)
LOG_LEVEL=info              # Logging level (debug, info, warn, error)
```

### FINA API Configuration
```bash
FINA_WSDL_URL=https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl
FINA_ENDPOINT_URL=https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest
FINA_TIMEOUT=10000          # Request timeout (ms)
```

### Digital Signature Service
```bash
SIGNATURE_SERVICE_URL=http://localhost:3002
SIGNATURE_TIMEOUT=5000      # Request timeout (ms)
```

### PostgreSQL (Offline Queue)
```bash
DATABASE_URL=postgresql://user:password@localhost/eracun_fina
```

### RabbitMQ
```bash
RABBITMQ_URL=amqp://localhost
FISCALIZATION_QUEUE=fina.fiscalization.requests
RESULT_QUEUE=fina.fiscalization.results
```

### Retry & Offline Queue
```bash
MAX_RETRIES=3                        # Max retry attempts
RETRY_DELAY_SECONDS=2                # Initial retry delay
OFFLINE_QUEUE_ENABLED=true           # Enable offline queue
OFFLINE_QUEUE_MAX_AGE_HOURS=48       # Grace period (hours)
```

## API Endpoints

### Health & Monitoring

#### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "fina-connector",
  "timestamp": "2025-11-12T14:30:00.000Z",
  "checks": {
    "database": "ok",
    "rabbitmq": "ok"
  }
}
```

#### `GET /ready`
Readiness check endpoint.

**Response:**
```json
{
  "ready": true,
  "service": "fina-connector",
  "timestamp": "2025-11-12T14:30:00.000Z"
}
```

#### `GET /metrics`
Prometheus metrics endpoint.

**Response:** Prometheus text format metrics

#### `GET /queue/stats`
Offline queue statistics.

**Response:**
```json
{
  "pending": 5,
  "processing": 1,
  "failed": 2,
  "oldestEntryAge": 3600
}
```

## Message Contracts

### Input: Fiscalization Request (RabbitMQ)

**Queue:** `fina.fiscalization.requests`

**Message Format:**
```json
{
  "messageId": "uuid",
  "invoiceId": "invoice-123",
  "timestamp": "2025-11-12T14:30:00Z",
  "correlationId": "request-456",
  "invoice": {
    "oib": "12345678901",
    "datVrijeme": "2025-11-12T14:30:00",
    "brojRacuna": "1",
    "oznPoslProstora": "PP1",
    "oznNapUr": "NAP1",
    "ukupanIznos": "100.00",
    "zki": "a1b2c3d4...",
    "nacinPlac": "G",
    "pdv": [
      {
        "porez": "80.00",
        "stopa": "25.00",
        "iznos": "20.00"
      }
    ]
  }
}
```

### Output: Fiscalization Result (RabbitMQ)

**Queue:** `fina.fiscalization.results`

**Success Response:**
```json
{
  "messageId": "uuid",
  "invoiceId": "invoice-123",
  "jir": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "success": true,
  "timestamp": "2025-11-12T14:30:05Z",
  "correlationId": "request-456"
}
```

**Error Response:**
```json
{
  "messageId": "uuid",
  "invoiceId": "invoice-123",
  "success": false,
  "error": {
    "code": "s:001",
    "message": "Invalid invoice data"
  },
  "timestamp": "2025-11-12T14:30:05Z",
  "correlationId": "request-456"
}
```

## Installation

```bash
# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Edit configuration
nano .env
```

## Development

```bash
# Build TypeScript
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Start service (development)
npm run dev

# Start service (production)
npm start
```

## Deployment

### Prerequisites
- PostgreSQL database (for offline queue)
- RabbitMQ message broker
- digital-signature-service running and accessible
- FINA test/production credentials

### systemd Deployment

1. Build the service:
```bash
npm run build
```

2. Create systemd service unit:
```ini
[Unit]
Description=FINA Connector Service
After=network.target postgresql.service rabbitmq-server.service

[Service]
Type=simple
User=eracun
WorkingDirectory=/opt/eracun/services/fina-connector
EnvironmentFile=/etc/eracun/fina-connector.env
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=10

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

3. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable eracun-fina-connector
sudo systemctl start eracun-fina-connector
sudo systemctl status eracun-fina-connector
```

## Monitoring

### Key Metrics

Monitor these Prometheus metrics:

- `fina_fiscalization_total{status="failure"}` - Failed fiscalizations
- `fina_fiscalization_duration_seconds{quantile="0.99"}` - P99 latency
- `fina_errors_total` - FINA API errors
- `fina_offline_queue_depth` - Offline queue size
- `fina_offline_queue_max_age_seconds` - Oldest queued entry

### Alerts

Recommended alert rules:

```yaml
groups:
  - name: fina-connector
    rules:
      - alert: FINAHighErrorRate
        expr: rate(fina_fiscalization_total{status="failure"}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High FINA fiscalization error rate"

      - alert: FINAOfflineQueueGrowing
        expr: fina_offline_queue_depth > 100
        for: 10m
        annotations:
          summary: "FINA offline queue growing"

      - alert: FINAOfflineQueueExpiringSoon
        expr: fina_offline_queue_max_age_seconds > 172800  # 48 hours
        annotations:
          summary: "FINA offline queue entries expiring soon"
```

## Error Handling

### FINA Error Codes

Common FINA API error codes:

- `s:001` - Invalid request structure
- `s:002` - Invalid ZKI code
- `s:003` - Certificate validation failed
- `s:004` - Invoice already fiscalized
- `s:999` - Unknown server error

### Retry Policy

- **Max retries:** 3 attempts
- **Backoff:** Exponential (2s, 4s, 8s)
- **Retryable errors:** Network timeouts, 5xx server errors, 429 rate limits
- **Non-retryable errors:** 4xx client errors

### Offline Queue

If fiscalization fails after all retries:
1. Invoice queued in PostgreSQL
2. Retry processing every 5 minutes
3. Grace period: 48 hours (Croatian regulation)
4. After 48 hours: Entry expires and alert triggered

## Troubleshooting

### Service won't start

1. Check configuration:
```bash
grep -v '^#' .env | grep -v '^$'
```

2. Test database connection:
```bash
psql $DATABASE_URL -c 'SELECT 1'
```

3. Test RabbitMQ connection:
```bash
rabbitmqctl status
```

### FINA API errors

1. Check FINA service status:
```bash
curl -I https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl
```

2. Verify digital-signature-service is running:
```bash
curl http://localhost:3002/health
```

3. Check certificate validity:
```bash
curl http://localhost:3002/api/v1/certificates
```

### Offline queue growing

1. Check queue stats:
```bash
curl http://localhost:3003/queue/stats
```

2. Check FINA API availability
3. Review error logs:
```bash
journalctl -u eracun-fina-connector -f
```

## Security

### Secrets Management

- Never commit `.env` files
- Use SOPS + age for encrypted secrets in production
- Certificates stored in `/etc/eracun/certificates/` with 600 permissions

### PII Protection

- OIB numbers masked in logs (`***********`)
- No sensitive data in metrics labels
- Request IDs used for correlation (not invoice IDs)

## Performance

### Throughput

- **Target:** 10,000 invoices/hour
- **Latency (P99):** <5 seconds
- **RabbitMQ prefetch:** 1 (process one invoice at a time)

### Resource Usage

- **Memory:** 512MB (typical), 1GB (burst)
- **CPU:** 0.5 cores (typical), 2 cores (burst)
- **Database:** <1GB for 48-hour queue

## License

Proprietary - eRačun Invoice Processing Platform

## Support

For issues and questions:
- **Technical Issues:** See `RUNBOOK.md`
- **FINA Integration:** Contact FINA support (01 4404 707)
- **Service Architecture:** See `/docs/adr/` for design decisions
