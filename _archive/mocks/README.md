# eRačun Mock Services

**Production-grade mock services for Croatian e-invoice system external dependencies**

## 🎯 Overview

Complete mock suite for all external services required by the eRačun invoice processing platform. Designed for deterministic testing, chaos engineering, and development without external dependencies.

### Services Included

1. **FINA Mock** (Port 8449) - Tax Authority fiscalization API (SOAP/XML)
2. **Porezna Mock** (Port 8450) - Tax reporting API (REST + OAuth 2.0)
3. **Email Mock** (Port 1025/1143/8025) - SMTP/IMAP email service
4. **KLASUS Mock** (Port 8451) - Product classification registry
5. **Bank Mock** (Port 8452) - Banking API (IBAN, transactions, MT940)
6. **Cert Mock** (Port 8453) - Certificate Authority (X.509, CRL, OCSP)
7. **Admin UI** (Port 8080) - Centralized management dashboard

---

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js 20+ (for local development)

### Start All Services

```bash
cd mocks
docker-compose up -d
```

### Access Services

- **Admin UI:** http://localhost:8080
- **FINA Mock:** http://localhost:8449
- **Porezna Mock:** http://localhost:8450
- **Email Web UI:** http://localhost:8025
- **KLASUS Mock:** http://localhost:8451
- **Bank Mock:** http://localhost:8452
- **Cert Mock:** http://localhost:8453

---

## 📦 Service Details

### 1. FINA Fiscalization Mock

**Purpose:** Mock Croatian Tax Authority fiscalization service

**Features:**
- Full SOAP/XML endpoint matching production API
- JIR (unique invoice ID) generation
- XML signature validation (mock)
- Configurable chaos engineering
- Stateful transaction tracking

**Example Usage:**

```bash
# Health check
curl http://localhost:8449/health

# Submit invoice (SOAP)
curl -X POST http://localhost:8449/FiskalizacijaService \
  -H "Content-Type: text/xml" \
  -d @sample-invoice.xml

# Check transaction status
curl http://localhost:8449/FiskalizacijaService/status/TRANSACTION_ID
```

**Configuration:**
```bash
FINA_PORT=8449
CHAOS_MODE=off|light|moderate|extreme
ERROR_RATE=0.01
LATENCY_MIN=100
LATENCY_MAX=500
```

---

### 2. Porezna API Mock

**Purpose:** Mock Croatian Tax Authority reporting API

**Features:**
- OAuth 2.0 authentication flow
- Batch invoice submission
- Async processing simulation
- Webhook callbacks
- Rate limiting (60 req/min)

**Example Usage:**

```bash
# Get OAuth token
curl -X POST http://localhost:8450/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "test",
    "client_secret": "secret"
  }'

# Submit batch
curl -X POST http://localhost:8450/api/v1/invoices/batch \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "invoices": [...],
    "webhookUrl": "http://your-service/webhook"
  }'

# Check batch status
curl http://localhost:8450/api/v1/batches/BATCH_ID \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

---

### 3. Email Mock

**Purpose:** Mock SMTP/IMAP email service

**Features:**
- SMTP server (Port 1025)
- IMAP server (Port 1143)
- Web UI for email inspection (Port 8025)
- Attachment handling
- Multi-part MIME support

**Example Usage:**

```bash
# Send email via SMTP
echo "Subject: Test\n\nHello" | \
  curl smtp://localhost:1025 \
  --mail-from sender@example.com \
  --mail-rcpt recipient@example.com \
  -T -

# View emails in browser
open http://localhost:8025

# List emails via API
curl http://localhost:8025/api/emails

# Get specific email
curl http://localhost:8025/api/emails/EMAIL_ID
```

**Configuration:**
```bash
SMTP_PORT=1025
IMAP_PORT=1143
WEB_PORT=8025
MAIL_DIR=/app/maildir
```

---

### 4. KLASUS Registry Mock

**Purpose:** Mock Croatian product classification system

**Features:**
- Complete KLASUS 2025 code database
- Search and filter by code/name
- Hierarchical code structure
- Bulk validation
- Fast in-memory lookups

**Example Usage:**

```bash
# Get code by ID
curl http://localhost:8451/api/codes/26.11

# Search codes
curl "http://localhost:8451/api/search?q=računalo&level=3"

# Bulk validate
curl -X POST http://localhost:8451/api/validate/bulk \
  -H "Content-Type: application/json" \
  -d '{"codes": ["26.11", "26.12", "99.99"]}'

# Get random code (for testing)
curl http://localhost:8451/api/random?level=3
```

---

### 5. Bank API Mock

**Purpose:** Mock Croatian banking API

**Features:**
- IBAN validation (Croatian format)
- Account verification
- Transaction queries
- Payment processing
- MT940 statement generation

**Example Usage:**

```bash
# Validate IBAN
curl -X POST http://localhost:8452/api/v1/validate/iban \
  -H "Content-Type: application/json" \
  -d '{"iban": "HR1210010051863000160"}'

# Get account info
curl http://localhost:8452/api/v1/accounts/HR1210010051863000160

# Get account balance
curl http://localhost:8452/api/v1/accounts/HR1210010051863000160/balance

# Get transactions
curl "http://localhost:8452/api/v1/accounts/HR1210010051863000160/transactions?from=2024-01-01&to=2024-12-31"

# Download MT940 statement
curl "http://localhost:8452/api/v1/accounts/HR1210010051863000160/statement/mt940?from=2024-01-01"
```

---

### 6. Certificate Authority Mock

**Purpose:** Mock X.509 certificate operations

**Features:**
- Certificate generation
- Certificate validation
- CRL (Certificate Revocation List)
- OCSP (Online Certificate Status Protocol)
- Certificate renewal

**Example Usage:**

```bash
# Request new certificate
curl -X POST http://localhost:8453/api/v1/certificates/request \
  -H "Content-Type: application/json" \
  -d '{
    "commonName": "Test Company",
    "organization": "Test d.o.o.",
    "country": "HR",
    "oib": "12345678903",
    "validityDays": 365
  }'

# Validate certificate
curl -X POST http://localhost:8453/api/v1/certificates/validate \
  -H "Content-Type: application/json" \
  -d '{"serialNumber": "ABC123"}'

# Get CRL
curl http://localhost:8453/api/v1/crl

# OCSP check
curl -X POST http://localhost:8453/api/v1/ocsp \
  -H "Content-Type: application/json" \
  -d '{"serialNumber": "ABC123"}'
```

---

## 🎮 Admin UI

**Access:** http://localhost:8080

**Features:**
- View status of all services
- Configure chaos settings globally
- Reset service state
- View metrics and logs
- Test data generation

**Global Chaos Configuration:**
- Chaos Mode: off / light / moderate / extreme
- Error Rate: 0.01 - 1.0
- Latency Range: 100-500ms (configurable)

---

## 🧪 Chaos Engineering

All services support chaos engineering modes:

### Chaos Modes

- **Off:** Normal operation, no failures
- **Light:** 0.5% error rate, normal latency
- **Moderate:** 1% error rate, variable latency
- **Extreme:** 3% error rate, high latency (1-5s)

### Configuration per Service

```bash
# Configure FINA chaos
curl -X POST http://localhost:8449/mock/config \
  -H "Content-Type: application/json" \
  -d '{
    "chaosMode": "moderate",
    "errorRate": 0.05,
    "latency": {"min": 200, "max": 2000}
  }'
```

### Global Chaos (via Admin UI)

Visit http://localhost:8080 and use the chaos controls to apply settings to all services.

---

## 🔧 Development

### Local Development

```bash
# Install dependencies
cd mocks/fina-mock
npm install

# Run in development mode
npm run dev

# Build
npm run build

# Run tests
npm test
```

### Directory Structure

```
mocks/
├── core/                      # Shared utilities
│   ├── chaos-engine/         # Chaos engineering
│   └── data-generator/       # Test data generation
├── fina-mock/                # FINA service
├── porezna-mock/             # Porezna service
├── email-mock/               # Email service
├── klasus-mock/              # KLASUS registry
├── bank-mock/                # Banking API
├── cert-mock/                # Certificate Authority
├── mock-admin/               # Admin UI
└── docker-compose.yml        # Orchestration
```

---

## 🧰 Shared Utilities

### Chaos Engine

```typescript
import { ChaosEngine } from '@eracun/chaos-engine';

const chaos = new ChaosEngine({
  mode: 'moderate',
  errorRate: 0.01,
  latency: { min: 100, max: 500 }
});

const result = chaos.evaluate();
if (result.shouldFail) {
  // Inject failure
}
await chaos.applyDelay(result.delay);
```

### Data Generator

```typescript
import { DataGenerator } from '@eracun/data-generator';

const generator = new DataGenerator('seed-for-determinism');

// Generate valid Croatian OIB
const oib = generator.generateOIB();

// Generate valid Croatian IBAN
const iban = generator.generateIBAN();

// Generate realistic invoice
const invoice = generator.generateInvoice({
  currency: 'EUR',
  items: 5
});
```

---

## 🐳 Docker Operations

### Build All Services

```bash
docker-compose build
```

### Start Services

```bash
# Start all
docker-compose up -d

# Start specific service
docker-compose up -d fina-mock

# View logs
docker-compose logs -f fina-mock

# Stop all
docker-compose down
```

### Reset All Data

```bash
# Stop and remove volumes
docker-compose down -v

# Start fresh
docker-compose up -d
```

---

## 📊 Monitoring

### Health Checks

All services expose `/health` endpoint:

```bash
curl http://localhost:8449/health
```

Response:
```json
{
  "status": "operational",
  "uptime": 123456,
  "metrics": {
    "requests": 150,
    "errors": 2,
    "avgLatency": 250
  },
  "config": {
    "chaosMode": "off",
    "errorRate": 0.01
  }
}
```

### Metrics

- Request count
- Error count
- Average latency
- Service-specific metrics (emails, certificates, etc.)

---

## 🔒 Security Notes

**⚠️ FOR TESTING ONLY**

These are mock services for development and testing:

- **NO real security** - accept all authentication
- **Expose private keys** - for testing convenience
- **NO data persistence** - data lost on restart
- **NEVER use in production**

---

## 🎯 Use Cases

### 1. Development
- Test invoice processing without external services
- Deterministic test scenarios
- Fast local development

### 2. CI/CD
- Integration tests in pipeline
- No external dependencies
- Parallelizable tests

### 3. Chaos Engineering
- Test failure scenarios
- Verify circuit breakers
- Validate retry logic

### 4. Load Testing
- Benchmark system performance
- Test at scale without hitting real APIs
- Configurable latency for stress testing

---

## 📝 Environment Variables

### Global
```bash
CHAOS_MODE=off|light|moderate|extreme
ERROR_RATE=0.01
NODE_ENV=development|production
```

### Service-Specific
See individual service documentation above.

---

## 🤝 Contributing

When adding new mock services:

1. Follow existing patterns (TypeScript, Express)
2. Include chaos engineering support
3. Add health check endpoint
4. Provide Dockerfile and package.json
5. Update docker-compose.yml
6. Add to Admin UI service list

---

## 📚 Related Documentation

- **Implementation Plan:** [MOCK_IMPLEMENTATION_PLAN.md](../MOCK_IMPLEMENTATION_PLAN.md)
- **Main Documentation:** [../docs/](../docs/)
- **API Contracts:** [../docs/api-contracts/](../docs/api-contracts/)

---

**Version:** 1.0.0
**Last Updated:** 2025-11-16
**Status:** ✅ Production Ready

All 6 mock services + Admin UI implemented and tested! 🚀
