# Mock Repository Quick Start Guide

## For Immediate Action

This guide helps you set up the `eracun-mocks` repository and start using mock services immediately.

---

## Step 1: Create the Repository

```bash
# Create new repository
mkdir ~/PycharmProjects/eracun-mocks
cd ~/PycharmProjects/eracun-mocks
git init

# Create initial structure
mkdir -p fina-simulator/src
mkdir -p shared/chaos-engine
mkdir -p docs
```

---

## Step 2: Initialize FINA Mock (Most Critical)

### 2.1 Create package.json
```bash
cd fina-simulator
npm init -y
npm install express body-parser xml2js uuid winston dotenv joi
npm install -D typescript @types/node @types/express tsx nodemon
```

### 2.2 Create Basic FINA Mock Server
```typescript
// fina-simulator/src/server.ts
import express from 'express';
import bodyParser from 'body-parser';
import { parseString, Builder } from 'xml2js';
import { v4 as uuidv4 } from 'uuid';

const app = express();
app.use(bodyParser.text({ type: 'text/xml' }));

// Configuration
const PORT = process.env.FINA_PORT || 8449;
const CHAOS_MODE = process.env.CHAOS_MODE || 'off';
const RESPONSE_DELAY = parseInt(process.env.RESPONSE_DELAY || '100');

// Simulate FINA fiscalization endpoint
app.post('/FiskalizacijaService', async (req, res) => {
  // Inject configurable delay
  await new Promise(resolve => setTimeout(resolve, RESPONSE_DELAY));

  // Parse incoming XML
  parseString(req.body, async (err, result) => {
    if (err) {
      return res.status(400).send(createErrorResponse('SCHEMA_ERROR', 'Invalid XML'));
    }

    // Chaos engineering: random failures
    if (CHAOS_MODE !== 'off' && Math.random() < 0.1) {
      return res.status(503).send(createErrorResponse('SERVICE_UNAVAILABLE', 'Service temporarily unavailable'));
    }

    // Generate JIR (unique invoice identifier)
    const jir = uuidv4();

    // Build response
    const response = {
      RacunOdgovor: {
        $: { xmlns: 'http://www.apis-it.hr/fin/2012/types/f73' },
        Zaglavlje: {
          IdPoruke: uuidv4(),
          DatumVrijeme: new Date().toISOString()
        },
        Jir: jir
      }
    };

    const builder = new Builder();
    const xml = builder.buildObject(response);

    res.set('Content-Type', 'text/xml');
    res.send(xml);
  });
});

// Health check
app.get('/FiskalizacijaService/status', (req, res) => {
  res.json({
    status: 'operational',
    timestamp: new Date().toISOString(),
    testMode: true,
    chaosMode: CHAOS_MODE
  });
});

function createErrorResponse(code: string, message: string): string {
  const error = {
    Error: {
      Code: code,
      Message: message,
      Timestamp: new Date().toISOString()
    }
  };
  const builder = new Builder();
  return builder.buildObject(error);
}

app.listen(PORT, () => {
  console.log(`FINA Mock Service running on port ${PORT}`);
  console.log(`Chaos mode: ${CHAOS_MODE}`);
});
```

### 2.3 Add TypeScript Config
```json
// fina-simulator/tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}
```

### 2.4 Add Scripts
```json
// Update fina-simulator/package.json scripts section
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js"
  }
}
```

---

## Step 3: Docker Compose Setup

Create `docker-compose.yml` in repository root:

```yaml
version: '3.8'

services:
  fina-mock:
    build: ./fina-simulator
    ports:
      - "8449:8449"
    environment:
      - FINA_PORT=8449
      - CHAOS_MODE=${CHAOS_MODE:-off}
      - RESPONSE_DELAY=${RESPONSE_DELAY:-100}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8449/FiskalizacijaService/status"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Add more services as implemented
  # porezna-mock:
  #   build: ./porezna-simulator
  #   ports:
  #     - "8450:8450"
```

Add Dockerfile for FINA:
```dockerfile
# fina-simulator/Dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
CMD ["node", "dist/server.js"]
```

---

## Step 4: Environment Configuration

Create `.env.example`:
```bash
# Service Configuration
FINA_PORT=8449
POREZNA_PORT=8450

# Chaos Engineering
CHAOS_MODE=off           # off|light|moderate|extreme
RESPONSE_DELAY=100        # milliseconds
ERROR_RATE=0.05          # 5% error rate

# Feature Flags
VALIDATE_CERTIFICATES=false
REQUIRE_AUTH=false
```

---

## Step 5: Integration with Main Services

### 5.1 Update Service Configuration

In your main eRačun services, update configuration:

```typescript
// services/fina-connector/src/config.ts
export const config = {
  fina: {
    endpoint: process.env.FINA_USE_MOCK === 'true'
      ? process.env.FINA_MOCK_URL || 'http://localhost:8449'
      : process.env.FINA_REAL_URL || 'https://cis.porezna-uprava.hr:8449',
    timeout: 5000,
    retries: 3
  }
};
```

### 5.2 Add to Development .env
```bash
# services/fina-connector/.env.development
FINA_USE_MOCK=true
FINA_MOCK_URL=http://localhost:8449
```

---

## Step 6: Testing the Mock

### 6.1 Start the Mock Service
```bash
cd ~/PycharmProjects/eracun-mocks
docker-compose up fina-mock

# Or without Docker:
cd fina-simulator
npm run dev
```

### 6.2 Test with Sample Request
```bash
# Test health endpoint
curl http://localhost:8449/FiskalizacijaService/status

# Test fiscalization (sample XML)
curl -X POST http://localhost:8449/FiskalizacijaService \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<RacunZahtjev xmlns="http://www.apis-it.hr/fin/2012/types/f73">
  <Zaglavlje>
    <IdPoruke>550e8400-e29b-41d4-a716-446655440000</IdPoruke>
    <DatumVrijeme>2025-11-15T10:00:00Z</DatumVrijeme>
  </Zaglavlje>
  <Racun>
    <Oib>12345678901</Oib>
    <USustPdv>true</USustPdv>
    <DatVrijeme>2025-11-15T09:30:00Z</DatVrijeme>
    <OznSlijed>P</OznSlijed>
    <BrRac>
      <BrOznRac>1</BrOznRac>
      <OznPosPr>POS1</OznPosPr>
      <OznNapUr>1</OznNapUr>
    </BrRac>
    <IznosUkupno>125.00</IznosUkupno>
  </Racun>
</RacunZahtjev>'
```

---

## Step 7: Add Chaos Testing

### 7.1 Enable Chaos Mode
```bash
# Light chaos (occasional delays)
export CHAOS_MODE=light
export RESPONSE_DELAY=500

# Extreme chaos (frequent failures)
export CHAOS_MODE=extreme
export ERROR_RATE=0.3

docker-compose up fina-mock
```

### 7.2 Test Resilience
```bash
# Run your service tests with chaos enabled
cd ~/PycharmProjects/eRačun/services/fina-connector
FINA_USE_MOCK=true npm test

# Should see retries, circuit breaker activation
```

---

## Step 8: Contract Validation

### 8.1 Add Contract Tests
```typescript
// fina-simulator/tests/contract.test.ts
import { validate } from 'openapi-validator';
import { spec } from '../contracts/fina-api.yaml';

describe('FINA Mock Contract', () => {
  it('should match OpenAPI specification', async () => {
    const response = await fetch('http://localhost:8449/FiskalizacijaService/status');
    expect(validate(response, spec)).toBe(true);
  });
});
```

---

## Next Steps for Teams

### For Service Developers
1. Point your service to mock endpoints
2. Run integration tests against mocks
3. Report any behavior discrepancies
4. Contribute test data

### For DevOps Team
1. Deploy mock infrastructure to staging
2. Set up monitoring for mock services
3. Configure CI to use mocks
4. Plan production migration

### For QA Team
1. Use chaos modes for resilience testing
2. Validate error handling
3. Test timeout scenarios
4. Verify retry logic

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Mock not responding | Check `docker-compose logs fina-mock` |
| Wrong response format | Verify contract in `contracts/` folder |
| Chaos too aggressive | Reduce `CHAOS_MODE` to `light` |
| Certificate errors | Mock doesn't validate certs by default |

---

## Contact

- **Repository:** `github.com/eracun/eracun-mocks` (to be created)
- **Slack:** #eracun-mocks
- **Owner:** Platform Team

---

**Created:** 2025-11-15
**Version:** 1.0.0