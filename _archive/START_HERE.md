# START HERE — eRačun MVP Migration

## What Is This?

We are collapsing 31 microservices into a **single modular monolith**. The existing codebase has RabbitMQ, Kafka, gRPC, OpenTelemetry, circuit breakers, and distributed tracing — all massively over-engineered for one company's invoices.

**Your job:** Build a clean monolith by extracting working business logic from the old services. Do NOT rewrite business logic. Copy it, strip infrastructure, done.

**Deadline:** Croatian Fiskalizacija 2.0 compliance by **January 1, 2026**.

---

## Rules

1. **Every phase has binary pass/fail verification tests.** If a test fails, fix it before moving on.
2. **Copy working code, don't rewrite it.** The source files are listed with exact line numbers.
3. **No infrastructure gold-plating.** No message buses, no distributed tracing, no gRPC, no circuit breakers.
4. **Banned dependencies** (must NEVER appear in `package.json`):
   - `amqplib` (RabbitMQ)
   - `kafkajs` (Kafka)
   - `@grpc/grpc-js` or `@grpc/proto-loader` (gRPC)
   - `opossum` (circuit breaker)
   - `@opentelemetry/*` (distributed tracing)
   - `prom-client` (Prometheus metrics)
   - `inversify` (DI container)

---

## Dependency Graph (Execution Order)

```
Phase 0 (Scaffold)
  └── Phase 1 (Shared Foundation)
        ├── Phase 2 (OIB Validator)        ─┐
        ├── Phase 3 (Signing Module)        │ Can run in PARALLEL
        ├── Phase 4 (FINA Client)           │
        └── Phase 7 (Archive/DB)           ─┘
              │
              ├── Phase 5 (REST API)        ── depends on Phase 7
              │
              └── Phase 6 (Job Pipeline)    ── depends on 2, 3, 4, 7
                    │
                    └── Phase 8 (Email)     ── depends on Phase 6
                          │
                          └── Phase 9 (Delete Old Code)
                                │
                                └── Phase 10 (Integration Tests)
                                      │
                                      └── Phase 11 (Deployment)
```

**Phases 2, 3, 4, 7 can run in parallel** after Phase 1 is done.

---

## Target Directory Structure

```
eRacun-SU/
├── src/
│   ├── api/
│   │   ├── app.ts                    # Express setup (Phase 5)
│   │   ├── schemas.ts                # Zod schemas (Phase 5)
│   │   ├── routes/
│   │   │   ├── health.ts             # GET /health (Phase 5)
│   │   │   └── invoices.ts           # POST/GET invoices (Phase 5)
│   │   └── middleware/
│   │       └── validate.ts           # Zod validation middleware (Phase 5)
│   ├── validation/
│   │   └── oib-validator.ts          # OIB validation (Phase 2)
│   ├── signing/
│   │   ├── index.ts                  # Re-exports (Phase 3)
│   │   ├── xmldsig-signer.ts         # XML signing (Phase 3)
│   │   ├── certificate-parser.ts     # PKCS#12 parsing (Phase 3)
│   │   └── zki-generator.ts          # ZKI code generation (Phase 3)
│   ├── fina/
│   │   ├── index.ts                  # Re-exports (Phase 4)
│   │   ├── types.ts                  # FINA types (Phase 4)
│   │   ├── soap-envelope-builder.ts  # SOAP XML builder (Phase 4)
│   │   └── fina-client.ts            # SOAP client (Phase 4)
│   ├── ingestion/
│   │   ├── imap-client.ts            # IMAP connection (Phase 8)
│   │   ├── attachment-extractor.ts   # Email attachment parsing (Phase 8)
│   │   └── email-poller.ts           # Poll + enqueue jobs (Phase 8)
│   ├── archive/
│   │   ├── index.ts                  # Re-exports (Phase 7)
│   │   ├── schema.sql                # DB migration (Phase 7)
│   │   └── invoice-repository.ts     # CRUD operations (Phase 7)
│   ├── jobs/
│   │   ├── queue.ts                  # BullMQ setup (Phase 6)
│   │   ├── process-invoice.ts        # Invoice pipeline worker (Phase 6)
│   │   └── email-poll.ts             # Repeatable email poll job (Phase 6)
│   ├── shared/
│   │   ├── logger.ts                 # Pino JSON logger (Phase 1)
│   │   ├── config.ts                 # Zod-validated env config (Phase 1)
│   │   ├── db.ts                     # PostgreSQL pool (Phase 1)
│   │   └── types.ts                  # Domain types (Phase 1)
│   └── index.ts                      # App entry point (Phase 5)
├── tests/
│   ├── unit/
│   │   ├── oib-validator.test.ts
│   │   ├── signing/
│   │   ├── fina/
│   │   ├── api/
│   │   └── archive/
│   ├── integration/
│   │   ├── full-pipeline.test.ts     # Phase 10
│   │   └── fina-test-endpoint.test.ts # Phase 10
│   └── fixtures/
│       ├── test-cert.p12             # Phase 3
│       └── sample-invoice.json       # Phase 10
├── docs/
│   └── standards/                    # KEEP existing UBL XSD files
├── deployment/
│   └── systemd/
│       └── eracun.service            # Phase 11
├── scripts/
│   ├── deploy.sh                     # Phase 11
│   └── setup-db.sh                   # Phase 11
├── package.json
├── tsconfig.json
├── jest.config.ts
├── .eslintrc.json
├── .env.example
└── CLAUDE.md
```

---

# PHASE 0: Project Scaffolding

## What to do

Create the monolith project skeleton. No business logic yet — just build tooling and directory structure.

### Step 0.1 — `package.json`

Create at project root. These dependencies and NO others (besides dev tooling):

```json
{
  "name": "eracun-mvp",
  "version": "1.0.0",
  "description": "eRačun MVP - Croatian e-invoice compliance",
  "main": "dist/index.js",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "test": "jest",
    "test:unit": "jest tests/unit/",
    "test:integration": "jest tests/integration/",
    "lint": "eslint src/ --ext .ts",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "express": "^4.21.0",
    "pg": "^8.13.0",
    "bullmq": "^5.20.0",
    "ioredis": "^5.4.0",
    "xml-crypto": "^6.0.0",
    "node-forge": "^1.3.1",
    "xml2js": "^0.6.2",
    "fast-xml-parser": "^4.5.0",
    "soap": "^1.1.0",
    "imap": "^0.8.19",
    "mailparser": "^3.7.0",
    "pino": "^9.5.0",
    "zod": "^3.23.0",
    "dotenv": "^16.4.0",
    "uuid": "^10.0.0"
  },
  "devDependencies": {
    "@types/express": "^5.0.0",
    "@types/node": "^22.0.0",
    "@types/pg": "^8.11.0",
    "@types/xml2js": "^0.4.14",
    "@types/imap": "^0.8.40",
    "@types/mailparser": "^3.4.5",
    "@types/uuid": "^10.0.0",
    "@types/node-forge": "^1.3.11",
    "@types/jest": "^29.5.0",
    "typescript": "^5.6.0",
    "tsx": "^4.19.0",
    "ts-jest": "^29.2.0",
    "jest": "^29.7.0",
    "eslint": "^8.57.0",
    "@typescript-eslint/eslint-plugin": "^7.0.0",
    "@typescript-eslint/parser": "^7.0.0"
  }
}
```

### Step 0.2 — `tsconfig.json`

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### Step 0.3 — `jest.config.ts`

```ts
import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: ['src/**/*.ts', '!src/index.ts'],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }],
  },
};

export default config;
```

### Step 0.4 — `.eslintrc.json`

```json
{
  "parser": "@typescript-eslint/parser",
  "plugins": ["@typescript-eslint"],
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended"
  ],
  "parserOptions": {
    "ecmaVersion": 2022,
    "sourceType": "module"
  },
  "rules": {
    "@typescript-eslint/no-explicit-any": "warn",
    "@typescript-eslint/explicit-function-return-type": "off",
    "no-console": "warn"
  },
  "env": {
    "node": true,
    "jest": true
  }
}
```

### Step 0.5 — `.env.example`

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/eracun

# Redis
REDIS_URL=redis://localhost:6379

# FINA
FINA_WSDL_URL=https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl
FINA_CERT_PATH=./certs/fina.p12
FINA_CERT_PASSPHRASE=

# Email
IMAP_HOST=
IMAP_PORT=993
IMAP_USER=
IMAP_PASS=

# App
PORT=3000
LOG_LEVEL=info
NODE_ENV=development
```

### Step 0.6 — Create all directories

```bash
mkdir -p src/{api/routes,api/middleware,validation,signing,fina,ingestion,archive,jobs,shared}
mkdir -p tests/{unit/signing,unit/fina,unit/api,unit/archive,integration,fixtures}
```

### Step 0.7 — Placeholder files

Create empty `index.ts` files so TypeScript compiles:

- `src/shared/config.ts` — put a minimal `export {}` for now (will be implemented in Phase 1)
- `src/index.ts` — put `console.log('eRačun MVP');`

## Phase 0 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 0.1 | TypeScript compiles | `npx tsc --noEmit` | Exit code 0 |
| 0.2 | Jest runs | `npx jest --passWithNoTests` | Exit code 0 |
| 0.3 | Lint passes | `npx eslint src/ --ext .ts` | Exit code 0 |
| 0.4 | No banned deps | `grep -E "amqplib\|kafkajs\|@grpc\|inversify\|opossum\|@opentelemetry" package.json` | Zero matches |
| 0.5 | Dirs exist | `ls src/api src/validation src/signing src/fina src/ingestion src/archive src/jobs src/shared` | All exist |

---

# PHASE 1: Shared Foundation

## Depends on: Phase 0

### File 1.1 — `src/shared/logger.ts`

Create a Pino logger with JSON output:

```ts
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport:
    process.env.NODE_ENV === 'development'
      ? { target: 'pino-pretty', options: { colorize: true } }
      : undefined,
});
```

That's it. No Prometheus, no OpenTelemetry, no custom transports.

### File 1.2 — `src/shared/config.ts`

Use Zod to validate env vars on startup. If any required var is missing, **crash immediately** with a clear error:

```ts
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const configSchema = z.object({
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  FINA_WSDL_URL: z.string().url(),
  FINA_CERT_PATH: z.string().min(1),
  FINA_CERT_PASSPHRASE: z.string().default(''),
  IMAP_HOST: z.string().default(''),
  IMAP_PORT: z.coerce.number().default(993),
  IMAP_USER: z.string().default(''),
  IMAP_PASS: z.string().default(''),
  PORT: z.coerce.number().default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

export type Config = z.infer<typeof configSchema>;

export function loadConfig(): Config {
  const result = configSchema.safeParse(process.env);
  if (!result.success) {
    const formatted = result.error.issues
      .map((i) => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${formatted}`);
  }
  return result.data;
}

export const config = loadConfig();
```

### File 1.3 — `src/shared/db.ts`

PostgreSQL connection pool. Pool size 10. Export `query()` and `getClient()`:

```ts
import { Pool, PoolClient, QueryResult } from 'pg';
import { config } from './config.js';
import { logger } from './logger.js';

const pool = new Pool({
  connectionString: config.DATABASE_URL,
  max: 10,
});

pool.on('error', (err) => {
  logger.error({ err }, 'Unexpected PostgreSQL pool error');
});

export async function query(text: string, params?: unknown[]): Promise<QueryResult> {
  return pool.query(text, params);
}

export async function getClient(): Promise<PoolClient> {
  return pool.connect();
}

export { pool };
```

### File 1.4 — `src/shared/types.ts`

Core domain types. **Copy the FINA types from the source** and add internal types.

**Source to copy (verbatim, lines 1–145):**
`services/fina-connector/src/types.ts`

Copy these interfaces exactly:
- `FINAInvoice` (lines 10–39)
- `FINAVATBreakdown` (lines 44–51)
- `FINANonTaxable` (lines 56–63)
- `FINAOtherTaxes` (lines 68–75)
- `FINAFiscalizationRequest` (lines 80–85)
- `FINAFiscalizationResponse` (lines 90–99)
- `FINAError` (lines 104–111)
- `FINAEchoRequest` (lines 116–119)
- `FINAEchoResponse` (lines 124–127)
- `FINAValidationRequest` (lines 132–135)
- `FINAValidationResponse` (lines 140–145)

**DO NOT copy** these (they are RabbitMQ-specific):
- `OfflineQueueEntry` (lines 150–167)
- `FiscalizationMessage` (lines 172–183)
- `FiscalizationResultMessage` (lines 188–203)

**Add these new types** (internal domain model):

```ts
export interface Invoice {
  id: string;
  oib: string;
  invoiceNumber: string;
  originalXml: string;
  signedXml: string;
  jir?: string;
  finaResponse?: Record<string, unknown>;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  submittedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface ArchiveRecord {
  invoiceId: string;
  oib: string;
  invoiceNumber: string;
  jir: string;
  archivedAt: Date;
}

export interface JobPayload {
  invoiceId: string;
  oib: string;
  invoiceData: Record<string, unknown>;
}
```

## Phase 1 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 1.1 | Config loads | Unit test: set env vars, call `loadConfig()`, returns valid object | Pass |
| 1.2 | Config rejects missing | Unit test: unset `DATABASE_URL`, `loadConfig()` throws with field name | Pass |
| 1.3 | Logger outputs JSON | `logger.info({invoice: '123'}, 'test')` stdout contains JSON with `msg`, `level`, `invoice` | Pass |
| 1.4 | DB pool connects | Integration test: `pool.query('SELECT 1')` returns `{ rows: [{?column?: 1}] }` | Pass (requires PostgreSQL) |
| 1.5 | Types compile | `npx tsc --noEmit` | Exit code 0 |
| 1.6 | No infra imports | `grep -rn "amqplib\|kafkajs\|@grpc\|rabbitmq\|kafka" src/shared/` | Zero matches |

---

# PHASE 2: OIB Validator

## Depends on: Phase 1

### File 2.1 — `src/validation/oib-validator.ts`

**Copy the entire file verbatim (all 257 lines):**

**Source:** `services/oib-validator/src/oib-validator.ts`

This file is a pure algorithm module with **zero external imports**. No modifications needed. It exports:
- `OIBValidationResult` (interface)
- `validateOIBFormat(oib: string): string[]`
- `validateOIBChecksum(oib: string): boolean`
- `determineOIBType(oib: string): 'business' | 'personal' | 'unknown'`
- `validateOIB(oib: string): OIBValidationResult`
- `validateOIBBatch(oibs: string[]): OIBValidationResult[]`
- `generateValidOIB(prefix?: string): string`

Just copy it. Don't touch the logic.

## Phase 2 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 2.1 | Valid OIB accepted | `validateOIB` with a valid OIB | `{ valid: true, errors: [] }` |
| 2.2 | Invalid checksum | `validateOIB('12345678901')` | `{ valid: false }` with checksum error |
| 2.3 | Wrong length | `validateOIB('123')` | `{ valid: false }` with length error |
| 2.4 | Empty rejected | `validateOIB('')` | `{ valid: false, errors: ['OIB is required'] }` |
| 2.5 | Non-numeric | `validateOIB('abcdefghijk')` | `{ valid: false }` with digits error |
| 2.6 | Batch works | `validateOIBBatch` with 2 OIBs | Array of 2 results |
| 2.7 | Generator valid | `generateValidOIB()` then `validateOIB()` on result | `{ valid: true }` |
| 2.8 | Zero deps | `grep -c "^import" src/validation/oib-validator.ts` | 0 |

---

# PHASE 3: XMLDSig Signing Module

## Depends on: Phase 1

You are extracting 3 files from `services/digital-signature-service/src/`. For each one, you must **remove all observability infrastructure** and replace with simple Pino logger calls.

### What to remove from ALL THREE files

Delete every occurrence of:
```ts
// DELETE these imports
import { createSpan, setSpanError, endSpanSuccess, ... } from './observability.js';
import { signatureTotal, signatureDuration, signatureErrors, ... } from './observability.js';

// DELETE all spans
const span = createSpan('...');
endSpanSuccess(span);
setSpanError(span, error);
span.end();

// DELETE all metrics
signatureTotal.inc({ ... });
signatureDuration.observe({ ... });
signatureErrors.inc({ ... });
```

Replace with:
```ts
import { logger } from '../shared/logger.js';
```

And use `logger.info(...)` / `logger.error(...)` where the old code had metric calls.

### File 3.1 — `src/signing/xmldsig-signer.ts`

**Source:** `services/digital-signature-service/src/xmldsig-signer.ts` (292 lines)

**Keep exactly:**
- `SignatureOptions` interface
- `DEFAULT_SIGNATURE_OPTIONS` constant
- `XMLSignatureError` class
- `signXMLDocument()` function — core `xml-crypto` SignedXml logic
- `signUBLInvoice()` function
- `createDetachedSignature()` function

**Change:**
- Import path: `'./observability.js'` → `'../shared/logger.js'`
- Import path: `'./certificate-parser.js'` → `'./certificate-parser.js'` (same — they're in the same directory now)
- Remove all `createSpan`, `endSpanSuccess`, `setSpanError`, metric calls
- Replace with `logger.info`/`logger.error`

### File 3.2 — `src/signing/certificate-parser.ts`

**Source:** `services/digital-signature-service/src/certificate-parser.ts` (317 lines)

**Keep exactly:**
- `CertificateInfo` interface
- `ParsedCertificate` interface
- `CertificateParseError` class
- `CertificateValidationError` class
- `loadCertificateFromFile()` function
- `parseCertificate()` function
- `extractCertificateInfo()` function
- `validateCertificate()` function
- `assertCertificateValid()` function

**Change:**
- Same observability removal as above

### File 3.3 — `src/signing/zki-generator.ts`

**Source:** `services/digital-signature-service/src/zki-generator.ts` (309 lines)

**Keep exactly:**
- `ZKIParams` interface
- `ZKIGenerationError` class
- `validateZKIParams()` function
- `generateZKI()` function — MD5 + RSA signing
- `verifyZKI()` function
- `formatZKI()` function

**Change:**
- Import path: `'./certificate-parser.js'` stays the same
- Same observability removal

### File 3.4 — `src/signing/index.ts`

```ts
export { signXMLDocument, signUBLInvoice, createDetachedSignature, XMLSignatureError, DEFAULT_SIGNATURE_OPTIONS } from './xmldsig-signer.js';
export type { SignatureOptions } from './xmldsig-signer.js';
export { loadCertificateFromFile, parseCertificate, extractCertificateInfo, validateCertificate, assertCertificateValid, CertificateParseError, CertificateValidationError } from './certificate-parser.js';
export type { CertificateInfo, ParsedCertificate } from './certificate-parser.js';
export { generateZKI, verifyZKI, formatZKI, validateZKIParams, ZKIGenerationError } from './zki-generator.js';
export type { ZKIParams } from './zki-generator.js';
```

### Test Certificate

Generate a self-signed test certificate for unit tests:

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/test-key.pem -out /tmp/test-cert.pem \
  -days 365 -nodes -subj "/CN=Test"
openssl pkcs12 -export -out tests/fixtures/test-cert.p12 \
  -inkey /tmp/test-key.pem -in /tmp/test-cert.pem -passout pass:test123
rm /tmp/test-key.pem /tmp/test-cert.pem
```

## Phase 3 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 3.1 | Sign XML | Load test cert, call `signXMLDocument('<Invoice>test</Invoice>', cert)` | Returns XML with `<ds:Signature>` |
| 3.2 | Valid XML | Parse output with `xml2js` | No parse error |
| 3.3 | Required elements | Check for `<ds:SignedInfo>`, `<ds:SignatureValue>`, `<ds:Reference>` | All present |
| 3.4 | Parse PKCS#12 | `parseCertificate(fs.readFileSync('tests/fixtures/test-cert.p12'), 'test123')` | Returns `{ privateKeyPEM, certificatePEM, ... }` |
| 3.5 | Bad passphrase | `parseCertificate(certBuffer, 'wrong')` | Throws error |
| 3.6 | ZKI generation | `generateZKI(params, cert)` with known inputs | Returns 32-char hex string |
| 3.7 | ZKI deterministic | Call `generateZKI` twice, same inputs | Identical output |
| 3.8 | No observability | `grep -rn "opentelemetry\|prom-client\|createSpan\|signatureTotal" src/signing/` | Zero matches |
| 3.9 | Compiles | `npx tsc --noEmit` | Exit code 0 |

---

# PHASE 4: SOAP Envelope Builder + FINA Client

## Depends on: Phase 1

### File 4.1 — `src/fina/types.ts`

**Source:** `services/fina-connector/src/types.ts`, lines 1–145 ONLY.

Copy these interfaces verbatim:
- `FINAInvoice` (lines 10–39)
- `FINAVATBreakdown` (lines 44–51)
- `FINANonTaxable` (lines 56–63)
- `FINAOtherTaxes` (lines 68–75)
- `FINAFiscalizationRequest` (lines 80–85)
- `FINAFiscalizationResponse` (lines 90–99)
- `FINAError` (lines 104–111)
- `FINAEchoRequest` (lines 116–119)
- `FINAEchoResponse` (lines 124–127)
- `FINAValidationRequest` (lines 132–135)
- `FINAValidationResponse` (lines 140–145)

**DO NOT copy** lines 147–204 (`OfflineQueueEntry`, `FiscalizationMessage`, `FiscalizationResultMessage`).

### File 4.2 — `src/fina/soap-envelope-builder.ts`

**Source:** `services/fina-connector/src/soap-envelope-builder.ts` — ENTIRE FILE (251 lines)

This is already a pure module with **zero infrastructure deps**. The only change:

```diff
- import type { FINAInvoice, FINAVATBreakdown, FINANonTaxable, FINAOtherTaxes } from './types.js';
+ import type { FINAInvoice, FINAVATBreakdown, FINANonTaxable, FINAOtherTaxes } from './types.js';
```

Import path is the same since types.ts is in the same directory. **Copy verbatim. Do not modify any logic.**

The file exports:
- `SOAPEnvelopeBuilder` class with methods: `buildRacuniRequest()`, `buildProveraRequest()`, `buildEchoRequest()`
- `createSOAPEnvelopeBuilder()` factory function
- Private methods: `escapeXML()` (XML injection prevention), `validateRequiredFields()`

### File 4.3 — `src/fina/fina-client.ts`

**This is a SIMPLIFIED REWRITE** of `services/fina-connector/src/soap-client.ts` (859 lines → ~200 lines).

You are building a simplified FINA SOAP client. Use the source file for reference but strip out:
- Circuit breakers (all `opossum` usage, `CircuitBreaker` class fields, `*Internal` methods)
- Shared HTTP client pooling (`getOrCreateSharedHttpClient`, `buildHttpClientSignature`)
- WSDL cache refresh logic (`refreshWSDLCache`, `wsdlCacheExpireAt`, etc.)
- All OpenTelemetry spans (`createSpan`, `endSpanSuccess`, `setSpanError`)
- All Prometheus metrics (`fiscalizationTotal`, `fiscalizationDuration`, `finaErrors`, `wsdlCacheHealth`)

**Keep (copy verbatim from source):**
- `SOAPClientConfig` interface (lines 134–149) — but remove `wsdlRefreshIntervalHours` and `wsdlRequestTimeoutMs` fields
- `FINASOAPError` class (lines 154–163)
- `ensureInitialized()` method (lines 277–284)
- `buildInvoiceXML()` method (lines 527–561)
- `parseRacuniResponse()` method (lines 569–631) — verbatim, just change `logger` import
- `parseSoapFault()` method (lines 672–716) — verbatim, just change `logger` import
- `loadTlsMaterial()` function (lines 102–129)
- `createHttpsAgent()` function (lines 74–100) — simplified, remove shared client logic

**Build new simplified versions of:**
- `initialize()` — just `soap.createClientAsync()`, no WSDL cache refresh
- `fiscalizeInvoice()` — direct call (no circuit breaker), with simple retry (3 attempts, 1s/2s/4s backoff)
- `echo()` — direct call, no circuit breaker
- `close()` — cleanup

**Simple retry pattern to use (inline, not a library):**

```ts
async function withRetry<T>(fn: () => Promise<T>, maxAttempts = 3): Promise<T> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (attempt === maxAttempts) throw error;
      const delay = Math.pow(2, attempt - 1) * 1000; // 1s, 2s, 4s
      logger.warn({ attempt, maxAttempts, delay }, 'Retrying after failure');
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}
```

### File 4.4 — `src/fina/index.ts`

```ts
export { SOAPEnvelopeBuilder, createSOAPEnvelopeBuilder } from './soap-envelope-builder.js';
export { FINASOAPClient, FINASOAPError, createFINAClient } from './fina-client.js';
export type { SOAPClientConfig } from './fina-client.js';
export type * from './types.js';
```

## Phase 4 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 4.1 | Build SOAP envelope | `new SOAPEnvelopeBuilder().buildRacuniRequest(testInvoice)` | Valid XML with `<soap:Envelope>`, `<tns:RacunZahtjev>`, `<tns:Oib>` |
| 4.2 | Missing field | `buildRacuniRequest({})` | Throws `Error: Required field missing: oib` |
| 4.3 | XML escaping | Input `oib: '<script>'` | Output contains `&lt;script&gt;` |
| 4.4 | VAT breakdown | Input with `pdv: [{ porez: '100', stopa: '25.00', iznos: '25.00' }]` | XML contains `<tns:Pdv>` section |
| 4.5 | Echo request | `buildEchoRequest()` | XML with `<tns:Echo>` |
| 4.6 | Client init | Mock `soap.createClientAsync`, call `initialize()` | Resolves |
| 4.7 | Parse success | `parseRacuniResponse([{ Jir: 'abc-123' }])` | `{ success: true, jir: 'abc-123' }` |
| 4.8 | Parse error | `parseRacuniResponse([{ Greska: { SifraGreske: 's:001', PorukaGreske: 'err' } }])` | `{ success: false, error: { code: 's:001' } }` |
| 4.9 | Parse empty | `parseRacuniResponse([])` or `null` | `{ success: false, error: { code: 'EMPTY_RESPONSE' } }` |
| 4.10 | No banned deps | `grep -rn "opossum\|@opentelemetry\|prom-client\|amqplib" src/fina/` | Zero matches |

---

# PHASE 5: REST API Layer

## Depends on: Phase 7 (archive repository)

### File 5.1 — `src/api/app.ts`

Express app with:
- `express.json({ limit: '10mb' })` — body parser
- Request ID middleware: generate UUID, set `X-Request-ID` response header
- Error handler middleware: catch-all, log with Pino, return `{ error: "Internal Server Error" }` (never expose stack traces)
- Mount routes from `routes/health.ts` and `routes/invoices.ts`

### File 5.2 — `src/api/routes/health.ts`

```
GET /health          → { status: 'ok', timestamp: ISO string, version: '1.0.0' }
GET /health/db       → Run SELECT 1 on PostgreSQL, return { status: 'ok' } or { status: 'error', message }
```

### File 5.3 — `src/api/routes/invoices.ts`

```
POST /api/v1/invoices         → Validate body (Zod), enqueue BullMQ job, return 202 { jobId, status: 'queued' }
GET  /api/v1/invoices/:id     → Fetch from archive by UUID, return 200 or 404
GET  /api/v1/invoices/:id/status → Return processing status { status: 'queued'|'processing'|'completed'|'failed' }
```

### File 5.4 — `src/api/middleware/validate.ts`

Generic Zod validation middleware. Takes a Zod schema, returns 400 with validation errors if body doesn't match.

### File 5.5 — `src/api/schemas.ts`

Zod schema for invoice submission. Required fields: `oib`, `invoiceNumber`, `amount`, `paymentMethod`, `businessPremises`, `cashRegister`, `dateTime`. Validate OIB is 11 digits, amount is positive number string, paymentMethod is one of G/K/C/T/O.

### File 5.6 — `src/index.ts`

Application entry point:
1. Load config (crash if invalid)
2. Connect DB pool
3. Create Express app
4. Start BullMQ workers (Phase 6)
5. Start HTTP server on configured port
6. Log "eRačun MVP listening on port XXXX"

## Phase 5 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 5.1 | Health check | `curl localhost:3000/health` | `200 { "status": "ok" }` |
| 5.2 | DB health | `curl localhost:3000/health/db` | `200 { "status": "ok" }` |
| 5.3 | Submit invoice | `POST /api/v1/invoices` with valid body | `202 { "jobId": "...", "status": "queued" }` |
| 5.4 | Invalid body | `POST /api/v1/invoices` with `{}` | `400` with Zod errors |
| 5.5 | Request ID | `curl -v /health` | `X-Request-ID` header present |
| 5.6 | Large payload | `POST` with >10MB body | `413` |
| 5.7 | 404 missing | `GET /api/v1/invoices/nonexistent` | `404` |
| 5.8 | Error handler | Unhandled error in route | JSON `{ error }`, no stack trace |
| 5.9 | Tests pass | `npx jest tests/unit/api/` | Exit code 0 |

---

# PHASE 6: Invoice Processing Pipeline (BullMQ)

## Depends on: Phase 2, 3, 4, 7

### File 6.1 — `src/jobs/queue.ts`

BullMQ queue setup:
- Queue name: `invoice-processing`
- Connection: Redis from config
- Default job options: `{ attempts: 3, backoff: { type: 'exponential', delay: 1000 } }`

### File 6.2 — `src/jobs/process-invoice.ts`

BullMQ Worker that processes an invoice through the full pipeline:

```
Step 1 (0%):   Validate OIB         → src/validation/oib-validator.ts
Step 2 (16%):  Build UBL XML        → wrap invoice data in minimal UBL Invoice envelope
Step 3 (33%):  Generate ZKI         → src/signing/zki-generator.ts
Step 4 (50%):  Sign XML (XMLDSig)   → src/signing/xmldsig-signer.ts
Step 5 (66%):  Build SOAP envelope  → src/fina/soap-envelope-builder.ts
Step 6 (83%):  Submit to FINA       → src/fina/fina-client.ts
Step 7 (100%): Archive result       → src/archive/invoice-repository.ts
```

Each step updates `job.updateProgress()`. On failure at any step, fail with step name and error.

### File 6.3 — `src/jobs/email-poll.ts`

Repeatable BullMQ job that:
- Polls IMAP mailbox (using `src/ingestion/` from Phase 8)
- Runs every 5 minutes (configurable via env)
- For each email with XML attachment: creates a `process-invoice` job

## Phase 6 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 6.1 | Valid invoice completes | Enqueue job with valid data + test FINA endpoint | Job status = `completed`, result has `jir` |
| 6.2 | Invalid OIB fails | Enqueue with bad OIB | Job fails at step 1, `OIB validation failed` |
| 6.3 | FINA error fails | Mock FINA to error | Job fails at step 6 with FINA error code |
| 6.4 | Progress updates | Listen for progress events | Receives 0%, 16%, 33%, 50%, 66%, 83%, 100% |
| 6.5 | Retry on transient | Mock FINA to fail once then succeed | Job completes on retry |
| 6.6 | Error details | Check failed job's `failedReason` | Contains step name + error message |

---

# PHASE 7: Invoice Archive (PostgreSQL)

## Depends on: Phase 1

### File 7.1 — `src/archive/schema.sql`

```sql
CREATE TABLE IF NOT EXISTS invoices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  oib VARCHAR(11) NOT NULL,
  invoice_number VARCHAR(100) NOT NULL,
  original_xml TEXT NOT NULL,
  signed_xml TEXT NOT NULL,
  jir VARCHAR(100),
  fina_response JSONB,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  submitted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT valid_oib CHECK (length(oib) = 11),
  CONSTRAINT valid_status CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_invoices_oib ON invoices(oib);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_created_at ON invoices(created_at);
```

### File 7.2 — `src/archive/invoice-repository.ts`

Repository functions. **ALL queries MUST use parameterized statements (`$1`, `$2`, etc.). ZERO string interpolation in SQL.** This is a hard security requirement.

```ts
import { query } from '../shared/db.js';
import type { Invoice } from '../shared/types.js';

export async function createInvoice(data: {
  oib: string;
  invoiceNumber: string;
  originalXml: string;
  signedXml: string;
}): Promise<Invoice> {
  const result = await query(
    `INSERT INTO invoices (oib, invoice_number, original_xml, signed_xml)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [data.oib, data.invoiceNumber, data.originalXml, data.signedXml]
  );
  return result.rows[0];
}

export async function updateInvoiceStatus(
  id: string,
  status: string,
  jir?: string,
  finaResponse?: Record<string, unknown>
): Promise<void> {
  await query(
    `UPDATE invoices
     SET status = $1, jir = $2, fina_response = $3, updated_at = NOW(),
         submitted_at = CASE WHEN $1 = 'completed' THEN NOW() ELSE submitted_at END
     WHERE id = $4`,
    [status, jir || null, finaResponse ? JSON.stringify(finaResponse) : null, id]
  );
}

export async function getInvoiceById(id: string): Promise<Invoice | null> {
  const result = await query('SELECT * FROM invoices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

export async function getInvoicesByOIB(
  oib: string,
  limit = 50,
  offset = 0
): Promise<Invoice[]> {
  const result = await query(
    'SELECT * FROM invoices WHERE oib = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
    [oib, limit, offset]
  );
  return result.rows;
}
```

### File 7.3 — `src/archive/index.ts`

```ts
export { createInvoice, updateInvoiceStatus, getInvoiceById, getInvoicesByOIB } from './invoice-repository.js';
```

## Phase 7 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 7.1 | Schema applies | `psql $DATABASE_URL -f src/archive/schema.sql` | Exit code 0 |
| 7.2 | Insert invoice | `createInvoice(...)` | Returns row with UUID `id` |
| 7.3 | Update status | `updateInvoiceStatus(id, 'completed', 'JIR-123')` | Row updated |
| 7.4 | Query by ID | `getInvoiceById(id)` | Returns the row |
| 7.5 | Query by OIB | `getInvoicesByOIB('12345678903')` | Array of matching rows |
| 7.6 | Invalid OIB rejected | `createInvoice({ oib: '123', ... })` | CHECK constraint error |
| 7.7 | SQL injection safe | `getInvoiceById("'; DROP TABLE invoices; --")` | Returns null, table exists |
| 7.8 | No interpolation | `grep -rn "\${" src/archive/invoice-repository.ts` | Zero matches |
| 7.9 | Uses params | `grep -c "\\$[0-9]" src/archive/invoice-repository.ts` | At least 5 matches |

---

# PHASE 8: Email Ingestion

## Depends on: Phase 6

### File 8.1 — `src/ingestion/imap-client.ts`

**Source:** `services/email-ingestion-worker/src/imap-client.ts` (475 lines)

Extract a simplified IMAP client. **Remove:**
- All `observability` imports (OpenTelemetry, Prometheus)
- RabbitMQ publisher integration

**Keep:**
- `ImapConfig` interface
- `EmailMessage` interface
- IMAP connection with TLS
- `connect()`, `disconnect()`, `searchMessages()`, `fetchMessage()`, `markAsSeen()`
- Reconnection logic

Replace observability with `logger` from `../shared/logger.js`.

### File 8.2 — `src/ingestion/attachment-extractor.ts`

**Source:** `services/email-ingestion-worker/src/attachment-extractor.ts` (758 lines)

Simplify heavily. You only need:
- Parse email with `mailparser.simpleParser()`
- Filter attachments: keep only `.xml` files (by filename extension AND content-type `text/xml` or `application/xml`)
- Reject attachments >10MB
- Return array of `{ filename: string, content: string }` for XML attachments

This can be ~80 lines instead of 758. Strip out:
- Streaming parser (use simple parser)
- Message publisher integration
- Filter options configuration
- Hash computation
- All observability

### File 8.3 — `src/ingestion/email-poller.ts`

New file. Ties together IMAP client + attachment extractor + BullMQ queue:
1. Connect to IMAP
2. Search for unseen emails
3. For each email: extract XML attachments
4. For each XML: create `process-invoice` BullMQ job
5. Mark email as seen

## Phase 8 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 8.1 | IMAP connects | Unit test with mock | Connection OK |
| 8.2 | XML extracted | Mock email with `.xml` attachment | Returns array with one XML string |
| 8.3 | Non-XML ignored | Mock email with `.pdf` | Returns empty array |
| 8.4 | Large file rejected | Mock >10MB `.xml` | Rejected |
| 8.5 | Multiple attachments | 1 XML + 1 PDF + 1 PNG | Returns 1 XML only |
| 8.6 | Email marked seen | After processing | `\Seen` flag set |
| 8.7 | No RabbitMQ | `grep -rn "amqplib\|rabbitmq" src/ingestion/` | Zero matches |

---

# PHASE 9: Delete Old Code

## Depends on: Phase 8

This is the cleanup phase. Delete everything from the old architecture.

### Delete these directories entirely

```bash
rm -rf services/           # All 31 microservices (see list below)
rm -rf mocks/              # 7 mock services + infrastructure
rm -rf shared/             # Old shared packages (replaced by src/shared/)
rm -rf deployment/rabbitmq/
rm -rf deployment/grafana/
rm -rf deployment/prometheus/
rm -rf deployment/scripts/
```

**Services being deleted (31 total):**
admin-portal-api, ai-validation-service, archive-service, attachment-handler, audit-logger, cert-lifecycle-manager, dead-letter-handler, digital-signature-service, email-ingestion-worker, file-classifier, fina-connector, health-monitor, iban-validator, invoice-gateway-api, invoice-orchestrator, kpd-registry-sync, kpd-validator, notification-service, ocr-processing-service, oib-validator, pdf-parser, porezna-connector, reporting-service, retry-scheduler, schematron-validator, sftp-ingestion-worker, ubl-transformer, validation, validation-coordinator, xml-parser, xsd-validator

**Mocks being deleted (7):**
bank-mock, cert-mock, email-mock, fina-mock, klasus-mock, mock-admin, porezna-mock

### Delete these files

```bash
rm -f docker-compose.yml
rm -f docker-compose.team3.yml
```

### Delete these root-level markdown files

```bash
rm -f AGENTS.md
rm -f ARCHITECTURE_DIAGRAMS.md
rm -f CROATIAN_COMPLIANCE.md
rm -f CURRENT_STATUS_AND_NEXT_STEPS.md
rm -f FUTURE_REPOSITORIES_STRUCTURE.md
rm -f INDEPENDENCE_VERIFICATION_REPORT.md
rm -f MIGRATION_CONTINUATION_DECISION.md
rm -f MIGRATION-STATUS.md
rm -f MIGRATION-TODO-CLARIFICATION_NEEDED.md
rm -f MIGRATION-TODO.md
rm -f MIGRATION_UNBLOCKING_ROADMAP.md
rm -f MOCK_IMPLEMENTATION_PLAN.md
rm -f MOCK_SERVICES_COMPLETION.md
rm -f PENDING.md
rm -f REPOSITORY_HAND_OFF_READINESS_AUDIT.md
rm -f REPOSITORY_INDEPENDENCE_VERIFICATION.md
rm -f REPOSITORY_INDEPENDENCE_VERIFICATION_REPORT.md
rm -f RESOURCES_NEEDED.md
rm -f SHARED_CONTRACTS.md
rm -f STAKEHOLDER_MOCK_STRATEGY_SUMMARY.md
rm -f TBD.md
rm -f TODO.md
rm -f TypeScript-TODO.md
rm -f UNBLOCKING_VERIFICATION_CHECKLIST.md
```

### Delete docs subdirectories

```bash
rm -rf docs/reports/
rm -rf docs/pending/
rm -rf docs/improvement-plans/
rm -rf docs/guides/          # EXCEPT certificate-setup-guide.md — move it first:
#   cp docs/guides/certificate-setup-guide.md docs/certificate-setup-guide.md
#   rm -rf docs/guides/
rm -rf docs/adr/
rm -rf docs/api-contracts/
rm -rf docs/architecture/
rm -rf docs/message-contracts/
rm -rf docs/research/
rm -rf docs/runbooks/
rm -rf docs/templates/
rm -rf docs/testing/
```

### Delete miscellaneous

```bash
rm -rf config/                # Old config templates
rm -rf secrets/               # Old secrets structure
rm -rf scripts/architecture-checker.ts
rm -rf scripts/independence-verification-*.txt
rm -f .lintstagedrc.json
rm -f .pre-commit-config.yaml
rm -f .prettierignore
rm -f .prettierrc
rm -f .sopsrc
```

### KEEP these files/directories

- `CLAUDE.md` — updated for MVP
- `docs/COMPLIANCE_REQUIREMENTS.md` — legal reference
- `docs/standards/` — UBL XSD files, CIUS rules (compliance reference)
- `docs/certificate-setup-guide.md` — moved from guides/
- `deployment/systemd/` — will be updated in Phase 11
- `src/` — the new monolith code
- `tests/` — the new tests
- `package.json`, `tsconfig.json`, `jest.config.ts`, `.eslintrc.json`, `.env.example`

## Phase 9 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 9.1 | No services | `ls services/ 2>&1` | "No such file or directory" |
| 9.2 | No mocks | `ls mocks/ 2>&1` | "No such file or directory" |
| 9.3 | No docker compose | `ls docker-compose*.yml 2>&1` | "No such file or directory" |
| 9.4 | Standards preserved | `ls docs/standards/UBL-2.1/maindoc/UBL-Invoice-2.1.xsd` | File exists |
| 9.5 | Compliance preserved | `ls docs/COMPLIANCE_REQUIREMENTS.md` | File exists |
| 9.6 | Still compiles | `npx tsc --noEmit` | Exit code 0 |
| 9.7 | Tests pass | `npx jest` | All pass |

---

# PHASE 10: Integration Tests

## Depends on: Phase 9

### File 10.1 — `tests/integration/full-pipeline.test.ts`

End-to-end test:
1. Create valid invoice data (use `generateValidOIB()` for a valid OIB)
2. `POST /api/v1/invoices` — expect 202
3. Poll `GET /api/v1/invoices/:id/status` until completed or failed (timeout: 30s)
4. Verify invoice archived in PostgreSQL with JIR
5. `GET /api/v1/invoices/:id` — expect 200 with completed invoice

### File 10.2 — `tests/integration/fina-test-endpoint.test.ts`

Integration test against FINA test environment (requires FINA test certificate and network access):
1. Initialize SOAP client with FINA test WSDL
2. Send echo request — verify response matches
3. Submit test invoice — verify JIR received

### File 10.3 — `tests/fixtures/sample-invoice.json`

```json
{
  "oib": "VALID_11_DIGIT_OIB",
  "invoiceNumber": "1/PP1/1",
  "amount": "1250.00",
  "paymentMethod": "T",
  "businessPremises": "PP1",
  "cashRegister": "1",
  "dateTime": "2026-01-15T10:30:00",
  "vatBreakdown": [
    { "base": "1000.00", "rate": "25.00", "amount": "250.00" }
  ]
}
```

## Phase 10 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 10.1 | Full pipeline | `npx jest tests/integration/full-pipeline.test.ts` | All assertions pass |
| 10.2 | Invoice archived | After pipeline, row in DB with `status='completed'`, `jir IS NOT NULL` | Pass |
| 10.3 | API returns result | `GET /api/v1/invoices/:id` | 200, `status: 'completed'` |
| 10.4 | FINA echo | `npx jest tests/integration/fina-test-endpoint.test.ts` | Pass (requires FINA test env) |
| 10.5 | Invalid fails cleanly | Submit with bad OIB | Status = `failed`, error describes issue |

---

# PHASE 11: Deployment Configuration

## Depends on: Phase 10

### File 11.1 — `deployment/systemd/eracun.service`

```ini
[Unit]
Description=eRačun MVP Invoice Service
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=eracun
WorkingDirectory=/opt/eracun
ExecStart=/usr/bin/node /opt/eracun/dist/index.js
Restart=on-failure
RestartSec=10s
EnvironmentFile=/etc/eracun/eracun.env

ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths=/var/log/eracun

[Install]
WantedBy=multi-user.target
```

### File 11.2 — `scripts/deploy.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

REMOTE_USER=${REMOTE_USER:-eracun}
REMOTE_HOST=${REMOTE_HOST:?Set REMOTE_HOST}
REMOTE_DIR=/opt/eracun

echo "Building..."
npm run build

echo "Deploying to $REMOTE_HOST..."
rsync -avz --delete dist/ package.json package-lock.json "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/"

echo "Installing production dependencies and restarting..."
ssh "$REMOTE_USER@$REMOTE_HOST" "cd $REMOTE_DIR && npm ci --production && sudo systemctl restart eracun"

echo "Done."
```

### File 11.3 — `scripts/setup-db.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

DATABASE_URL=${DATABASE_URL:?Set DATABASE_URL}

echo "Applying database schema..."
psql "$DATABASE_URL" -f src/archive/schema.sql

echo "Done."
```

## Phase 11 Verification

| # | Test | Command | Pass if |
|---|------|---------|---------|
| 11.1 | Build produces dist | `npm run build && ls dist/index.js` | File exists |
| 11.2 | dist runs | `node dist/index.js` (with env vars) | Logs "listening on port 3000" |
| 11.3 | systemd valid | `systemd-analyze verify deployment/systemd/eracun.service` | No errors |
| 11.4 | Deploy script syntax | `bash -n scripts/deploy.sh` | OK |

---

# Summary

| Phase | Files Created | Files Copied From Old | Files Deleted |
|-------|--------------|----------------------|---------------|
| 0 | 5 (config files) | 0 | 0 |
| 1 | 4 | 0 | 0 |
| 2 | 1 | 1 (verbatim) | 0 |
| 3 | 4 | 3 (modified - strip observability) | 0 |
| 4 | 4 | 1 verbatim + 2 modified | 0 |
| 5 | 6 | 0 | 0 |
| 6 | 3 | 0 | 0 |
| 7 | 3 | 0 | 0 |
| 8 | 3 | 2 (heavily simplified) | 0 |
| 9 | 0 | 0 | ~500+ |
| 10 | 3 | 0 | 0 |
| 11 | 3 | 0 | 0 |
| **Total** | **~39** | **~9** | **~500+** |

**Final codebase:** ~40 files, ~3,000 LOC.
**Previous codebase:** 31 services, ~30,000+ LOC.

---

**Questions?** Read `CLAUDE.md` for the project context and constraints. Read the source files referenced in each phase for exact code to copy. If a verification test fails, fix it before proceeding.
