# Protocol Buffer Schemas

**Purpose:** Type-safe message schemas for inter-service communication in the eRacun platform.

---

## Schema Files

| File | Package | Description |
|------|---------|-------------|
| `common.proto` | `eracun.v1.common` | Shared types (InvoiceId, OIB, RequestContext, Error) |
| `ingestion.proto` | `eracun.v1.ingestion` | Ingestion commands (email, API, AS4 uploads) |
| `parsing.proto` | `eracun.v1.parsing` | Parsing commands (PDF, OCR, file classification) |
| `validation.proto` | `eracun.v1.validation` | Validation commands (XSD, Schematron, KPD) |
| `events.proto` | `eracun.v1.events` | Domain events (ingested, parsed, validated, signed, submitted, archived, failed) |

---

## Generating Code

### TypeScript (for Node.js services)

```bash
# Install protoc and ts-proto plugin
npm install -D ts-proto

# Generate TypeScript types
protoc \
  --plugin=./node_modules/.bin/protoc-gen-ts_proto \
  --ts_proto_out=./src/generated \
  --ts_proto_opt=esModuleInterop=true \
  --proto_path=./docs/api-contracts/protobuf \
  *.proto
```

**Result:** TypeScript interfaces in `src/generated/`

### Python (for potential ML services)

```bash
# Generate Python types
python -m grpc_tools.protoc \
  -I./docs/api-contracts/protobuf \
  --python_out=./src/generated \
  --grpc_python_out=./src/generated \
  *.proto
```

### Go (for high-performance services)

```bash
# Generate Go types
protoc \
  --go_out=./internal/generated \
  --go_opt=paths=source_relative \
  --proto_path=./docs/api-contracts/protobuf \
  *.proto
```

---

## Usage Examples

### TypeScript: Sending a Command

```typescript
import { ProcessUploadedFileCommand } from './generated/ingestion';
import { RequestContext, InvoiceType } from './generated/common';

const command: ProcessUploadedFileCommand = {
  context: {
    requestId: uuid(),
    userId: 'user-123',
    timestampMs: Date.now(),
    invoiceType: InvoiceType.B2B,
  },
  filename: 'invoice.xml',
  fileContent: Buffer.from(xmlData),
  contentType: 'application/xml',
  uploaderUserId: 'user-123',
};

// Publish to RabbitMQ
await rabbitMQ.publish('file-classification-queue', command);
```

### TypeScript: Emitting an Event

```typescript
import { InvoiceValidatedEvent } from './generated/events';

const event: InvoiceValidatedEvent = {
  invoiceId: { uuid: 'invoice-uuid-here' },
  context: requestContext,
  isValid: true,
  failedValidators: [],
  validatedAtMs: Date.now(),
};

// Publish to Kafka
await kafka.produce('invoice-events', event);
```

---

## Versioning

**Current Version:** `v1` (all schemas in `eracun.v1.*` package)

**Backward Compatibility Rules:**
1. **Never change field numbers** (breaks binary compatibility)
2. **Never remove required fields** (use `deprecated` option)
3. **Add new fields as optional** with defaults
4. **Use `reserved` for deleted fields**

**Version Migration Example:**

```protobuf
// v1.0 (original)
message InvoiceData {
  string invoice_number = 1;
  int64 amount = 2;
}

// v1.1 (backward compatible - added optional field)
message InvoiceData {
  string invoice_number = 1;
  int64 amount = 2;
  string currency = 3; // NEW, optional, defaults to "HRK"
}

// v2.0 (breaking change - new package)
package eracun.v2.common;

message InvoiceData {
  reserved 2; // Old 'amount' field
  string invoice_number = 1;
  int64 amount_cents = 4; // Changed unit to cents
  string currency = 3;
}
```

---

## Schema Validation

### Compile-Time Validation

```bash
# Validate all .proto files
protoc \
  --proto_path=./docs/api-contracts/protobuf \
  --descriptor_set_out=/dev/null \
  *.proto

# Exit code 0 = valid, non-zero = syntax errors
```

### Runtime Validation (TypeScript)

```typescript
import { ValidateXSDCommand } from './generated/validation';

function isValidCommand(obj: unknown): obj is ValidateXSDCommand {
  // ts-proto generates runtime type guards
  return ValidateXSDCommand.decode(obj).isOk();
}
```

---

## Message Size Limits

**Maximum Message Size:** 10 MB (enforced by RabbitMQ/Kafka)

**Large Payloads (>1MB):**
- Store in S3/DigitalOcean Spaces
- Send reference URL in message:

```protobuf
message LargeInvoiceCommand {
  eracun.v1.common.InvoiceId invoice_id = 1;
  string storage_url = 2; // S3 URL to retrieve content
  int64 content_size_bytes = 3;
}
```

---

## Testing

### Unit Tests (TypeScript Example)

```typescript
import { ValidateXSDCommand, SchemaType } from './generated/validation';

describe('ValidateXSDCommand', () => {
  it('should serialize and deserialize correctly', () => {
    const original: ValidateXSDCommand = {
      context: { requestId: 'test', timestampMs: Date.now() },
      invoiceId: { uuid: 'invoice-123' },
      xmlContent: Buffer.from('<xml/>'),
      schemaType: SchemaType.UBL_2_1,
    };

    // Serialize to binary
    const bytes = ValidateXSDCommand.encode(original).finish();

    // Deserialize from binary
    const decoded = ValidateXSDCommand.decode(bytes);

    expect(decoded).toEqual(original);
  });
});
```

### Contract Tests (Pact)

```typescript
import { Pact } from '@pact-foundation/pact';
import { ValidateXSDCommand } from './generated/validation';

describe('XSD Validator Contract', () => {
  it('should accept ValidateXSDCommand', async () => {
    await provider
      .addInteraction({
        state: 'validator is ready',
        uponReceiving: 'a validate XSD command',
        withRequest: {
          method: 'POST',
          path: '/validate',
          body: ValidateXSDCommand.encode(command).finish(),
        },
        willRespondWith: {
          status: 200,
          body: ValidateXSDResponse.encode(response).finish(),
        },
      })
      .executeTest();
  });
});
```

---

## CI/CD Integration

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Validate all .proto files before commit
protoc \
  --proto_path=./docs/api-contracts/protobuf \
  --descriptor_set_out=/dev/null \
  docs/api-contracts/protobuf/*.proto

if [ $? -ne 0 ]; then
  echo "❌ Protocol Buffer validation failed"
  exit 1
fi

echo "✅ Protocol Buffer schemas valid"
```

### CI Pipeline (GitHub Actions)

```yaml
name: Validate Protobuf Schemas

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install protoc
        run: sudo apt-get install -y protobuf-compiler
      - name: Validate schemas
        run: |
          protoc \
            --proto_path=./docs/api-contracts/protobuf \
            --descriptor_set_out=/dev/null \
            docs/api-contracts/protobuf/*.proto
```

---

## References

- **Protocol Buffers Guide:** https://protobuf.dev/
- **ts-proto Documentation:** https://github.com/stephenh/ts-proto
- **gRPC Documentation:** https://grpc.io/docs/
- **Semantic Versioning:** https://semver.org/

---

**Last Updated:** 2025-11-10
**Version:** v1.0
**Owner:** System Architect
