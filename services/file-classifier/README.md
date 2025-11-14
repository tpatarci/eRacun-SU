# File Classifier Service

## Purpose
Identify document types and formats using MIME type detection and magic number analysis. Routes files to appropriate processors (OCR, XML validation, PDF parsing) based on classification.

## Scope
- MIME type detection (magic bytes + file extension)
- Content-based classification (invoice vs non-invoice)
- Language detection for multi-language support
- Confidence scoring for classification
- Message bus integration (RabbitMQ)
- Routing to downstream processors

## Priority
**P0** - Required for routing attachments to correct processors

## Responsibilities

### File Type Detection
- Detect MIME types using magic bytes (primary)
- Fall back to file extension if magic bytes unavailable
- Validate file sizes (min/max limits)
- Identify supported vs unsupported file types

### Classification
- **PDF documents** → Route to PDF parser
- **XML/UBL documents** → Route to schema validator
- **Images (JPEG/PNG/TIFF)** → Route to OCR processor
- **Unknown types** → Route to manual review queue

### Message Bus Integration
- Consume messages from `attachments.extracted` queue
- Publish classified files to:
  - `files.pdf.parse` - PDF documents
  - `files.xml.validate` - XML/UBL documents
  - `files.image.ocr` - Image files requiring OCR
  - `files.manual.review` - Unknown or unsupported types

## Dependencies

### Internal
None (standalone service)

### External
- `@opentelemetry/api`: Distributed tracing
- `@opentelemetry/sdk-node`: OpenTelemetry SDK
- `@opentelemetry/exporter-jaeger`: Jaeger exporter
- `pino`: Structured logging
- `prom-client`: Prometheus metrics

## Architecture

### Components

1. **FileDetector**: Magic byte and extension-based type detection
2. **Classifier**: Business logic for routing decisions
3. **MessageConsumer**: RabbitMQ message consumption
4. **MessagePublisher**: RabbitMQ message publishing
5. **Observability**: Logging, metrics, and tracing

### Data Flow

```
┌─────────────────────┐
│ Attachment Extracted│
│ (RabbitMQ Message)  │
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐
    │FileDetector  │ ◄── Magic bytes + extension
    └──────┬───────┘
           │
           ▼ MIME type + metadata
    ┌──────────────┐
    │ Classifier   │ ◄── Classification rules
    └──────┬───────┘
           │
           ├─► PDF → files.pdf.parse
           ├─► XML → files.xml.validate
           ├─► Image → files.image.ocr
           └─► Unknown → files.manual.review
```

## Configuration

### Environment Variables

```bash
# RabbitMQ Configuration
RABBITMQ_URL=amqp://localhost:5672
INPUT_QUEUE=attachments.extracted
OUTPUT_EXCHANGE=files.classified

# File Size Limits
MAX_FILE_SIZE=10485760              # 10MB (bytes)
MIN_FILE_SIZE=0                     # 0 bytes

# Supported MIME Types (comma-separated)
SUPPORTED_MIME_TYPES=application/pdf,application/xml,text/xml,image/jpeg,image/png,image/tiff

# Classification Rules
PDF_MIME_TYPES=application/pdf
XML_MIME_TYPES=application/xml,text/xml
IMAGE_MIME_TYPES=image/jpeg,image/png,image/tiff

# Observability
LOG_LEVEL=info
METRICS_PORT=9090
JAEGER_ENDPOINT=http://localhost:14268/api/traces
```

### Classification Rules

Rules define which MIME types route to which processors:

```typescript
const defaultRules = {
  pdfTypes: ['application/pdf'],
  xmlTypes: ['application/xml', 'text/xml'],
  imageTypes: ['image/jpeg', 'image/png', 'image/tiff']
};
```

## API

### Programmatic Usage

```typescript
import { FileClassifierService } from '@eracun/file-classifier';

// Create service with defaults
const service = new FileClassifierService();

// Start service (begins consuming messages)
await service.start();

// Health check
const isHealthy = await service.healthCheck();

// Graceful shutdown
await service.shutdown();
```

### Message Formats

**Input Message** (`attachments.extracted`):
```json
{
  "messageId": "msg-12345",
  "emailId": "email-67890",
  "attachmentId": "att-11111",
  "filename": "invoice.pdf",
  "mimeType": "application/pdf",
  "size": 123456,
  "hash": "sha256-hash",
  "content": "base64-encoded-content"
}
```

**Output Message** (`files.pdf.parse`):
```json
{
  "command": "ParsePdfFile",
  "data": {
    "fileId": "file-22222",
    "filename": "invoice.pdf",
    "mimeType": "application/pdf",
    "size": 123456,
    "hash": "sha256-hash",
    "content": "base64-encoded-content"
  },
  "metadata": {
    "messageId": "msg-12345",
    "emailId": "email-67890",
    "attachmentId": "att-11111",
    "classifiedAt": "2025-11-14T10:00:00Z"
  }
}
```

## Features

### Magic Byte Detection

Detects file types by examining file headers:

| Type | Magic Bytes | MIME Type |
|------|-------------|-----------|
| PDF | `%PDF` (0x25504446) | `application/pdf` |
| XML | `<?xml` (0x3C3F786D) | `application/xml` |
| JPEG | `0xFFD8FF` | `image/jpeg` |
| PNG | `0x89504E47` | `image/png` |
| TIFF | `II*` or `MM*` | `image/tiff` |

### File Size Validation

Configurable limits prevent processing of oversized or empty files:

```typescript
// Default limits
const options = {
  maxFileSize: 10 * 1024 * 1024,  // 10MB
  minFileSize: 0                   // No minimum
};
```

### Classification Confidence

Each classification includes confidence scoring (future enhancement):

```typescript
interface ClassificationResult {
  destination: string;
  confidence: number;  // 0.0 - 1.0
  reasoning: string;
}
```

## Performance

### Processing Times

| Operation | Time (p50) | Time (p95) |
|-----------|------------|------------|
| Magic byte detection | 1ms | 3ms |
| Classification | <1ms | 1ms |
| Message publish | 5ms | 15ms |
| Total per file | 10ms | 25ms |

### Throughput

- **Target**: 1000 files/minute
- **Actual**: ~600 files/minute (single instance)
- **Scaling**: Horizontal (multiple service instances)

### Resource Usage

- **Memory**: ~50MB baseline
- **CPU**: <10% utilization (single core)
- **Network**: Minimal (RabbitMQ local)

## Observability

### Metrics (Prometheus)

```promql
# Files classified by type
files_classified_total{mime_type="application/pdf"}

# Files routed to processors
files_routed_total{destination="files.pdf.parse"}

# Classification errors
classification_errors_total{error_type="unsupported_type"}

# Processing duration
classification_duration_ms_bucket

# Queue depth
queue_depth{queue="attachments.extracted"}

# File sizes
file_size_bytes_bucket
```

### Logs (Pino/JSON)

```json
{
  "level": 30,
  "time": 1699980000000,
  "name": "file-classifier",
  "msg": "File classified successfully",
  "messageId": "msg-12345",
  "filename": "invoice.pdf",
  "mimeType": "application/pdf",
  "destination": "files.pdf.parse",
  "durationMs": 12
}
```

### Distributed Tracing (Jaeger)

```typescript
// Automatic span creation
withSpan('classify-file', async (span) => {
  span.setAttribute('file.name', filename);
  span.setAttribute('file.mimeType', mimeType);
  // ... classification logic
});
```

## Error Handling

### Common Errors

| Error Code | Description | Recovery |
|------------|-------------|----------|
| `UNSUPPORTED_TYPE` | File type not in supported list | Route to manual review |
| `FILE_TOO_LARGE` | Exceeds max size limit | Reject with error |
| `FILE_TOO_SMALL` | Below min size limit | Reject with error |
| `DETECTION_FAILED` | Cannot determine file type | Route to manual review |
| `INVALID_MESSAGE` | Malformed input message | Log and skip |

### Dead Letter Queue

Messages that fail processing after 3 retries move to DLQ:

```bash
# View DLQ messages
rabbitmqadmin get queue=attachments.extracted.dlq count=10

# Reprocess DLQ
rabbitmqadmin get queue=attachments.extracted.dlq requeue=true
```

## Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

### Test Coverage

**Current**: 73 tests, all passing

| File | Coverage |
|------|----------|
| classifier.ts | 100% |
| file-detector.ts | 100% |
| observability.ts | 100% |

### Example Test

```typescript
describe('Classifier', () => {
  it('should classify PDF documents', () => {
    const classifier = new Classifier();
    const result = classifier.classify('application/pdf', 'invoice.pdf');

    expect(result.destination).toBe('files.pdf.parse');
    expect(result.command).toBe('ParsePdfFile');
  });
});
```

## Deployment

### systemd Service

```ini
[Unit]
Description=eRacun File Classifier
After=network.target rabbitmq-server.service

[Service]
Type=simple
User=eracun
WorkingDirectory=/opt/eracun/services/file-classifier
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=10

# Environment
Environment=NODE_ENV=production
Environment=RABBITMQ_URL=amqp://localhost:5672

# Resource limits
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY dist ./dist
EXPOSE 9090
CMD ["node", "dist/index.js"]
```

### Health Check

```bash
# HTTP health endpoint
curl http://localhost:9090/health

# Response
{"status":"healthy","uptime":12345,"version":"1.0.0"}
```

## Integration

### With Email Ingestion Worker

Email worker publishes to `attachments.extracted`, file-classifier consumes:

```typescript
// Email worker publishes
await rabbitMQ.publish('attachments.extracted', {
  messageId,
  filename: 'invoice.pdf',
  content: buffer.toString('base64')
});

// File classifier consumes and routes
// → Publishes to files.pdf.parse
```

### With OCR Processing Service

Images route to OCR service:

```typescript
// File classifier routes image
classifier.classify('image/jpeg', 'scan.jpg');
// → Publishes to files.image.ocr

// OCR service consumes
await rabbitMQ.subscribe('files.image.ocr', async (message) => {
  const text = await ocrEngine.extractText(message.content);
  // ...
});
```

## Failure Modes

### Classification Failure
**Symptom**: Files not routed
**Cause**: Misconfigured classification rules
**Recovery**: Check environment variables, restart service

### Message Bus Failure
**Symptom**: Messages not consumed/published
**Cause**: RabbitMQ connection issue
**Recovery**: Service auto-reconnects, check RabbitMQ health

### High Memory Usage
**Symptom**: OOM kills
**Cause**: Large files or memory leak
**Recovery**: Increase limits, check for leaks, enable streaming

## Monitoring

### Alerts

- **High error rate**: >5% classification errors
- **Processing time**: p95 >100ms
- **Queue depth**: >1000 messages
- **Memory usage**: >80% of limit

### Dashboards

Grafana panels:
- Classification throughput (files/min)
- Error rate by type
- Processing duration (p50/p95/p99)
- Queue depth over time
- Memory/CPU usage

## Future Enhancements

- [ ] Machine learning-based classification
- [ ] Content analysis (not just MIME type)
- [ ] Invoice-specific detection (keywords, patterns)
- [ ] Multi-language support (Croatian, English, German)
- [ ] Confidence scoring algorithm
- [ ] A/B testing of classification rules
- [ ] Auto-tuning based on downstream feedback

## Maintainer

eRacun Team 2 (Ingestion & Document Processing)

## Last Updated

2025-11-14
