# Attachment Handler Service

## Purpose
Extract and process email and archive attachments with support for nested archives, virus scanning, and file validation.

## Scope
- ZIP/RAR/7z archive extraction
- Nested archive handling (configurable depth limit)
- Password-protected archive support
- Virus scanning (mock for development)
- File size and type validation
- MIME type detection using magic bytes
- Invoice file identification

## Priority
**P1** - Required for complete email processing pipeline

## Dependencies

### Internal
- `@eracun/team2-mocks`: Shared mock infrastructure

### External
- `adm-zip`: ZIP archive extraction
- `file-type`: Magic byte detection
- `magic-bytes.js`: File signature validation
- `mime-types`: MIME type utilities
- `pino`: Structured logging

## API

### AttachmentHandler

Main service class for attachment processing.

```typescript
import { AttachmentHandler } from '@eracun/attachment-handler';

const handler = new AttachmentHandler({
  maxFileSize: 10 * 1024 * 1024,  // 10MB per file
  maxTotalSize: 50 * 1024 * 1024,  // 50MB total
  maxFiles: 100,
  maxNestingLevel: 3,
  enableVirusScan: true
});

// Process attachment
const result = await handler.processAttachment(buffer, 'invoice.zip');

console.log(`Extracted ${result.files.length} files`);
for (const file of result.files) {
  console.log(`- ${file.filename} (${file.mimeType}, ${file.size} bytes)`);
}
```

### ExtractionResult

```typescript
interface ExtractionResult {
  success: boolean;
  files: ExtractedFile[];
  errors: string[];
  metadata: {
    totalFiles: number;
    totalSize: number;
    archives: number;
    invoices: number;
    skipped: number;
  };
}
```

### ExtractedFile

```typescript
interface ExtractedFile {
  filename: string;
  originalPath: string;
  content: Buffer;
  mimeType: string;
  size: number;
  hash: string;  // SHA-256
  extractedFrom?: string;  // Parent archive name
}
```

## Features

### Archive Extraction

Supports multiple archive formats:
- ✅ **ZIP**: Full support (adm-zip)
- ⏳ **RAR**: Planned (requires unrar-js)
- ⏳ **7-Zip**: Planned (requires 7zip-min)
- ⏳ **TAR**: Planned
- ⏳ **GZIP**: Planned

### Nested Archives

Automatically extracts nested archives up to configured depth:

```typescript
const handler = new AttachmentHandler({
  maxNestingLevel: 3  // Default
});

// archive.zip
//   ├── invoice.pdf
//   └── nested.zip  <-- Level 1
//       ├── document.xml
//       └── deep.zip  <-- Level 2
//           └── file.pdf  <-- Level 3
```

### Virus Scanning

Mock virus scanner for development, production should use ClamAV:

```typescript
const handler = new AttachmentHandler({
  enableVirusScan: true
});

const result = await handler.processAttachment(buffer, 'file.zip');

if (!result.success && result.errors.includes('Virus detected')) {
  console.error('File is infected!');
}
```

### File Validation

Validates files before processing:
- File size limits (per-file and total)
- File count limits
- MIME type validation
- Filename safety checks
- Magic byte verification

### MIME Type Detection

Uses multiple methods for accurate detection:
1. **Magic bytes** (primary): Reads file signatures
2. **File extension** (fallback): Uses filename extension
3. **Content analysis**: For text-based formats (XML)

## Configuration

### Environment Variables

```bash
# Virus scanning
ENABLE_VIRUS_SCAN=true

# File size limits (bytes)
MAX_FILE_SIZE=10485760          # 10MB
MAX_TOTAL_SIZE=52428800         # 50MB
MAX_FILES=100

# Extraction limits
MAX_NESTING_LEVEL=3

# Allowed MIME types (comma-separated)
ALLOWED_TYPES=application/pdf,application/xml,application/zip
```

### ExtractionOptions

```typescript
interface ExtractionOptions {
  maxFileSize?: number;       // Default: 10MB
  maxTotalSize?: number;      // Default: 50MB
  maxFiles?: number;          // Default: 100
  maxNestingLevel?: number;   // Default: 3
  allowedTypes?: string[];    // Default: PDF, XML, ZIP, images
  enableVirusScan?: boolean;  // Default: true
  password?: string;          // For encrypted archives
}
```

## Performance

### Processing Times (Mock)

| Operation | Time (p50) | Time (p95) |
|-----------|------------|------------|
| Single file | 50ms | 100ms |
| ZIP extraction (10 files) | 200ms | 500ms |
| Nested archive (3 levels) | 500ms | 1000ms |
| Virus scan (per MB) | 50ms | 100ms |

### Resource Limits

- **Memory**: ~50MB baseline + extracted file sizes
- **CPU**: Minimal (mostly I/O bound)
- **Disk**: None (all in-memory processing)

## Error Handling

### Common Errors

| Error Code | Description | Recovery |
|------------|-------------|----------|
| `FILE_TOO_LARGE` | File exceeds size limit | Reduce file size |
| `EMPTY_FILE` | File has no content | Provide valid file |
| `INVALID_FILENAME` | Missing or invalid filename | Use valid filename |
| `VIRUS_DETECTED` | Malware found | Remove infected file |
| `MAX_FILES_REACHED` | Too many files in archive | Reduce file count |
| `MAX_NESTING_EXCEEDED` | Archive nested too deep | Reduce nesting |

### Error Response

```typescript
{
  success: false,
  files: [],
  errors: [
    "File size 20971520 bytes exceeds maximum 10485760 bytes",
    "Maximum nesting level exceeded: 4"
  ],
  metadata: {
    totalFiles: 0,
    totalSize: 0,
    archives: 0,
    invoices: 0,
    skipped: 15
  }
}
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

Target: **85%** coverage (branches, functions, lines, statements)

### Example Test

```typescript
import { AttachmentHandler } from '@eracun/attachment-handler';

describe('AttachmentHandler', () => {
  it('should extract ZIP archive', async () => {
    const handler = new AttachmentHandler();
    const zipBuffer = createMockZipBuffer();

    const result = await handler.processAttachment(zipBuffer, 'test.zip');

    expect(result.success).toBe(true);
    expect(result.files.length).toBeGreaterThan(0);
  });
});
```

## Integration

### With Email Ingestion Worker

```typescript
import { AttachmentHandler } from '@eracun/attachment-handler';
import { IEmailClient } from '@eracun/team2-mocks';

const handler = new AttachmentHandler();
const emailClient: IEmailClient = ...;

const emails = await emailClient.fetchUnread();

for (const email of emails) {
  for (const attachment of email.attachments) {
    const content = await emailClient.downloadAttachment(email.id, attachment.id);

    // Process attachment
    const result = await handler.processAttachment(content, attachment.filename);

    // Send extracted files for further processing
    for (const file of result.files) {
      if (file.mimeType === 'application/pdf') {
        await sendToOCR(file);
      } else if (file.mimeType === 'application/xml') {
        await sendToValidator(file);
      }
    }
  }
}
```

### With Message Bus

```typescript
import { AttachmentHandler } from '@eracun/attachment-handler';

const handler = new AttachmentHandler();

// Subscribe to attachment processing messages
rabbitMQ.subscribe('attachments.process', async (message) => {
  const { buffer, filename, messageId } = message;

  try {
    const result = await handler.processAttachment(buffer, filename);

    // Publish extracted files
    for (const file of result.files) {
      await rabbitMQ.publish('files.extracted', {
        messageId,
        file: {
          filename: file.filename,
          mimeType: file.mimeType,
          hash: file.hash,
          content: file.content.toString('base64')
        }
      });
    }
  } catch (error) {
    await rabbitMQ.publish('attachments.failed', {
      messageId,
      error: error.message
    });
  }
});
```

## Failure Modes

### Extraction Failure
**Symptom**: `result.success === false`
**Cause**: Corrupted archive, unsupported format, or size limits
**Recovery**: Log error, move to dead letter queue, notify monitoring

### Virus Detection
**Symptom**: `Virus detected` in errors
**Cause**: Infected file
**Recovery**: Quarantine file, alert security team, block sender

### Memory Exhaustion
**Symptom**: Out of memory errors
**Cause**: Extracting very large archives
**Recovery**: Implement streaming extraction, increase memory limits

## Monitoring

### Metrics

- `attachments_processed_total`: Counter of processed attachments
- `attachments_extracted_files`: Histogram of files per attachment
- `attachments_processing_duration_ms`: Processing time
- `attachments_virus_detected_total`: Virus detection counter
- `attachments_errors_total`: Error counter by type

### Alerts

- **High error rate**: >5% of attachments fail
- **Virus detection**: Any virus detected
- **Processing time**: p95 >5 seconds
- **Memory usage**: >80% of allocated memory

## Security Considerations

1. **Virus scanning**: Always enabled in production
2. **File size limits**: Prevent DoS attacks
3. **Nesting limits**: Prevent zip bombs
4. **Filename validation**: Prevent path traversal
5. **Type validation**: Only allow safe file types
6. **Memory limits**: Prevent memory exhaustion

## Future Enhancements

- [ ] RAR extraction support
- [ ] 7-Zip extraction support
- [ ] Password-protected archives
- [ ] Streaming extraction for large files
- [ ] ClamAV integration for production
- [ ] Parallel extraction for multiple files
- [ ] Resume interrupted extractions
- [ ] Archive repair for corrupted files

## Maintainer

eRacun Team 2 (Ingestion & Document Processing)

## Last Updated

2025-11-14
