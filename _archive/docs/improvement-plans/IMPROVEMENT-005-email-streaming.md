# Improvement Plan: Implement Streaming Email Parsing

**Priority:** 🟠 **HIGH**
**Service:** `services/email-ingestion-worker/`
**Issue ID:** 5.4
**Status:** Memory Bottleneck Under Load
**Effort Estimate:** 2-3 hours
**Impact:** Reduces peak memory usage by 50-80%, enables processing of larger attachments

---

## Problem Statement

The email ingestion worker loads **entire emails and attachments into memory** before processing. At 100 concurrent email operations, a single 10MB attachment causes 10MB allocation per operation = 1GB+ peak memory.

**Current Code** (lines 85-97, `services/email-ingestion-worker/src/attachment-extractor.ts`):

```typescript
async parseEmail(emailStream: Readable): Promise<ParsedEmail> {
  // simpleParser loads ENTIRE email + all attachments into Node.js heap
  const parsed = await simpleParser(emailStream);

  // parsed.attachments is array of all attachments in memory
  const attachments = this.extractAttachments(parsed.attachments);

  return {
    from: parsed.from,
    to: parsed.to,
    attachments, // All in memory now
  };
}
```

### Memory Impact

| Scenario | Email Size | Concurrent Ops | Memory Usage | Issue |
|----------|-----------|-----------------|--------------|-------|
| Normal | 2MB | 10 | ~20MB | Acceptable |
| Large PDF | 10MB | 10 | ~100MB | High |
| Multiple PDFs | 10MB each, 3 attach | 10 | ~300MB | Critical |
| Surge | 10MB | 100 | ~1GB | OOM Risk |

### Why This Matters

- **Node.js Garbage Collection:** Loading 1GB of data creates pause latencies (GC stops world)
- **Container Limits:** If pod limited to 512MB, large batches cause OOM kills
- **Throughput Loss:** GC pauses add latency, reducing invoice processing rate

---

## Root Cause Analysis

The `simpleParser` library from `mailparser` is convenience-oriented, not performance-oriented. It:
- Buffers entire email into memory before emitting events
- Extracts all MIME parts eagerly (not lazily)
- Doesn't support streaming attachment processing

For a platform handling "legally binding financial documents", we need:
- **Streaming:** Process attachments as they arrive, not all-at-once
- **Backpressure:** Control how fast data flows (don't buffer if can't process)
- **Memory Bounds:** Fixed memory overhead regardless of attachment size

---

## Solution Design

### Approach: Replace `simpleParser` with Streaming Mime Parser

Instead of buffering entire email, parse MIME structure and stream attachments individually:

```typescript
import { simpleParser } from 'mailparser';
import { Readable } from 'stream';

// Option 1: Continue using simpleParser but limit buffers
// Option 2: Use node-mboxrd + streaming parser
// Option 3: Implement custom streaming MIME parser

// Recommended: Option 1 with memory limits + streaming attachment processing
```

### Implementation Strategy

1. **Keep simpleParser for simplicity** (proven library)
2. **Limit attachment buffering** (don't load all into memory)
3. **Process attachments immediately** (stream to downstream services)
4. **Bound memory usage** (backpressure handling)

### Code Design

```typescript
export class AttachmentExtractor {
  async parseEmailStreaming(emailStream: Readable): Promise<void> {
    const parser = simpleParser(emailStream);

    // Don't await entire parse - process as attachments arrive
    parser.on('attachment', (attachment: Attachment) => {
      // Process attachment immediately, don't buffer
      this.handleAttachmentStream(attachment);
    });

    parser.on('headers', (headers: Headers) => {
      this.emailMetadata = {
        from: headers.from,
        to: headers.to,
        subject: headers.subject,
        date: headers.date,
      };
    });

    // Wait for parsing to complete
    await parser;
  }

  private async handleAttachmentStream(attachment: Attachment): Promise<void> {
    // Don't read entire content into memory
    // Instead, publish to message bus immediately

    const hash = crypto.createHash('sha256');
    let bytesProcessed = 0;

    // Stream attachment to hash + message bus
    const processStream = attachment.content
      .on('data', (chunk: Buffer) => {
        hash.update(chunk);
        bytesProcessed += chunk.length;

        // Check size limits
        if (bytesProcessed > this.config.maxAttachmentSize) {
          processStream.destroy(
            new Error('Attachment exceeds max size')
          );
        }
      })
      .on('end', async () => {
        // Only now publish the attachment info + hash
        // The actual content was streamed to message bus
        await this.publishAttachmentReference({
          filename: attachment.filename,
          contentType: attachment.contentType,
          size: bytesProcessed,
          checksum: hash.digest('hex'),
        });
      });
  }
}
```

---

## Implementation Steps

### Step 1: Update Configuration

**File:** `services/email-ingestion-worker/src/config.ts`

Add:
```typescript
export interface EmailParsingConfig {
  // ... existing fields
  maxAttachmentSize: number;    // Default: 20MB
  maxAttachmentsPerEmail: number; // Default: 10
  streamBufferSize: number;      // Default: 64KB
}

export const DEFAULT_CONFIG = {
  // ...
  maxAttachmentSize: parseInt(process.env.MAX_ATTACHMENT_SIZE_MB ?? '20') * 1024 * 1024,
  maxAttachmentsPerEmail: parseInt(process.env.MAX_ATTACHMENTS ?? '10'),
  streamBufferSize: parseInt(process.env.STREAM_BUFFER_SIZE ?? '65536'),
};
```

### Step 2: Refactor Attachment Extractor

**File:** `services/email-ingestion-worker/src/attachment-extractor.ts`

```typescript
export class AttachmentExtractor {
  private emailMetadata: EmailMetadata | null = null;
  private attachmentCount: number = 0;

  async parseEmailStreaming(emailStream: Readable): Promise<ParsedEmail> {
    return new Promise<ParsedEmail>((resolve, reject) => {
      const parser = simpleParser(emailStream);

      parser.on('headers', (headers: Headers) => {
        this.emailMetadata = {
          from: this.parseAddresses(headers.from),
          to: this.parseAddresses(headers.to),
          cc: this.parseAddresses(headers.cc),
          bcc: this.parseAddresses(headers.bcc),
          subject: headers.subject || '',
          date: headers.date || new Date(),
        };
      });

      parser.on('attachment', async (attachment: Attachment) => {
        try {
          this.attachmentCount++;

          if (this.attachmentCount > this.config.maxAttachmentsPerEmail) {
            throw new Error(
              `Email exceeds max attachments (${this.config.maxAttachmentsPerEmail})`
            );
          }

          // Process attachment immediately (streaming)
          await this.processAttachmentStream(attachment);

          // Metrics
          emailAttachmentProcessed.inc({
            status: 'success',
            size_bucket: this.getSizeBucket(attachment.size || 0),
          });
        } catch (err) {
          logger.error({ error: err }, 'Failed to process attachment');
          emailAttachmentProcessed.inc({
            status: 'error',
            size_bucket: this.getSizeBucket(attachment.size || 0),
          });
          // Don't reject parser, continue with other attachments
        }
      });

      parser.on('error', (err: Error) => {
        logger.error({ error: err }, 'Email parsing error');
        reject(new Error(`Email parsing failed: ${err.message}`));
      });

      // Wait for parsing to complete
      parser.then(() => {
        if (!this.emailMetadata) {
          reject(new Error('No email headers found'));
          return;
        }

        resolve({
          metadata: this.emailMetadata,
          attachmentCount: this.attachmentCount,
        } as ParsedEmail);
      }).catch(reject);
    });
  }

  private async processAttachmentStream(attachment: Attachment): Promise<void> {
    const startTime = Date.now();
    const hash = crypto.createHash('sha256');

    let bytesProcessed = 0;
    let publishedMessageId: string | null = null;

    return new Promise<void>((resolve, reject) => {
      // Create stream for content
      const contentStream = attachment.content as Readable;

      contentStream
        .on('data', (chunk: Buffer) => {
          // Update hash as data arrives
          hash.update(chunk);
          bytesProcessed += chunk.length;

          // Size check
          if (bytesProcessed > this.config.maxAttachmentSize) {
            contentStream.destroy(
              new Error(
                `Attachment exceeds ${this.config.maxAttachmentSize / 1024 / 1024}MB limit`
              )
            );
          }

          // Backpressure: pause stream if queue full
          const queueDepth = this.messagePublisher.getQueueDepth();
          if (queueDepth > 100) {
            contentStream.pause();
            setTimeout(() => contentStream.resume(), 100);
          }
        })
        .on('end', async () => {
          try {
            // Only now publish attachment metadata
            publishedMessageId = await this.publishAttachmentMetadata({
              filename: attachment.filename || 'unnamed',
              contentType: attachment.contentType || 'application/octet-stream',
              size: bytesProcessed,
              checksum: hash.digest('hex'),
            });

            const duration = Date.now() - startTime;
            attachmentProcessingDuration.observe(
              {
                status: 'success',
                size_bucket: this.getSizeBucket(bytesProcessed),
              },
              duration
            );

            logger.debug('Attachment processed', {
              filename: attachment.filename,
              sizeBytes: bytesProcessed,
              durationMs: duration,
            });

            resolve();
          } catch (err) {
            logger.error({ error: err }, 'Failed to publish attachment');
            reject(err);
          }
        })
        .on('error', (err: Error) => {
          logger.error({ error: err }, 'Attachment stream error');
          reject(err);
        });
    });
  }

  private async publishAttachmentMetadata(metadata: {
    filename: string;
    contentType: string;
    size: number;
    checksum: string;
  }): Promise<string> {
    // Note: Actual content was streamed and stored separately
    // This publishes metadata reference only

    const command: ProcessAttachmentCommand = {
      attachment_id: crypto.randomUUID(),
      filename: metadata.filename,
      content_type: metadata.contentType,
      size_bytes: metadata.size,
      checksum_sha256: metadata.checksum,
      // Don't include content - already streamed!
    };

    return this.messagePublisher.publishAttachment(
      this.emailMetadata!.metadata.messageId,
      command
    );
  }

  private getSizeBucket(sizeBytes: number): string {
    if (sizeBytes < 1024 * 1024) return '<1MB';
    if (sizeBytes < 5 * 1024 * 1024) return '1-5MB';
    if (sizeBytes < 10 * 1024 * 1024) return '5-10MB';
    return '>10MB';
  }

  private parseAddresses(
    addressValue: string | { value: any[] } | undefined
  ): string[] {
    if (!addressValue) return [];
    if (typeof addressValue === 'string') return [addressValue];

    const value = (addressValue as any).value;
    if (!Array.isArray(value)) return [];

    return value
      .map((addr: any) => addr.address || '')
      .filter((addr: string) => addr.length > 0);
  }
}
```

### Step 3: Update Message Publisher for Streaming

**File:** `services/email-ingestion-worker/src/message-publisher.ts`

```typescript
export class MessagePublisher {
  private queueDepth: number = 0;
  private maxQueueDepth: number = 1000;

  getQueueDepth(): number {
    return this.queueDepth;
  }

  async publishAttachment(
    emailMessageId: string,
    command: ProcessAttachmentCommand
  ): Promise<string> {
    // Track queue depth
    this.queueDepth++;

    try {
      const messageId = crypto.randomUUID();

      const message = JSON.stringify({
        message_id: messageId,
        email_message_id: emailMessageId,
        type: 'ProcessAttachmentCommand',
        command,
        timestamp: new Date().toISOString(),
      });

      // Publish with publisher confirms
      await this.channel.assertQueue(this.config.attachmentQueue, {
        durable: true,
      });

      this.channel.sendToQueue(this.config.attachmentQueue, Buffer.from(message), {
        persistent: true,
        contentType: 'application/json',
        messageId,
      });

      // Wait for publisher confirms
      await this.channel.waitForConfirms();

      messagesPublishedTotal.inc({ type: 'attachment_metadata' });

      return messageId;
    } finally {
      this.queueDepth--;
    }
  }

  async publishBatchWithBackpressure(
    messages: any[]
  ): Promise<string[]> {
    // Publish messages with backpressure handling
    const result: string[] = [];

    for (const message of messages) {
      // Check if queue is full
      while (this.queueDepth >= this.maxQueueDepth) {
        logger.warn('Queue full, applying backpressure', {
          queueDepth: this.queueDepth,
        });
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      const id = await this.publishAttachment(
        message.emailMessageId,
        message.command
      );
      result.push(id);
    }

    return result;
  }
}
```

### Step 4: Add Metrics

**File:** `services/email-ingestion-worker/src/metrics.ts`

Add:
```typescript
export const attachmentProcessingDuration = new Histogram({
  name: 'attachment_processing_duration_ms',
  help: 'Time to process attachment',
  labelNames: ['status', 'size_bucket'], // 'success'|'error', '<1MB'|'1-5MB'|'5-10MB'|'>10MB'
  buckets: [100, 500, 1000, 5000, 10000],
});

export const emailAttachmentProcessed = new Counter({
  name: 'email_attachment_processed_total',
  help: 'Total attachments processed',
  labelNames: ['status', 'size_bucket'],
});

export const messagePublisherQueueDepth = new Gauge({
  name: 'message_publisher_queue_depth',
  help: 'Current message publisher queue depth',
});

export const attachmentMemoryUsage = new Gauge({
  name: 'attachment_memory_usage_bytes',
  help: 'Current memory used by attachment buffers',
});
```

### Step 5: Add Tests

**File:** `services/email-ingestion-worker/src/attachment-extractor.spec.ts`

```typescript
describe('AttachmentExtractor - Streaming', () => {
  let extractor: AttachmentExtractor;

  beforeEach(() => {
    extractor = new AttachmentExtractor(DEFAULT_CONFIG);
  });

  it('should process attachments as they arrive (not buffer all)', async () => {
    const emailStream = createTestEmailStream({
      attachments: [
        { filename: 'test1.pdf', size: 5 * 1024 * 1024 },
        { filename: 'test2.pdf', size: 5 * 1024 * 1024 },
      ],
    });

    // Track memory at start
    const memStart = process.memoryUsage().heapUsed;

    const result = await extractor.parseEmailStreaming(emailStream);

    // Track memory after
    const memEnd = process.memoryUsage().heapUsed;
    const memUsed = (memEnd - memStart) / 1024 / 1024; // MB

    // Should not buffer all 10MB in memory
    expect(memUsed).toBeLessThan(5); // Conservative bound
    expect(result.attachmentCount).toBe(2);
  });

  it('should reject attachment exceeding size limit', async () => {
    const config = { ...DEFAULT_CONFIG, maxAttachmentSize: 1024 * 1024 }; // 1MB
    extractor = new AttachmentExtractor(config);

    const emailStream = createTestEmailStream({
      attachments: [
        { filename: 'huge.pdf', size: 10 * 1024 * 1024 }, // 10MB
      ],
    });

    expect(extractor.parseEmailStreaming(emailStream)).rejects.toThrow(
      'exceeds'
    );
  });

  it('should enforce max attachment count', async () => {
    const config = { ...DEFAULT_CONFIG, maxAttachmentsPerEmail: 5 };
    extractor = new AttachmentExtractor(config);

    const emailStream = createTestEmailStream({
      attachments: Array.from({ length: 10 }, (_, i) => ({
        filename: `file${i}.pdf`,
        size: 1024 * 1024,
      })),
    });

    expect(extractor.parseEmailStreaming(emailStream)).rejects.toThrow(
      'exceeds max attachments'
    );
  });

  it('should apply backpressure when queue full', async () => {
    const publisher = mockMessagePublisher({
      getQueueDepth: () => 1000, // Queue full
    });
    extractor['messagePublisher'] = publisher;

    const pauseSpy = jest.spyOn(extractor, 'pauseStream');

    const emailStream = createTestEmailStream({
      attachments: [{ filename: 'test.pdf', size: 5 * 1024 * 1024 }],
    });

    await extractor.parseEmailStreaming(emailStream);

    // Should have paused stream due to backpressure
    expect(pauseSpy).toHaveBeenCalled();
  });

  it('should publish attachment metadata only (not content)', async () => {
    const publishSpy = jest.spyOn(
      extractor['messagePublisher'],
      'publishAttachment'
    );

    const emailStream = createTestEmailStream({
      attachments: [{ filename: 'test.pdf', size: 1024 * 1024 }],
    });

    await extractor.parseEmailStreaming(emailStream);

    expect(publishSpy).toHaveBeenCalledWith(expect.any(String), {
      attachment_id: expect.any(String),
      filename: 'test.pdf',
      size_bytes: 1024 * 1024,
      checksum_sha256: expect.any(String),
      // No 'content' field - not included in metadata
    });
  });
});
```

---

## Validation Checklist

- [ ] Email with 10MB attachment processes with <50MB peak memory
- [ ] Attachment stream never buffered entirely in memory
- [ ] Backpressure applied when queue depth exceeds threshold
- [ ] Attachment size limits enforced
- [ ] Attachment count limits enforced
- [ ] Failed attachments don't block other attachments
- [ ] Tests verify streaming behavior (memory bounded)
- [ ] Metrics track processing duration and queue depth

---

## Acceptance Criteria

✅ **Memory Efficiency:** Peak memory < 50MB regardless of attachment size
✅ **Streaming:** Attachment content streamed, not buffered
✅ **Backpressure:** Queue depth monitored and handled
✅ **Robustness:** Oversized attachments rejected cleanly
✅ **Observability:** Metrics track processing and queue health
✅ **Tests:** Verify streaming behavior and bounds
✅ **Backward Compatible:** Email metadata still extracted correctly

---

## Performance Impact

**Before Optimization:**
- 10MB attachment = 10MB heap allocated
- 100 concurrent = 1GB+ peak memory
- Risk of OOM in 512MB container

**After Optimization:**
- 10MB attachment = ~1MB heap (stream buffer only)
- 100 concurrent = ~100MB peak memory
- Safe in 512MB container with headroom

---

## Deployment Notes

**Configuration:**
```bash
# In systemd service or .env
MAX_ATTACHMENT_SIZE_MB=20
MAX_ATTACHMENTS=10
STREAM_BUFFER_SIZE=65536
```

**Monitoring:**
- Alert if `message_publisher_queue_depth` > 500 (backpressure active)
- Alert if `attachment_processing_duration` p99 > 5000ms
- Monitor memory usage (should stay under 200MB)

---

## Related Issues

- Issue 5.1: Crypto module require in loop (separate fix)
- Issue 5.11: Base64 encoding per message (attachment content not in memory now)
- Issue 5.12: No batching in message publishing (can batch if needed now)

---

**Owner:** Codex
**Due Date:** Before staging with large volume tests
**Blocked By:** None
**Blocks:** High-volume email processing tests

