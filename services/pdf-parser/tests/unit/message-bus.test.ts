import { beforeEach, afterEach, describe, expect, it, jest } from '@jest/globals';
import {
  type MessageBusConfig,
  MessageConsumer,
  type MessageProcessor,
  type PDFClassificationMessage,
} from '../../src/message-consumer';
import {
  MessagePublisher,
  type ParsedInvoiceCommand,
  type PublisherConfig,
} from '../../src/message-publisher';
import {
  drainMockQueue,
  mockBroker,
  publishMockMessage,
  resetMockBroker,
} from 'amqplib-mocks';
import { queueDepth } from '../../src/observability';

const consumerConfig: MessageBusConfig = {
  url: 'amqp://mock',
  exchange: 'incoming.files',
  queue: 'pdf-parser-queue',
  routingKey: 'file.pdf.classify',
  prefetchCount: 5,
};

const publisherConfig: PublisherConfig = {
  url: 'not-a-valid-url',
  exchange: 'parsed.invoices',
  routingKey: 'invoice.parsed',
  persistent: true,
};

const classificationMessage: PDFClassificationMessage = {
  messageId: 'msg-101',
  emailMessageId: 'email-101',
  attachmentId: 'att-101',
  filename: 'invoice.pdf',
  classification: {
    processor: 'classifier',
    priority: 'normal',
    category: 'invoice',
    mimeType: 'application/pdf',
    extension: 'pdf',
    size: 2048,
    confidence: '0.9',
  },
  content: Buffer.from('fake').toString('base64'),
  timestamp: new Date('2024-01-10T12:00:00Z').toISOString(),
  source: 'scanner@example.com',
};

const buildParsedInvoiceCommand = (): ParsedInvoiceCommand => ({
  messageId: 'parsed-msg-101',
  emailMessageId: classificationMessage.emailMessageId,
  attachmentId: classificationMessage.attachmentId,
  filename: classificationMessage.filename,
  pdfMetadata: {
    pageCount: 2,
    isScanned: false,
    quality: 'high',
    size: classificationMessage.classification.size,
  },
  invoice: {
    invoiceNumber: 'INV-2024-101',
    vendor: { name: 'Issuer d.o.o.', oib: '12345678903' },
    customer: { name: 'Buyer d.o.o.', oib: '98765432109' },
    lineItems: [{ description: 'Consulting', quantity: 1, amount: 100 }],
    amounts: { subtotal: 100, vatAmount: 25, total: 125, currency: 'EUR' },
    confidence: 'high',
    extractedFields: ['invoiceNumber', 'vendor.oib', 'customer.oib'],
  },
  timestamp: new Date().toISOString(),
  source: classificationMessage.source,
});

describe('Message bus integration', () => {
  beforeEach(() => {
    resetMockBroker();
    jest.clearAllMocks();
  });

  describe('MessageConsumer', () => {
    let consumer: MessageConsumer | null = null;
    let intervalSpy: ReturnType<typeof jest.spyOn>;

    beforeEach(() => {
      intervalSpy = jest.spyOn(global, 'setInterval').mockImplementation((
        (fn: Parameters<typeof setInterval>[0]) => {
          if (typeof fn === 'function') {
            (fn as () => void)();
          }
          return 0 as unknown as NodeJS.Timeout;
        }
      ) as typeof setInterval);
    });

    afterEach(async () => {
      if (consumer) {
        await consumer.disconnect();
        consumer = null;
      }
      intervalSpy.mockRestore();
    });

    it('processes messages and records queue metrics', async () => {
      const processor = jest
        .fn(async (_message: PDFClassificationMessage) => {})
        .mockResolvedValue(undefined) as jest.MockedFunction<MessageProcessor>;
      const queueDepthSpy = jest.spyOn(queueDepth, 'set');
      consumer = new MessageConsumer(consumerConfig, processor);

      await consumer.connect();

      publishMockMessage(
        consumerConfig.exchange,
        consumerConfig.routingKey,
        Buffer.from(JSON.stringify(classificationMessage)),
        { messageId: classificationMessage.messageId }
      );

      await new Promise((resolve) => setImmediate(resolve));
      expect(processor).toHaveBeenCalledWith(expect.objectContaining({ messageId: 'msg-101' }));
      expect(consumer.getConnectionStatus()).toBe(true);

      expect(queueDepthSpy).toHaveBeenCalledWith({ queue: consumerConfig.queue }, expect.any(Number));
      queueDepthSpy.mockRestore();
    });

    it('requeues messages when processor fails', async () => {
      const processor = jest
        .fn(async (_message: PDFClassificationMessage) => {})
        .mockRejectedValue(new Error('boom')) as jest.MockedFunction<MessageProcessor>;
      consumer = new MessageConsumer(consumerConfig, processor);
      await consumer.connect();

      publishMockMessage(
        consumerConfig.exchange,
        consumerConfig.routingKey,
        Buffer.from(JSON.stringify(classificationMessage)),
        { messageId: classificationMessage.messageId }
      );

      await new Promise((resolve) => setImmediate(resolve));
      const requeued = drainMockQueue(consumerConfig.queue);
      expect(requeued).toHaveLength(1);
    });
  });

  describe('MessagePublisher', () => {
    let publisher: MessagePublisher | null = null;

    afterEach(async () => {
      if (publisher) {
        await publisher.disconnect();
        publisher = null;
      }
    });

    const bindQueue = (queueName: string, routingKey: string): void => {
      mockBroker.assertExchange(publisherConfig.exchange);
      mockBroker.assertQueue(queueName);
      mockBroker.bindQueue(queueName, publisherConfig.exchange, routingKey);
    };

    it('publishes parsed invoices when connected', async () => {
      publisher = new MessagePublisher(publisherConfig);
      await publisher.connect();
      bindQueue('parsed-outbound', publisherConfig.routingKey);

      await publisher.publishParsedInvoice(buildParsedInvoiceCommand());

      const outbound = drainMockQueue('parsed-outbound');
      expect(outbound).toHaveLength(1);
      const payload = JSON.parse(outbound[0].content.toString('utf-8'));
      expect(payload.messageId).toBe('parsed-msg-101');
      expect(publisher.getConnectionStatus()).toBe(true);
    });

    it('publishes scanned PDF payloads to OCR routing key', async () => {
      publisher = new MessagePublisher(publisherConfig);
      await publisher.connect();
      bindQueue('ocr-outbound', 'file.image.classify');

      await publisher.publishScannedPDF('msg-202', 'att-202', 'scan.pdf', 'YmFzZTY0', 'scanner@example.com');

      const outbound = drainMockQueue('ocr-outbound');
      expect(outbound).toHaveLength(1);
      const command = JSON.parse(outbound[0].content.toString('utf-8'));
      expect(command.messageId).toBe('ocr-msg-202');
    });

    it('throws when publishing without a connection', async () => {
      publisher = new MessagePublisher(publisherConfig);
      await expect(publisher.publishParsedInvoice(buildParsedInvoiceCommand())).rejects.toThrow(
        'Publisher not connected'
      );
    });
  });
});
