import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, jest } from '@jest/globals';
import {
  publishMockMessage,
  drainMockQueue,
  resetMockBroker,
  mockBroker,
} from 'amqplib-mocks';
import { MessageConsumer, type MessageBusConfig, type PDFClassificationMessage } from '../../src/message-consumer.js';
import { MessagePublisher, type PublisherConfig } from '../../src/message-publisher.js';
import type { ParsedInvoice } from '../../src/invoice-parser.js';

const classificationConfig: MessageBusConfig = {
  url: 'amqp://mock',
  exchange: 'eracun.files',
  queue: 'pdf-parser-queue',
  routingKey: 'file.pdf.classify',
  prefetchCount: 5,
};

const publisherConfig: PublisherConfig = {
  url: 'amqp://mock',
  exchange: 'parsed.invoices',
  routingKey: 'pdf.invoice.parsed',
  persistent: true,
};

const parsedQueueName = 'pdf-parser-outbound';

let publisher: MessagePublisher;
let consumer: MessageConsumer;
let intervalSpy: ReturnType<typeof jest.spyOn>;

beforeAll(() => {
  intervalSpy = jest.spyOn(global, 'setInterval').mockImplementation((() => ({
    ref() {
      return this;
    },
    unref() {
      return this;
    },
  })) as unknown as typeof setInterval);
});

afterAll(() => {
  intervalSpy.mockRestore();
});

beforeEach(async () => {
  resetMockBroker();
  mockBroker.assertExchange(publisherConfig.exchange);
  mockBroker.assertQueue(parsedQueueName);
  mockBroker.bindQueue(parsedQueueName, publisherConfig.exchange, publisherConfig.routingKey);

  publisher = new MessagePublisher(publisherConfig);
  await publisher.connect();

  consumer = new MessageConsumer(classificationConfig, async (message) => {
    await publisher.publishParsedInvoice(createParsedInvoiceCommand(message));
  });
  await consumer.connect();
});

afterEach(async () => {
  await consumer.disconnect();
  await publisher.disconnect();
  resetMockBroker();
});

describe('PDF parser message flow', () => {
  it('consumes classification events and republishes parsed invoices', async () => {
    const classificationMessage: PDFClassificationMessage = {
      messageId: 'msg-001',
      emailMessageId: 'email-123',
      attachmentId: 'att-456',
      filename: 'invoice.pdf',
      classification: {
        processor: 'file-classifier',
        priority: 'normal',
        category: 'invoice',
        mimeType: 'application/pdf',
        extension: 'pdf',
        size: 2048,
        confidence: '0.92',
      },
      content: Buffer.from('test').toString('base64'),
      timestamp: new Date().toISOString(),
      source: 'mailbox@example.com',
    };

    publishMockMessage(
      classificationConfig.exchange,
      classificationConfig.routingKey,
      Buffer.from(JSON.stringify(classificationMessage)),
      { messageId: classificationMessage.messageId }
    );

    await new Promise((resolve) => setTimeout(resolve, 0));

    const outboundMessages = drainMockQueue(parsedQueueName);
    expect(outboundMessages).toHaveLength(1);
    const payload = JSON.parse(outboundMessages[0].content.toString('utf-8'));
    expect(payload.messageId).toBe('parsed-msg-001');
    expect(payload.invoice.extractedFields).toHaveLength(4);
    expect(payload.pdfMetadata.pageCount).toBe(1);
  });
});

function createParsedInvoiceCommand(message: PDFClassificationMessage) {
  const invoice: ParsedInvoice = {
    invoiceNumber: 'INV-2024-001',
    invoiceDate: new Date(message.timestamp),
    vendor: {
      name: 'Issuer d.o.o.',
      oib: '12345678903',
      iban: 'HR1210010051863000160',
    },
    customer: {
      name: 'Buyer d.o.o.',
      oib: '98765432109',
    },
    lineItems: [
      {
        description: 'Digital archiving service',
        quantity: 1,
        unitPrice: 100,
        vatRate: 0.25,
        amount: 125.4,
      },
    ],
    amounts: {
      subtotal: 100,
      vatAmount: 25.4,
      total: 125.4,
      currency: 'EUR',
    },
    confidence: 'high',
    extractedFields: ['invoiceNumber', 'vendor.oib', 'customer.oib', 'amounts.total'],
  };

  return {
    messageId: 'parsed-' + message.messageId,
    emailMessageId: message.emailMessageId,
    attachmentId: message.attachmentId,
    filename: message.filename,
    pdfMetadata: {
      pageCount: 1,
      isScanned: false,
      quality: 'high',
      size: message.classification.size,
    },
    invoice,
    timestamp: new Date().toISOString(),
    source: message.source,
  };
}
