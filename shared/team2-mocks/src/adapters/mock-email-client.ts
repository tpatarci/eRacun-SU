/**
 * Mock Email Client
 * Simulates IMAP email behavior for testing without real email server
 */

import { faker } from '@faker-js/faker';
import { IEmailClient } from './interfaces';
import { EmailMessage, Attachment, FetchOptions } from '../types/email-types';
import { generateValidUBL } from '../generators/invoice-generator';

export class MockEmailClient implements IEmailClient {
  private mockInbox: EmailMessage[] = [];
  private connected = false;

  constructor(seedCount: number = 15) {
    // Generate mock emails on initialization
    this.seedMockInbox(seedCount);
  }

  /**
   * Connect to email server
   */
  async connect(): Promise<void> {
    // Simulate connection delay
    await this.delay(300);
    this.connected = true;
  }

  /**
   * Disconnect from email server
   */
  async disconnect(): Promise<void> {
    await this.delay(100);
    this.connected = false;
  }

  /**
   * Fetch unread messages
   */
  async fetchUnread(options?: FetchOptions): Promise<EmailMessage[]> {
    this.ensureConnected();

    // Filter unread messages
    let messages = this.mockInbox.filter(m => !m.read);

    // Apply filters
    if (options?.since) {
      messages = messages.filter(m => m.date >= options.since!);
    }

    if (options?.before) {
      messages = messages.filter(m => m.date <= options.before!);
    }

    if (options?.withAttachments) {
      messages = messages.filter(m => m.attachments.length > 0);
    }

    // Apply limit
    if (options?.limit) {
      messages = messages.slice(0, options.limit);
    }

    // Mark as read
    messages.forEach(m => m.read = true);

    // Simulate network delay
    await this.delay(200);

    return messages;
  }

  /**
   * Fetch specific message by ID
   */
  async fetchMessage(messageId: string): Promise<EmailMessage> {
    this.ensureConnected();

    const message = this.mockInbox.find(m => m.id === messageId);
    if (!message) {
      throw new Error(`Message ${messageId} not found`);
    }

    await this.delay(150);
    return message;
  }

  /**
   * Mark message as processed
   */
  async markAsProcessed(messageId: string): Promise<void> {
    this.ensureConnected();

    const message = this.mockInbox.find(m => m.id === messageId);
    if (message) {
      message.processed = true;
      message.labels.push('PROCESSED', 'ERACUN');
    }

    await this.delay(100);
  }

  /**
   * Download attachment
   */
  async downloadAttachment(messageId: string, attachmentId: string): Promise<Buffer> {
    this.ensureConnected();

    const message = this.mockInbox.find(m => m.id === messageId);
    if (!message) {
      throw new Error(`Message ${messageId} not found`);
    }

    const attachment = message.attachments.find(a => a.id === attachmentId);
    if (!attachment) {
      throw new Error(`Attachment ${attachmentId} not found in message ${messageId}`);
    }

    // Simulate download delay based on file size
    const delaytime = Math.min(100 + (attachment.size / 10000), 2000);
    await this.delay(delaytime);

    // Return cached content or generate mock content
    if (attachment.content) {
      return attachment.content;
    }

    // Generate mock content based on type
    return this.generateAttachmentContent(attachment);
  }

  /**
   * Search messages
   */
  async search(criteria: Record<string, any>): Promise<EmailMessage[]> {
    this.ensureConnected();

    let results = [...this.mockInbox];

    if (criteria.from) {
      results = results.filter(m =>
        m.from.toLowerCase().includes(criteria.from.toLowerCase())
      );
    }

    if (criteria.subject) {
      results = results.filter(m =>
        m.subject.toLowerCase().includes(criteria.subject.toLowerCase())
      );
    }

    if (criteria.hasAttachment) {
      results = results.filter(m => m.attachments.length > 0);
    }

    await this.delay(250);
    return results;
  }

  /**
   * Move message to folder
   */
  async moveMessage(messageId: string, folder: string): Promise<void> {
    this.ensureConnected();

    const message = this.mockInbox.find(m => m.id === messageId);
    if (message) {
      message.labels.push(`FOLDER_${folder.toUpperCase()}`);
    }

    await this.delay(100);
  }

  /**
   * Seed inbox with mock emails for testing
   */
  seedMockInbox(count: number): void {
    this.mockInbox = [];

    for (let i = 0; i < count; i++) {
      this.mockInbox.push(this.generateMockEmail());
    }
  }

  /**
   * Seed specific invoice email for testing
   */
  seedInvoiceEmail(options: {
    type: 'pdf' | 'xml' | 'zip';
    supplierOIB?: string;
    hasErrors?: boolean;
  }): string {
    const email = this.generateMockEmail();

    // Clear default attachments and add specific one
    email.attachments = [];

    const filename = `invoice_${Date.now()}.${options.type}`;
    const attachment: Attachment = {
      id: faker.string.uuid(),
      filename,
      mimeType: this.getMimeType(options.type),
      size: faker.number.int({ min: 50000, max: 500000 })
    };

    // Generate content based on type
    if (options.type === 'xml') {
      attachment.content = Buffer.from(generateValidUBL());
    } else if (options.type === 'pdf') {
      attachment.content = this.generateMockPDF();
    } else if (options.type === 'zip') {
      attachment.content = this.generateMockZIP();
    }

    email.attachments.push(attachment);
    email.subject = `Invoice ${filename}`;
    email.read = false;
    email.processed = false;

    this.mockInbox.push(email);

    return email.id;
  }

  /**
   * Seed corrupted email for error testing
   */
  seedCorruptedEmail(): string {
    const email = this.generateMockEmail();
    email.subject = 'Corrupted Invoice';
    email.attachments = [{
      id: faker.string.uuid(),
      filename: 'corrupted.pdf',
      mimeType: 'application/pdf',
      size: 1000,
      content: Buffer.from('CORRUPTED_DATA_NOT_A_PDF')
    }];

    this.mockInbox.push(email);
    return email.id;
  }

  // Private helper methods

  private ensureConnected(): void {
    if (!this.connected) {
      throw new Error('Email client not connected. Call connect() first.');
    }
  }

  private generateMockEmail(): EmailMessage {
    const hasAttachment = Math.random() > 0.3; // 70% have attachments

    return {
      id: faker.string.uuid(),
      from: faker.internet.email(),
      to: 'invoices@eracun.hr',
      cc: Math.random() > 0.7 ? [faker.internet.email()] : undefined,
      subject: this.generateSubject(),
      body: faker.lorem.paragraphs(2),
      htmlBody: `<p>${faker.lorem.paragraphs(2)}</p>`,
      date: faker.date.recent({ days: 7 }),
      read: false,
      processed: false,
      attachments: hasAttachment ? this.generateAttachments() : [],
      labels: [],
      headers: {
        'message-id': `<${faker.string.uuid()}@${faker.internet.domainName()}>`,
        'return-path': faker.internet.email(),
        'x-mailer': 'Mock Email Client 1.0'
      },
      priority: faker.helpers.arrayElement(['low', 'normal', 'normal', 'high']) as any
    };
  }

  private generateSubject(): string {
    const templates = [
      `Račun br. ${faker.number.int({ min: 1000, max: 9999 })}`,
      `Invoice ${faker.date.recent().toISOString().split('T')[0]}`,
      `Faktura - ${faker.company.name()}`,
      'RE: Dostava računa',
      'Fwd: Invoice for services',
      `Račun ${faker.number.int({ min: 1000, max: 9999 })}/${new Date().getFullYear()}`,
      'Nova faktura za pregled',
      'Invoice attached - please process'
    ];

    return faker.helpers.arrayElement(templates);
  }

  private generateAttachments(): Attachment[] {
    const count = Math.floor(Math.random() * 3) + 1; // 1-3 attachments
    const attachments: Attachment[] = [];

    for (let i = 0; i < count; i++) {
      const type = faker.helpers.arrayElement(['pdf', 'xml', 'zip', 'jpg', 'png']);
      const invoiceNumber = faker.number.int({ min: 1000, max: 9999 });

      attachments.push({
        id: faker.string.uuid(),
        filename: `invoice_${invoiceNumber}.${type}`,
        mimeType: this.getMimeType(type),
        size: faker.number.int({ min: 10000, max: 5000000 })
      });
    }

    return attachments;
  }

  private getMimeType(extension: string): string {
    const mimeTypes: Record<string, string> = {
      pdf: 'application/pdf',
      xml: 'application/xml',
      zip: 'application/zip',
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      png: 'image/png',
      tiff: 'image/tiff'
    };

    return mimeTypes[extension] || 'application/octet-stream';
  }

  private generateAttachmentContent(attachment: Attachment): Buffer {
    const ext = attachment.filename.split('.').pop()?.toLowerCase();

    switch (ext) {
      case 'xml':
        return Buffer.from(generateValidUBL());
      case 'pdf':
        return this.generateMockPDF();
      case 'zip':
        return this.generateMockZIP();
      case 'jpg':
      case 'jpeg':
      case 'png':
        return this.generateMockImage();
      default:
        return Buffer.from(`Mock content for ${attachment.filename}`);
    }
  }

  private generateMockPDF(): Buffer {
    // Generate a minimal mock PDF structure
    const mockContent = `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Mock Invoice) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000214 00000 n
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
307
%%EOF`;

    return Buffer.from(mockContent);
  }

  private generateMockZIP(): Buffer {
    // Minimal ZIP file structure (empty archive)
    const zipHeader = Buffer.from([
      0x50, 0x4B, 0x05, 0x06, // End of central directory signature
      0x00, 0x00, 0x00, 0x00, // Number of this disk
      0x00, 0x00, 0x00, 0x00, // Disk where central directory starts
      0x00, 0x00,             // Number of central directory records on this disk
      0x00, 0x00,             // Total number of central directory records
      0x00, 0x00, 0x00, 0x00, // Size of central directory
      0x00, 0x00, 0x00, 0x00, // Offset of start of central directory
      0x00, 0x00              // ZIP file comment length
    ]);

    return zipHeader;
  }

  private generateMockImage(): Buffer {
    // Minimal 1x1 pixel PNG
    const png = Buffer.from([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 dimensions
      0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
      0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
      0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
      0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
      0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
      0x44, 0xAE, 0x42, 0x60, 0x82 // IEND chunk
    ]);

    return png;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
