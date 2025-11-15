import fc from 'fast-check';
import { createHash } from 'crypto';

process.env.NODE_ENV = 'development';
process.env.ARCHIVE_DATABASE_URL = process.env.ARCHIVE_DATABASE_URL || 'postgres://unit:test@localhost:5432/archive';
process.env.RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost';
process.env.ARCHIVE_ENVELOPE_KEY = process.env.ARCHIVE_ENVELOPE_KEY || 'test-envelope-key';

const fcConfig = { numRuns: 40, interruptAfterTimeLimit: 5000 } as const;
import { ArchiveService, type ArchiveInvoiceCommand } from '../../src/services/archive-service';
import { MockWORMStorage } from '../../src/storage/mock-worm-storage';
import { InvoiceRepository, type Invoice } from '../../src/repositories/invoice-repository';
import {
  invoicePropertyArb,
  payloadDigestArb,
  type InvoicePropertySample,
  type PayloadDigestSample,
} from '../../../../shared/testing/property-generators';

class InMemoryInvoiceRepository extends InvoiceRepository {
  private readonly invoices = new Map<string, Invoice>();

  constructor() {
    super('postgresql://localhost:5432/property_tests');
  }

  override async findById(invoiceId: string): Promise<Invoice | null> {
    return this.invoices.get(invoiceId) ?? null;
  }

  override async create(invoice: Invoice): Promise<void> {
    const existing = this.invoices.get(invoice.invoiceId);
    if (existing) {
      if (existing.sha512Hash === invoice.sha512Hash) {
        return;
      }
      throw new Error(`Invoice ${invoice.invoiceId} already exists with different content`);
    }

    this.invoices.set(invoice.invoiceId, invoice);
  }

  override async updateSignatureStatus(
    invoiceId: string,
    status: 'VALID' | 'PENDING' | 'INVALID' | 'EXPIRED'
  ): Promise<void> {
    const invoice = this.invoices.get(invoiceId);
    if (!invoice) {
      throw new Error('Invoice not found');
    }

    invoice.signatureStatus = status;
    invoice.signatureLastChecked = new Date();
  }

  override async findByFilter(): Promise<Invoice[]> {
    return Array.from(this.invoices.values());
  }

  override async close(): Promise<void> {
    this.invoices.clear();
  }
}

function toArchiveCommand(sample: InvoicePropertySample): ArchiveInvoiceCommand {
  return {
    invoiceId: sample.invoiceId,
    originalXml: sample.base64Xml,
    submissionChannel: sample.submissionChannel,
    confirmationReference: sample.confirmationReference,
    submissionTimestamp: sample.submissionTimestamp,
  };
}

describe('Archive validators - property based', () => {
  it('preserves payload round-trips through storage', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample: InvoicePropertySample) => {
        const storage = new MockWORMStorage();
        const repo = new InMemoryInvoiceRepository();
        const service = new ArchiveService(storage, repo);
        const command = toArchiveCommand(sample);

        await service.archiveInvoice(command);
        const retrieved = await storage.retrieve(command.invoiceId);

        expect(retrieved.available).toBe(true);
        expect(retrieved.content?.toString('base64')).toEqual(sample.base64Xml);
      }),
      fcConfig
    );
  });

  it('produces deterministic SHA-512 hashes', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample: InvoicePropertySample) => {
        const storage = new MockWORMStorage();
        const repo = new InMemoryInvoiceRepository();
        const service = new ArchiveService(storage, repo);
        const command = toArchiveCommand(sample);

        const result = await service.archiveInvoice(command);
        const expectedHash = createHash('sha512')
          .update(Buffer.from(sample.base64Xml, 'base64'))
          .digest('hex');

        expect(result.sha512Hash).toEqual(expectedHash);

        const replay = await service.archiveInvoice(command);
        expect(replay.sha512Hash).toEqual(expectedHash);
      }),
      fcConfig
    );
  });

  it('treats byte-identical duplicates as idempotent writes', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample: InvoicePropertySample) => {
        const storage = new MockWORMStorage();
        const repo = new InMemoryInvoiceRepository();
        const service = new ArchiveService(storage, repo);
        const command = toArchiveCommand(sample);

        const first = await service.archiveInvoice(command);
        const second = await service.archiveInvoice(command);

        expect(second.sha512Hash).toEqual(first.sha512Hash);
        expect(second.storageLocation).toEqual(first.storageLocation);
      }),
      fcConfig
    );
  });

  it('rejects duplicate invoiceIds with mutated payloads', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample: InvoicePropertySample) => {
        const storage = new MockWORMStorage();
        const repo = new InMemoryInvoiceRepository();
        const service = new ArchiveService(storage, repo);
        const command = toArchiveCommand(sample);

        await service.archiveInvoice(command);

        const mutatedXml = Buffer.from(sample.xml.replace(sample.note, `${sample.note}-tampered`), 'utf-8').toString('base64');
        const mutatedCommand: ArchiveInvoiceCommand = {
          ...command,
          originalXml: mutatedXml,
        };

        await expect(service.archiveInvoice(mutatedCommand)).rejects.toThrow(/already exists/);
      }),
      fcConfig
    );
  });

  it('enforces checksum validation inside WORM storage', async () => {
    await fc.assert(
      fc.asyncProperty(payloadDigestArb, async ({ payload, digest }: PayloadDigestSample) => {
        const storage = new MockWORMStorage();
        const objectId = `obj-${payload.length}`;

        const metadata = await storage.store(objectId, payload, {
          tier: 'HOT',
          sha512: digest,
          retentionYears: 11,
        });

        expect(metadata.sha512).toEqual(digest);
        await expect(storage.verifyIntegrity(objectId)).resolves.toBe(true);

        const mismatched = digest[0] === '0' ? `a${digest.slice(1)}` : `0${digest.slice(1)}`;

        await expect(
          storage.store(`${objectId}-tampered`, payload, {
            tier: 'HOT',
            sha512: mismatched,
            retentionYears: 11,
          })
        ).rejects.toThrow(/Hash mismatch/);
      }),
      fcConfig
    );
  });
});
