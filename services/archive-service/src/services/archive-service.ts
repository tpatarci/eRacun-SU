/**
 * Archive Service (Business Logic)
 *
 * Orchestrates invoice archival workflow:
 * 1. Validate payload
 * 2. Check idempotency
 * 3. Store metadata in PostgreSQL
 * 4. Upload XML to WORM storage
 * 5. Emit InvoiceArchivedEvent
 *
 * Implements 11-year retention with WORM storage (Object Lock compliance mode).
 *
 * See: docs/adr/004-archive-compliance-layer.md §47-54
 */

import { createHash } from 'crypto';
import { createLogger } from '../utils/logger';
import { IWORMStorage } from '../storage/interfaces';
import { InvoiceRepository, Invoice } from '../repositories/invoice-repository';

const logger = createLogger('archive-service');

export interface ArchiveInvoiceCommand {
  invoiceId: string;
  originalXml: string; // base64-encoded
  submissionChannel: 'B2C' | 'B2B';
  confirmationReference: {
    type: 'JIR' | 'UUID';
    value: string;
  };
  submissionTimestamp: string; // RFC3339
}

export interface ArchiveResult {
  invoiceId: string;
  sha512Hash: string;
  storageLocation: string;
  retentionUntil: string;
}

export interface SignatureValidationResult {
  invoiceId: string;
  status: 'VALID' | 'INVALID' | 'EXPIRED';
  validatedAt: Date;
  details: Record<string, unknown>;
}

export class ArchiveService {
  private static readonly MAX_INVOICE_SIZE = 10 * 1024 * 1024; // 10MB

  constructor(
    private readonly storage: IWORMStorage,
    private readonly repository: InvoiceRepository,
    private readonly signatureServiceUrl?: string
  ) {}

  /**
   * Archive invoice with 11-year retention
   *
   * @param command - Archive command
   * @returns Archive result with storage metadata
   * @throws Error if validation fails or storage error
   */
  async archiveInvoice(command: ArchiveInvoiceCommand): Promise<ArchiveResult> {
    logger.info('Archiving invoice', { invoiceId: command.invoiceId });

    // 1. Validate payload
    this.validateCommand(command);

    // 2. Decode base64 XML
    const xmlBuffer = Buffer.from(command.originalXml, 'base64');

    // 3. Validate size
    if (xmlBuffer.length > ArchiveService.MAX_INVOICE_SIZE) {
      throw new Error(
        `Invoice exceeds maximum size: ${xmlBuffer.length} > ${ArchiveService.MAX_INVOICE_SIZE}`
      );
    }

    // 4. Compute SHA-512 hash
    const sha512Hash = this.computeSHA512(xmlBuffer);

    // 5. Check idempotency (query repository)
    const existing = await this.repository.findById(command.invoiceId);
    if (existing) {
      if (existing.sha512Hash === sha512Hash) {
        // Idempotent - same invoice already archived
        logger.info('Invoice already archived (idempotent)', { invoiceId: command.invoiceId });
        return {
          invoiceId: command.invoiceId,
          sha512Hash: existing.sha512Hash,
          storageLocation: `${existing.storageMetadata.bucket}/${existing.storageMetadata.key}`,
          retentionUntil: existing.storageMetadata.retentionUntil,
        };
      }

      // Different content - conflict
      throw new Error(`Invoice ${command.invoiceId} already exists with different content`);
    }

    // 6. Store in WORM storage (HOT tier by default)
    const storageMetadata = await this.storage.store(command.invoiceId, xmlBuffer, {
      tier: 'HOT',
      sha512: sha512Hash,
      retentionYears: 11, // Croatian law requires 11 years
      tags: {
        channel: command.submissionChannel,
        confirmationType: command.confirmationReference.type,
        confirmationValue: command.confirmationReference.value,
      },
    });

    logger.info('Invoice stored in WORM storage', {
      invoiceId: command.invoiceId,
      tier: storageMetadata.tier,
      size: storageMetadata.contentLength,
    });

    // 7. Store metadata in PostgreSQL
    const invoice: Invoice = {
      invoiceId: command.invoiceId,
      originalXml: command.originalXml,
      sha512Hash,
      contentLength: xmlBuffer.length,
      submissionChannel: command.submissionChannel,
      confirmationReference: command.confirmationReference,
      submissionTimestamp: new Date(command.submissionTimestamp),
      signatureStatus: 'PENDING', // Will be validated later
      storageMetadata,
      createdAt: new Date(),
      retentionExpiresAt: new Date(storageMetadata.retentionUntil),
    };

    await this.repository.create(invoice);

    logger.info('Invoice archived successfully', {
      invoiceId: command.invoiceId,
      retentionUntil: storageMetadata.retentionUntil,
    });

    // 8. Emit InvoiceArchivedEvent (TODO: Message bus integration)
    // await this.messageBus.publish('InvoiceArchivedEvent', { invoiceId: command.invoiceId });

    return {
      invoiceId: command.invoiceId,
      sha512Hash,
      storageLocation: `${storageMetadata.bucket}/${storageMetadata.key}`,
      retentionUntil: storageMetadata.retentionUntil,
    };
  }

  /**
   * Validate invoice signature
   *
   * @param invoiceId - Invoice identifier
   * @returns Validation result
   * @throws Error if invoice not found or validation service unavailable
   */
  async validateSignature(invoiceId: string): Promise<SignatureValidationResult> {
    logger.info('Validating signature', { invoiceId });

    // 1. Retrieve invoice from repository
    const invoice = await this.repository.findById(invoiceId);
    if (!invoice) {
      throw new Error(`Invoice not found: ${invoiceId}`);
    }

    // 2. Retrieve XML from storage
    const retrieveResult = await this.storage.retrieve(invoiceId);
    if (!retrieveResult.available) {
      throw new Error(`Invoice not available for validation: ${invoiceId}`);
    }

    // 3. Verify integrity
    const actualHash = this.computeSHA512(retrieveResult.content!);
    if (actualHash !== invoice.sha512Hash) {
      logger.error('Integrity check failed', {
        invoiceId,
        expected: invoice.sha512Hash,
        actual: actualHash,
      });

      // Update status to INVALID
      await this.repository.updateSignatureStatus(invoiceId, 'INVALID', 'archive-service');

      return {
        invoiceId,
        status: 'INVALID',
        validatedAt: new Date(),
        details: {
          reason: 'Hash mismatch',
          expected: invoice.sha512Hash,
          actual: actualHash,
        },
      };
    }

    // 4. Call digital-signature-service (if configured)
    let signatureValid = false;
    if (this.signatureServiceUrl) {
      try {
        signatureValid = await this.callSignatureService(retrieveResult.content!);
      } catch (error) {
        logger.error('Signature validation service error', { invoiceId, error });
        throw error;
      }
    } else {
      // Mock validation for development
      signatureValid = true;
      logger.warn('Signature service not configured, using mock validation', { invoiceId });
    }

    // 5. Update signature status
    const status = signatureValid ? 'VALID' : 'INVALID';
    await this.repository.updateSignatureStatus(invoiceId, status, 'archive-service');

    logger.info('Signature validation complete', { invoiceId, status });

    return {
      invoiceId,
      status,
      validatedAt: new Date(),
      details: {
        integrityCheck: 'PASSED',
        signatureCheck: signatureValid ? 'PASSED' : 'FAILED',
      },
    };
  }

  /**
   * Batch validate signatures (for monthly workflow)
   *
   * @param invoiceIds - Array of invoice IDs
   * @returns Array of validation results
   */
  async batchValidateSignatures(invoiceIds: string[]): Promise<SignatureValidationResult[]> {
    logger.info('Starting batch signature validation', { count: invoiceIds.length });

    const results: SignatureValidationResult[] = [];

    for (const invoiceId of invoiceIds) {
      try {
        const result = await this.validateSignature(invoiceId);
        results.push(result);
      } catch (error) {
        logger.error('Batch validation error', { invoiceId, error });
        results.push({
          invoiceId,
          status: 'INVALID',
          validatedAt: new Date(),
          details: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });
      }
    }

    const validCount = results.filter((r) => r.status === 'VALID').length;
    logger.info('Batch signature validation complete', {
      total: results.length,
      valid: validCount,
      invalid: results.length - validCount,
    });

    return results;
  }

  /**
   * Get invoices pending signature validation
   *
   * @returns Array of invoice IDs
   */
  async getPendingValidationInvoices(): Promise<string[]> {
    const invoices = await this.repository.findByFilter({
      signatureStatus: 'PENDING',
      limit: 10000,
    });

    return invoices.map((inv) => inv.invoiceId);
  }

  /**
   * Get invoices for monthly re-validation
   *
   * @returns Array of invoice IDs
   */
  async getInvoicesForMonthlyValidation(): Promise<string[]> {
    // Get all invoices that haven't been checked in the last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    // TODO: Add signatureLastCheckedBefore filter to repository
    // For now, return all invoices (will be filtered in production)
    const invoices = await this.repository.findByFilter({
      limit: 100000, // Large limit for monthly batch
    });

    return invoices
      .filter((inv) => {
        if (!inv.signatureLastChecked) return true;
        return inv.signatureLastChecked < thirtyDaysAgo;
      })
      .map((inv) => inv.invoiceId);
  }

  /**
   * Close service and release resources
   */
  async close(): Promise<void> {
    await this.storage.close();
    await this.repository.close();
    logger.info('Archive service closed');
  }

  // --- Private Methods ---

  private validateCommand(command: ArchiveInvoiceCommand): void {
    if (!command.invoiceId || typeof command.invoiceId !== 'string') {
      throw new Error('Invalid invoiceId');
    }

    if (!command.originalXml || typeof command.originalXml !== 'string') {
      throw new Error('Invalid originalXml');
    }

    if (!['B2C', 'B2B'].includes(command.submissionChannel)) {
      throw new Error('Invalid submissionChannel');
    }

    if (!['JIR', 'UUID'].includes(command.confirmationReference.type)) {
      throw new Error('Invalid confirmationReference.type');
    }

    if (!command.confirmationReference.value) {
      throw new Error('Invalid confirmationReference.value');
    }

    // Validate RFC3339 timestamp
    if (!command.submissionTimestamp || isNaN(Date.parse(command.submissionTimestamp))) {
      throw new Error('Invalid submissionTimestamp');
    }
  }

  private computeSHA512(data: Buffer): string {
    return createHash('sha512').update(data).digest('hex');
  }

  private async callSignatureService(xmlContent: Buffer): Promise<boolean> {
    if (!this.signatureServiceUrl) {
      throw new Error('Signature service URL not configured');
    }

    // TODO: Implement HTTP call to digital-signature-service
    // For now, mock implementation
    logger.warn('Using mock signature validation');
    return true;
  }
}

