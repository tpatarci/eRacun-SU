/**
 * Archive Service (Business Logic)
 *
 * Orchestrates invoice archival workflow:
 * 1. Validate payload
 * 2. Check idempotency
 * 3. Store metadata in PostgreSQL
 * 4. Upload XML to S3
 * 5. Emit InvoiceArchivedEvent
 *
 * See: docs/adr/004-archive-compliance-layer.md §47-54
 */

import { createLogger } from '../utils/logger';

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

export class ArchiveService {
  // TODO: Inject repositories, S3 client, RabbitMQ publisher

  async archiveInvoice(command: ArchiveInvoiceCommand): Promise<void> {
    logger.info('Archiving invoice', { invoiceId: command.invoiceId });

    // TODO: Validate payload (size limit, schema)
    // TODO: Check idempotency (invoice_id already exists?)
    // TODO: Decode base64 XML
    // TODO: Compute SHA-512 hash
    // TODO: Store metadata in PostgreSQL (serializable transaction)
    // TODO: Upload to S3 hot bucket (multipart, Object Lock)
    // TODO: Emit InvoiceArchivedEvent

    throw new Error('Not implemented');
  }

  async validateSignature(invoiceId: string): Promise<void> {
    logger.info('Validating signature', { invoiceId });

    // TODO: Retrieve invoice from storage
    // TODO: Call digital-signature-service
    // TODO: Update signature_status in database
    // TODO: Log audit event

    throw new Error('Not implemented');
  }
}
