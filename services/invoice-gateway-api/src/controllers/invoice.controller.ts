/**
 * Invoice Controller
 * Handles invoice submission and status operations
 */

import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { ProcessInvoiceCommand } from '@eracun/contracts';
import { InvoiceSubmission } from '../types/schemas';
import { createError } from '../middleware/error-handler';
import pino from 'pino';
import {
  InvoiceRepository,
  InvoiceStatus,
} from '../repositories/invoice.repository';
import { ProcessInvoiceCommandPublisher } from '../messaging/process-invoice.publisher';

const logger = pino({ name: 'invoice-controller' });

export class InvoiceController {
  constructor(
    private readonly repository: InvoiceRepository,
    private readonly publisher: ProcessInvoiceCommandPublisher
  ) {}

  /**
   * Submit invoice for processing
   */
  async submitInvoice(req: Request, res: Response): Promise<void> {
    if (!req.idempotencyKey) {
      throw createError(
        'Idempotency key is required',
        400,
        'MISSING_IDEMPOTENCY_KEY'
      );
    }

    const invoiceData: InvoiceSubmission = req.body;
    const invoiceId = uuidv4();
    const supplierOIB = this.extractOIB(invoiceData.supplier.vatNumber);
    const buyerOIB = this.extractOIB(invoiceData.buyer.vatNumber);

    logger.info({
      invoiceId,
      invoiceNumber: invoiceData.invoiceNumber,
      requestId: req.requestId,
      idempotencyKey: req.idempotencyKey,
    }, 'Invoice submission received');

    const persistedInvoice = await this.repository.saveInvoice({
      id: invoiceId,
      idempotencyKey: req.idempotencyKey,
      invoiceNumber: invoiceData.invoiceNumber,
      supplierOIB,
      buyerOIB,
      totalAmount: invoiceData.amounts.gross,
      currency: invoiceData.amounts.currency,
      status: 'QUEUED',
    });

    const command: ProcessInvoiceCommand = {
      type: 'PROCESS_INVOICE',
      correlationId: req.requestId,
      timestamp: new Date().toISOString(),
      payload: {
        source: 'api',
        sourceId: persistedInvoice.id,
        content: Buffer.from(JSON.stringify(invoiceData)).toString('base64'),
        format: 'json',
        metadata: {
          idempotencyKey: req.idempotencyKey,
          invoiceNumber: invoiceData.invoiceNumber,
          supplierOIB,
          buyerOIB,
          submittedAt: persistedInvoice.createdAt.toISOString(),
        },
      },
    };

    await this.publisher.publish(command);

    // Return 202 Accepted
    res.status(202).json({
      invoiceId: persistedInvoice.id,
      status: persistedInvoice.status,
      trackingUrl: `${req.protocol}://${req.get('host')}/api/v1/invoices/${persistedInvoice.id}`,
      acceptedAt: persistedInvoice.createdAt.toISOString(),
    });
  }

  /**
   * Get invoice status
   */
  async getInvoiceStatus(req: Request, res: Response): Promise<void> {
    const { invoiceId } = req.params;

    logger.info({
      invoiceId,
      requestId: req.requestId,
    }, 'Invoice status request');

    const invoice = await this.repository.findById(invoiceId);

    if (!invoice) {
      throw createError(
        `Invoice not found: ${invoiceId}`,
        404,
        'INVOICE_NOT_FOUND'
      );
    }

    res.status(200).json({
      invoiceId: invoice.id,
      invoiceNumber: invoice.invoiceNumber,
      status: invoice.status,
      progress: {
        currentStep: this.getProgressStep(invoice.status),
        totalSteps: 6,
        percentage: this.getProgressPercentage(invoice.status),
      },
      submittedAt: invoice.createdAt.toISOString(),
      updatedAt: (invoice.updatedAt || invoice.createdAt).toISOString(),
    });
  }

  private getProgressStep(status: InvoiceStatus): string {
    const steps: Record<InvoiceStatus, string> = {
      QUEUED: 'Queued for processing',
      PROCESSING: 'Initial processing',
      VALIDATING: 'Running validation',
      VALIDATED: 'Validation complete',
      COMPLETED: 'Processing complete',
      FAILED: 'Processing failed',
    };
    return steps[status] || 'Unknown';
  }

  private getProgressPercentage(status: InvoiceStatus): number {
    const percentages: Record<InvoiceStatus, number> = {
      QUEUED: 10,
      PROCESSING: 30,
      VALIDATING: 50,
      VALIDATED: 70,
      COMPLETED: 100,
      FAILED: 0,
    };
    return percentages[status] || 0;
  }

  private extractOIB(vatNumber: string): string {
    return vatNumber.replace(/^HR/i, '');
  }
}
