/**
 * Invoice Controller
 * Handles invoice submission and status operations
 */

import { Request, Response } from 'express';
import { Container } from 'inversify';
import { v4 as uuidv4 } from 'uuid';
import { InvoiceSubmission } from '../types/schemas';
import { createError } from '../middleware/error-handler';
import pino from 'pino';

const logger = pino({ name: 'invoice-controller' });

// In-memory invoice store (production should use database)
interface InvoiceRecord {
  id: string;
  invoiceNumber: string;
  status: 'QUEUED' | 'PROCESSING' | 'VALIDATING' | 'VALIDATED' | 'COMPLETED' | 'FAILED';
  data: any;
  submittedAt: string;
  updatedAt: string;
}

const invoiceStore = new Map<string, InvoiceRecord>();

export class InvoiceController {
  constructor(private container: Container) {}

  /**
   * Submit invoice for processing
   */
  async submitInvoice(req: Request, res: Response): Promise<void> {
    const invoiceData: InvoiceSubmission = req.body;
    const invoiceId = uuidv4();

    logger.info({
      invoiceId,
      invoiceNumber: invoiceData.invoiceNumber,
      requestId: req.requestId,
      idempotencyKey: req.idempotencyKey,
    }, 'Invoice submission received');

    // Create invoice record
    const invoice: InvoiceRecord = {
      id: invoiceId,
      invoiceNumber: invoiceData.invoiceNumber,
      status: 'QUEUED',
      data: invoiceData,
      submittedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Store invoice
    invoiceStore.set(invoiceId, invoice);

    // TODO: Publish to message bus for async processing
    // const command: ProcessInvoiceCommand = {
    //   type: 'PROCESS_INVOICE',
    //   correlationId: req.requestId,
    //   timestamp: new Date().toISOString(),
    //   payload: {
    //     source: 'api',
    //     sourceId: invoiceId,
    //     content: Buffer.from(JSON.stringify(invoiceData)).toString('base64'),
    //     format: 'json',
    //     metadata: { idempotencyKey: req.idempotencyKey }
    //   }
    // };

    // Return 202 Accepted
    res.status(202).json({
      invoiceId,
      status: 'QUEUED',
      trackingUrl: `${req.protocol}://${req.get('host')}/api/v1/invoices/${invoiceId}`,
      acceptedAt: invoice.submittedAt,
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

    const invoice = invoiceStore.get(invoiceId);

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
      submittedAt: invoice.submittedAt,
      updatedAt: invoice.updatedAt,
    });
  }

  private getProgressStep(status: string): string {
    const steps: Record<string, string> = {
      QUEUED: 'Queued for processing',
      PROCESSING: 'Initial processing',
      VALIDATING: 'Running validation',
      VALIDATED: 'Validation complete',
      COMPLETED: 'Processing complete',
      FAILED: 'Processing failed',
    };
    return steps[status] || 'Unknown';
  }

  private getProgressPercentage(status: string): number {
    const percentages: Record<string, number> = {
      QUEUED: 10,
      PROCESSING: 30,
      VALIDATING: 50,
      VALIDATED: 70,
      COMPLETED: 100,
      FAILED: 0,
    };
    return percentages[status] || 0;
  }
}
