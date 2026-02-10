import { type Request, type Response } from 'express';
import { getInvoiceById, getInvoicesByOIB, createInvoice as createInvoiceRecord } from '../../archive/invoice-repository.js';
import { submitInvoiceForProcessing } from '../../jobs/invoice-submission.js';
import { validationMiddleware } from '../middleware/validate.js';
import { invoiceSubmissionSchema } from '../schemas.js';
import { logger } from '../../shared/logger.js';
import { NotFoundError, BadRequestError, InternalError, buildErrorResponse } from '../errors.js';

// GET /api/v1/invoices/:id
export async function getInvoiceByIdHandler(req: Request, res: Response): Promise<void> {
  const { id } = req.params;

  const invoice = await getInvoiceById(String(id));

  if (!invoice) {
    const error = new NotFoundError('Invoice not found');
    res.status(404).json(buildErrorResponse(error, req.id, 404));
    return;
  }

  res.json(invoice);
}

// GET /api/v1/invoices/:id/status
export async function getInvoiceStatusHandler(req: Request, res: Response): Promise<void> {
  const { id } = req.params;

  const invoice = await getInvoiceById(String(id));

  if (!invoice) {
    const error = new NotFoundError('Invoice not found');
    res.status(404).json(buildErrorResponse(error, req.id, 404));
    return;
  }

  res.json({
    id: invoice.id,
    status: invoice.status,
    jir: invoice.jir,
    createdAt: invoice.createdAt,
    submittedAt: invoice.submittedAt,
  });
}

// POST /api/v1/invoices
export async function submitInvoiceHandler(req: Request, res: Response): Promise<void> {
  const invoiceData = req.body;

  try {
    // Create database record first
    const invoice = await createInvoiceRecord({
      oib: invoiceData.oib,
      invoiceNumber: invoiceData.invoiceNumber,
      originalXml: invoiceData.originalXml || '',
      signedXml: invoiceData.signedXml || '',
    });

    // Enqueue async processing job
    const jobId = await submitInvoiceForProcessing({
      invoiceId: invoice.id,
      oib: invoice.oib,
      invoiceNumber: invoice.invoiceNumber,
      originalXml: invoice.originalXml,
      signedXml: invoice.signedXml,
    });

    logger.info({
      invoiceId: invoice.id,
      jobId,
    }, 'Invoice submitted for processing');

    res.status(202).json({
      invoiceId: invoice.id,
      jobId,
      status: 'queued',
    });
  } catch (error) {
    logger.error({
      error: error instanceof Error ? error.message : String(error),
    }, 'Failed to submit invoice');

    const internalError = new InternalError('Failed to submit invoice', error instanceof Error ? error : undefined);
    res.status(500).json(buildErrorResponse(internalError, req.id, 500));
  }
}

// GET /api/v1/invoices?oib=xxx&limit=50&offset=0
export async function getInvoicesByOIBHandler(req: Request, res: Response): Promise<void> {
  const oib = req.query.oib as string;
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
  const offset = req.query.offset ? parseInt(req.query.offset as string, 10) : 0;

  if (!oib) {
    const error = new BadRequestError('Missing required query parameter: oib');
    res.status(400).json(buildErrorResponse(error, req.id, 400));
    return;
  }

  const invoices = await getInvoicesByOIB(oib, limit, offset);

  res.json({
    invoices,
    count: invoices.length,
    limit,
    offset,
  });
}

// Route handlers with validation middleware
export const invoiceRoutes = [
  {
    path: '/:id',
    method: 'get',
    handler: getInvoiceByIdHandler,
  },
  {
    path: '/:id/status',
    method: 'get',
    handler: getInvoiceStatusHandler,
  },
  {
    path: '/',
    method: 'get',
    handler: getInvoicesByOIBHandler,
  },
  {
    path: '/',
    method: 'post',
    handler: submitInvoiceHandler,
    middleware: [validationMiddleware(invoiceSubmissionSchema)],
  },
];
