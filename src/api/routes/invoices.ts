import type { Response } from 'express';
import type { AuthenticatedRequest } from '../../shared/auth.js';
import { authMiddleware } from '../../shared/auth.js';
import { getInvoiceById, getInvoicesByOIB, createInvoice as createInvoiceRecord } from '../../archive/invoice-repository.js';
import { submitInvoiceForProcessing } from '../../jobs/invoice-submission.js';
import { validationMiddleware } from '../middleware/validate.js';
import { invoiceSubmissionSchema } from '../schemas.js';
import { logger } from '../../shared/logger.js';

// GET /api/v1/invoices/:id
export async function getInvoiceByIdHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const { id } = req.params;
  // userId is guaranteed to exist because authMiddleware is used
  const userId = req.user!.id;
  // Express can return id as string[] in edge cases, normalize to string
  const invoiceId = Array.isArray(id) ? id[0] : id;

  const invoice = await getInvoiceById(invoiceId, userId);

  if (!invoice) {
    res.status(404).json({
      error: 'Invoice not found',
      requestId: req.id,
    });
    return;
  }

  res.json(invoice);
}

// GET /api/v1/invoices/:id/status
export async function getInvoiceStatusHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const { id } = req.params;
  // userId is guaranteed to exist because authMiddleware is used
  const userId = req.user!.id;
  // Express can return id as string[] in edge cases, normalize to string
  const invoiceId = Array.isArray(id) ? id[0] : id;

  const invoice = await getInvoiceById(invoiceId, userId);

  if (!invoice) {
    res.status(404).json({
      error: 'Invoice not found',
      requestId: req.id,
    });
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
export async function submitInvoiceHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const invoiceData = req.body;
  // userId is guaranteed to exist because authMiddleware is used
  const userId = req.user!.id;

  try {
    // Create database record first with user context
    const invoice = await createInvoiceRecord({
      oib: invoiceData.oib,
      invoiceNumber: invoiceData.invoiceNumber,
      originalXml: invoiceData.originalXml || '',
      signedXml: invoiceData.signedXml || '',
      userId,
    });

    // Enqueue async processing job with user context
    const jobId = await submitInvoiceForProcessing({
      invoiceId: invoice.id,
      userId,
      oib: invoice.oib,
      invoiceNumber: invoice.invoiceNumber,
      originalXml: invoice.originalXml,
      signedXml: invoice.signedXml,
    });

    logger.info({
      invoiceId: invoice.id,
      userId,
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

    res.status(500).json({
      error: 'Failed to submit invoice',
      requestId: req.id,
    });
  }
}

// GET /api/v1/invoices?oib=xxx&limit=50&offset=0
export async function getInvoicesByOIBHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const oib = req.query.oib as string;
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
  const offset = req.query.offset ? parseInt(req.query.offset as string, 10) : 0;
  // userId is guaranteed to exist because authMiddleware is used
  const userId = req.user!.id;

  if (!oib) {
    res.status(400).json({
      error: 'Missing required query parameter: oib',
      requestId: req.id,
    });
    return;
  }

  const invoices = await getInvoicesByOIB(oib, userId, limit, offset);

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
    middleware: [authMiddleware],
  },
  {
    path: '/:id/status',
    method: 'get',
    handler: getInvoiceStatusHandler,
    middleware: [authMiddleware],
  },
  {
    path: '/',
    method: 'get',
    handler: getInvoicesByOIBHandler,
    middleware: [authMiddleware],
  },
  {
    path: '/',
    method: 'post',
    handler: submitInvoiceHandler,
    middleware: [authMiddleware, validationMiddleware(invoiceSubmissionSchema)],
  },
];
