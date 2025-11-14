/**
 * Invoice Routes
 * Handles invoice submission and status retrieval
 */

import { Router, Request, Response, NextFunction } from 'express';
import { Container } from 'inversify';
import { InvoiceController } from '../controllers/invoice.controller';
import { validateBody, validateParams } from '../middleware/validation';
import { InvoiceSubmissionSchema, InvoiceIdParamSchema } from '../types/schemas';
import { SERVICE_TYPES } from '../types/di';
import { InvoiceRepository } from '../repositories/invoice.repository';
import { ProcessInvoiceCommandPublisher } from '../messaging/process-invoice.publisher';

export function invoiceRoutes(container: Container): Router {
  const router = Router();
  const repository = container.get<InvoiceRepository>(
    SERVICE_TYPES.InvoiceRepository
  );
  const publisher = container.get<ProcessInvoiceCommandPublisher>(
    SERVICE_TYPES.ProcessInvoicePublisher
  );
  const controller = new InvoiceController(repository, publisher);

  /**
   * POST /api/v1/invoices
   * Submit invoice for processing
   */
  router.post(
    '/',
    validateBody(InvoiceSubmissionSchema),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        await controller.submitInvoice(req, res);
      } catch (error) {
        next(error);
      }
    }
  );

  /**
   * GET /api/v1/invoices/:invoiceId
   * Get invoice status
   */
  router.get(
    '/:invoiceId',
    validateParams(InvoiceIdParamSchema),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        await controller.getInvoiceStatus(req, res);
      } catch (error) {
        next(error);
      }
    }
  );

  return router;
}
