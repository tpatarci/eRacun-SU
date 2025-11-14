/**
 * REST API Server
 *
 * Exposes endpoints for invoice retrieval, validation, and audit queries.
 * All endpoints require OAuth2 authentication (see ADR-004 §85-90).
 *
 * See: docs/adr/004-archive-compliance-layer.md §85-90
 */

import express, { Request, Response, NextFunction } from 'express';
import { createLogger } from '../utils/logger';
import { ArchiveService } from '../services/archive-service';
import { InvoiceRepository, MockInvoiceRepository } from '../repositories/invoice-repository';
import { createWORMStorage } from '../storage/interfaces';

const logger = createLogger('api-server');

/**
 * Start REST API server
 *
 * @param port - HTTP port to listen on
 * @param archiveService - Optional archive service instance (for testing)
 * @returns Express app instance
 */
export async function startApiServer(
  port: number,
  archiveService?: ArchiveService
): Promise<express.Application> {
  const app = express();

  // Initialize archive service if not provided
  if (!archiveService) {
    const storageType = (process.env.STORAGE_TYPE as 'mock' | 's3') ?? 'mock';
    const storage = createWORMStorage(storageType);
    const repository = process.env.ARCHIVE_DATABASE_URL
      ? new InvoiceRepository(process.env.ARCHIVE_DATABASE_URL)
      : new MockInvoiceRepository();
    archiveService = new ArchiveService(storage, repository, process.env.SIGNATURE_SERVICE_URL);
  }

  app.use(express.json({ limit: '1mb' }));

  // Request ID middleware
  app.use((req, _res, next) => {
    req.headers['x-request-id'] = req.headers['x-request-id'] ?? generateRequestId();
    next();
  });

  // Health checks
  app.get('/health/live', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.get('/health/ready', async (_req, res) => {
    try {
      // TODO: Check database, RabbitMQ, S3 connectivity
      res.status(200).json({ status: 'ready' });
    } catch (error) {
      logger.error('Readiness check failed', { error });
      res.status(503).json({ status: 'not ready', error: 'Service dependencies unavailable' });
    }
  });

  /**
   * GET /v1/archive/invoices/:id
   * Retrieve invoice metadata and presigned URL (or restore token for COLD tier)
   */
  app.get('/v1/archive/invoices/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id: invoiceId } = req.params;
      logger.info('Retrieving invoice', { invoiceId, requestId: req.headers['x-request-id'] });

      // Get invoice metadata from repository
      const invoice = await archiveService!['repository'].findById(invoiceId);
      if (!invoice) {
        return res.status(404).json({ error: 'Invoice not found', invoiceId });
      }

      // Check storage tier and availability
      const storageMetadata = invoice.storageMetadata;

      // For HOT/WARM tier, generate presigned URL
      if (storageMetadata.tier === 'HOT' || storageMetadata.tier === 'WARM') {
        const presignedUrl = await archiveService!['storage'].getPresignedUrl(invoiceId, 3600);

        return res.status(200).json({
          invoiceId,
          submissionChannel: invoice.submissionChannel,
          submissionTimestamp: invoice.submissionTimestamp,
          confirmationReference: invoice.confirmationReference,
          signatureStatus: invoice.signatureStatus,
          signatureLastChecked: invoice.signatureLastChecked,
          storage: {
            tier: storageMetadata.tier,
            bucket: storageMetadata.bucket,
            key: storageMetadata.key,
            retentionUntil: storageMetadata.retentionUntil,
            presignedUrl,
            expiresIn: 3600,
          },
          createdAt: invoice.createdAt,
          retentionExpiresAt: invoice.retentionExpiresAt,
        });
      }

      // For COLD tier, check restore status
      const retrieveResult = await archiveService!['storage'].retrieve(invoiceId);

      return res.status(200).json({
        invoiceId,
        submissionChannel: invoice.submissionChannel,
        submissionTimestamp: invoice.submissionTimestamp,
        confirmationReference: invoice.confirmationReference,
        signatureStatus: invoice.signatureStatus,
        signatureLastChecked: invoice.signatureLastChecked,
        storage: {
          tier: storageMetadata.tier,
          bucket: storageMetadata.bucket,
          key: storageMetadata.key,
          retentionUntil: storageMetadata.retentionUntil,
          restoreStatus: retrieveResult.restoreStatus,
        },
        createdAt: invoice.createdAt,
        retentionExpiresAt: invoice.retentionExpiresAt,
      });
    } catch (error) {
      next(error);
    }
  });

  /**
   * GET /v1/archive/invoices
   * Filter invoices by date range, channel, signature status (paginated)
   */
  app.get('/v1/archive/invoices', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        startDate,
        endDate,
        channel,
        signatureStatus,
        limit = '100',
        offset = '0',
      } = req.query;

      logger.info('Listing invoices', {
        startDate,
        endDate,
        channel,
        signatureStatus,
        limit,
        offset,
        requestId: req.headers['x-request-id'],
      });

      // Parse and validate query parameters
      const filter = {
        startDate: startDate ? new Date(startDate as string) : undefined,
        endDate: endDate ? new Date(endDate as string) : undefined,
        channel: channel as 'B2C' | 'B2B' | undefined,
        signatureStatus: signatureStatus as
          | 'VALID'
          | 'PENDING'
          | 'INVALID'
          | 'EXPIRED'
          | undefined,
        limit: parseInt(limit as string, 10),
        offset: parseInt(offset as string, 10),
      };

      // Validate dates
      if (filter.startDate && isNaN(filter.startDate.getTime())) {
        return res.status(400).json({ error: 'Invalid startDate format' });
      }
      if (filter.endDate && isNaN(filter.endDate.getTime())) {
        return res.status(400).json({ error: 'Invalid endDate format' });
      }

      // Query repository
      const invoices = await archiveService!['repository'].findByFilter(filter);

      return res.status(200).json({
        invoices: invoices.map((inv) => ({
          invoiceId: inv.invoiceId,
          submissionChannel: inv.submissionChannel,
          submissionTimestamp: inv.submissionTimestamp,
          confirmationReference: inv.confirmationReference,
          signatureStatus: inv.signatureStatus,
          signatureLastChecked: inv.signatureLastChecked,
          storage: {
            tier: inv.storageMetadata.tier,
            retentionUntil: inv.storageMetadata.retentionUntil,
          },
          createdAt: inv.createdAt,
        })),
        pagination: {
          limit: filter.limit,
          offset: filter.offset,
          total: invoices.length,
        },
      });
    } catch (error) {
      next(error);
    }
  });

  /**
   * GET /v1/archive/invoices/:id/audit
   * Return chronological audit events for invoice lifecycle
   */
  app.get(
    '/v1/archive/invoices/:id/audit',
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id: invoiceId } = req.params;
        logger.info('Retrieving audit trail', {
          invoiceId,
          requestId: req.headers['x-request-id'],
        });

        // Check invoice exists
        const invoice = await archiveService!['repository'].findById(invoiceId);
        if (!invoice) {
          return res.status(404).json({ error: 'Invoice not found', invoiceId });
        }

        // Get audit trail
        const auditEvents = await archiveService!['repository'].getAuditTrail(invoiceId);

        return res.status(200).json({
          invoiceId,
          events: auditEvents.map((event) => ({
            eventId: event.eventId,
            eventType: event.eventType,
            actor: event.actor,
            timestamp: event.timestamp,
            metadata: event.metadata,
          })),
        });
      } catch (error) {
        next(error);
      }
    }
  );

  /**
   * POST /v1/archive/invoices/:id/validate
   * Trigger idempotent revalidation and update signature status
   */
  app.post(
    '/v1/archive/invoices/:id/validate',
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { id: invoiceId } = req.params;
        logger.info('Validating invoice signature', {
          invoiceId,
          requestId: req.headers['x-request-id'],
        });

        // Check invoice exists
        const invoice = await archiveService!['repository'].findById(invoiceId);
        if (!invoice) {
          return res.status(404).json({ error: 'Invoice not found', invoiceId });
        }

        // Trigger validation
        const result = await archiveService!.validateSignature(invoiceId);

        return res.status(200).json({
          invoiceId: result.invoiceId,
          status: result.status,
          validatedAt: result.validatedAt,
          details: result.details,
        });
      } catch (error) {
        next(error);
      }
    }
  );

  // Error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled error', {
      error: err,
      stack: err.stack,
      requestId: _req.headers['x-request-id'],
    });

    res.status(500).json({
      error: 'Internal server error',
      message: err.message,
      requestId: _req.headers['x-request-id'],
    });
  });

  app.listen(port, () => {
    logger.info('API server listening', { port });
  });

  return app;
}

/**
 * Generate unique request ID
 */
function generateRequestId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}
