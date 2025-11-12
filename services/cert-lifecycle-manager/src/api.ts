import express, { Request, Response, NextFunction } from 'express';
import multer from 'multer';
import { CertificateRepository } from './repository';
import { parseCertificate, calculateDaysUntilExpiration } from './cert-parser';
import { validateCertificate } from './cert-validator';
import {
  logger,
  getMetrics,
  certificateOperations,
  createSpan,
  setSpanError,
} from './observability';

/**
 * API Server for Certificate Lifecycle Manager
 *
 * REST API endpoints for certificate management:
 * - POST /api/v1/certificates/upload - Upload new certificate
 * - GET /api/v1/certificates - List all certificates
 * - GET /api/v1/certificates/:id - Get certificate details
 * - DELETE /api/v1/certificates/:id/revoke - Revoke certificate
 * - GET /api/v1/certificates/expiring - List expiring certificates
 * - GET /health - Health check
 * - GET /ready - Readiness check
 * - GET /metrics - Prometheus metrics
 */

export class ApiServer {
  private app: express.Application;
  private repository: CertificateRepository;
  private upload: multer.Multer;

  constructor(repository: CertificateRepository) {
    this.app = express();
    this.repository = repository;

    // Configure multer for file uploads (in-memory storage)
    this.upload = multer({
      storage: multer.memoryStorage(),
      limits: {
        fileSize: 10 * 1024 * 1024, // 10MB max file size
      },
      fileFilter: (_req, file, cb) => {
        // Accept only .p12 and .pfx files
        if (
          file.originalname.endsWith('.p12') ||
          file.originalname.endsWith('.pfx')
        ) {
          cb(null, true);
        } else {
          cb(new Error('Only .p12 or .pfx certificate files are allowed'));
        }
      },
    });

    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  /**
   * Setup Express middleware
   */
  private setupMiddleware(): void {
    // JSON body parser
    this.app.use(express.json());

    // Request logging
    this.app.use((req, _res, next) => {
      const requestId = req.headers['x-request-id'] || `req-${Date.now()}`;
      logger.info(
        {
          requestId,
          method: req.method,
          path: req.path,
          userAgent: req.headers['user-agent'],
        },
        'HTTP request received'
      );
      next();
    });
  }

  /**
   * Setup API routes
   */
  private setupRoutes(): void {
    // Health endpoints
    this.app.get('/health', this.handleHealthCheck.bind(this));
    this.app.get('/ready', this.handleReadinessCheck.bind(this));
    this.app.get('/metrics', this.handleMetrics.bind(this));

    // API v1 routes
    const apiRouter = express.Router();

    apiRouter.post(
      '/certificates/upload',
      this.upload.single('certificate'),
      this.handleUploadCertificate.bind(this)
    );
    apiRouter.get('/certificates', this.handleListCertificates.bind(this));
    apiRouter.get(
      '/certificates/expiring',
      this.handleListExpiringCertificates.bind(this)
    );
    apiRouter.get('/certificates/:id', this.handleGetCertificate.bind(this));
    apiRouter.delete(
      '/certificates/:id/revoke',
      this.handleRevokeCertificate.bind(this)
    );

    this.app.use('/api/v1', apiRouter);
  }

  /**
   * Setup error handling middleware
   */
  private setupErrorHandling(): void {
    // 404 handler
    this.app.use((req, res, _next) => {
      res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.method} ${req.path} not found`,
      });
    });

    // Global error handler
    this.app.use(
      (err: Error, req: Request, res: Response, _next: NextFunction) => {
        logger.error({ error: err, path: req.path }, 'HTTP error');

        res.status(500).json({
          error: 'Internal Server Error',
          message: err.message,
        });
      }
    );
  }

  /**
   * Handle health check
   */
  private async handleHealthCheck(_req: Request, res: Response): Promise<void> {
    const uptime = process.uptime();

    res.json({
      status: 'healthy',
      service: 'cert-lifecycle-manager',
      uptime_seconds: Math.floor(uptime),
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Handle readiness check
   */
  private async handleReadinessCheck(
    _req: Request,
    res: Response
  ): Promise<void> {
    const span = createSpan('readiness_check');

    try {
      // Check database connection
      const dbHealthy = await this.repository.healthCheck();

      if (!dbHealthy) {
        res.status(503).json({
          status: 'not_ready',
          dependencies: {
            database: 'unhealthy',
          },
        });
        span.end();
        return;
      }

      res.json({
        status: 'ready',
        dependencies: {
          database: 'healthy',
        },
      });

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      res.status(503).json({
        status: 'not_ready',
        error: (error as Error).message,
      });
    }
  }

  /**
   * Handle Prometheus metrics endpoint
   */
  private async handleMetrics(_req: Request, res: Response): Promise<void> {
    res.set('Content-Type', 'text/plain');
    res.send(await getMetrics());
  }

  /**
   * Handle certificate upload
   *
   * POST /api/v1/certificates/upload
   * Content-Type: multipart/form-data
   * Body: certificate (file), password (string)
   */
  private async handleUploadCertificate(
    req: Request,
    res: Response
  ): Promise<void> {
    const span = createSpan('upload_certificate');

    try {
      // Validate file was uploaded
      if (!req.file) {
        res.status(400).json({
          error: 'Bad Request',
          message: 'No certificate file uploaded',
        });
        certificateOperations.labels('upload', 'failed').inc();
        span.end();
        return;
      }

      // Validate password was provided
      const password = req.body.password;
      if (!password) {
        res.status(400).json({
          error: 'Bad Request',
          message: 'Certificate password is required',
        });
        certificateOperations.labels('upload', 'failed').inc();
        span.end();
        return;
      }

      logger.info(
        {
          filename: req.file.originalname,
          size: req.file.size,
        },
        'Processing certificate upload'
      );

      // Parse certificate
      const certInfo = await parseCertificate(req.file.buffer, password);

      // Validate certificate
      const validationResult = await validateCertificate(certInfo);

      if (!validationResult.valid) {
        res.status(400).json({
          error: 'Invalid Certificate',
          message: 'Certificate validation failed',
          errors: validationResult.errors,
          warnings: validationResult.warnings,
        });
        certificateOperations.labels('upload', 'failed').inc();
        span.end();
        return;
      }

      // TODO: Encrypt password with SOPS + age
      // For now, store placeholder (NEVER store plaintext passwords in production!)
      const passwordEncrypted = `ENCRYPTED:${Buffer.from(password).toString('base64')}`;

      // TODO: Save certificate file to /etc/eracun/secrets/certs/
      // For now, use placeholder path
      const certPath = `/etc/eracun/secrets/certs/${certInfo.serialNumber}.p12`;

      // Save to database
      const savedCert = await this.repository.saveCertificate(
        certInfo,
        certPath,
        passwordEncrypted
      );

      // Record success metric
      certificateOperations.labels('upload', 'success').inc();

      res.status(201).json({
        message: 'Certificate uploaded successfully',
        certificate: {
          certId: savedCert.certId,
          serialNumber: savedCert.serialNumber,
          issuer: savedCert.issuer,
          subjectDn: savedCert.subjectDn,
          notBefore: savedCert.notBefore.toISOString(),
          notAfter: savedCert.notAfter.toISOString(),
          daysUntilExpiry: calculateDaysUntilExpiration(savedCert.notAfter),
          status: savedCert.status,
          certType: savedCert.certType,
          fingerprint: savedCert.fingerprint,
        },
        warnings: validationResult.warnings,
      });

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      certificateOperations.labels('upload', 'failed').inc();

      logger.error({ error }, 'Certificate upload failed');

      res.status(500).json({
        error: 'Upload Failed',
        message: (error as Error).message,
      });
    }
  }

  /**
   * Handle list all certificates
   *
   * GET /api/v1/certificates
   */
  private async handleListCertificates(
    _req: Request,
    res: Response
  ): Promise<void> {
    const span = createSpan('list_certificates');

    try {
      const certificates = await this.repository.getAllCertificates();

      const response = certificates.map((cert) => ({
        certId: cert.certId,
        serialNumber: cert.serialNumber,
        issuer: cert.issuer,
        subjectDn: cert.subjectDn,
        notBefore: cert.notBefore.toISOString(),
        notAfter: cert.notAfter.toISOString(),
        daysUntilExpiry: calculateDaysUntilExpiration(cert.notAfter),
        status: cert.status,
        certType: cert.certType,
        fingerprint: cert.fingerprint,
        createdAt: cert.createdAt.toISOString(),
        updatedAt: cert.updatedAt.toISOString(),
      }));

      res.json({
        count: response.length,
        certificates: response,
      });

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to list certificates');

      res.status(500).json({
        error: 'List Failed',
        message: (error as Error).message,
      });
    }
  }

  /**
   * Handle list expiring certificates
   *
   * GET /api/v1/certificates/expiring?days=30
   */
  private async handleListExpiringCertificates(
    req: Request,
    res: Response
  ): Promise<void> {
    const span = createSpan('list_expiring_certificates');

    try {
      const daysThreshold = parseInt(req.query.days as string) || 30;

      const certificates = await this.repository.getExpiringCertificates(
        daysThreshold
      );

      const response = certificates.map((cert) => ({
        certId: cert.certId,
        serialNumber: cert.serialNumber,
        issuer: cert.issuer,
        subjectDn: cert.subjectDn,
        notAfter: cert.notAfter.toISOString(),
        daysUntilExpiry: calculateDaysUntilExpiration(cert.notAfter),
        status: cert.status,
        certType: cert.certType,
      }));

      res.json({
        daysThreshold,
        count: response.length,
        certificates: response,
      });

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error }, 'Failed to list expiring certificates');

      res.status(500).json({
        error: 'List Failed',
        message: (error as Error).message,
      });
    }
  }

  /**
   * Handle get certificate details
   *
   * GET /api/v1/certificates/:id
   */
  private async handleGetCertificate(
    req: Request,
    res: Response
  ): Promise<void> {
    const span = createSpan('get_certificate', { certId: req.params.id });

    try {
      const certId = req.params.id;
      const cert = await this.repository.getCertificate(certId);

      if (!cert) {
        res.status(404).json({
          error: 'Not Found',
          message: `Certificate not found: ${certId}`,
        });
        span.end();
        return;
      }

      res.json({
        certificate: {
          certId: cert.certId,
          serialNumber: cert.serialNumber,
          issuer: cert.issuer,
          subjectDn: cert.subjectDn,
          notBefore: cert.notBefore.toISOString(),
          notAfter: cert.notAfter.toISOString(),
          daysUntilExpiry: calculateDaysUntilExpiration(cert.notAfter),
          status: cert.status,
          certType: cert.certType,
          fingerprint: cert.fingerprint,
          publicKey: cert.publicKey,
          certPath: cert.certPath,
          createdAt: cert.createdAt.toISOString(),
          updatedAt: cert.updatedAt.toISOString(),
        },
      });

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({ error, certId: req.params.id }, 'Failed to get certificate');

      res.status(500).json({
        error: 'Get Failed',
        message: (error as Error).message,
      });
    }
  }

  /**
   * Handle revoke certificate
   *
   * DELETE /api/v1/certificates/:id/revoke
   */
  private async handleRevokeCertificate(
    req: Request,
    res: Response
  ): Promise<void> {
    const span = createSpan('revoke_certificate', { certId: req.params.id });

    try {
      const certId = req.params.id;

      // Check if certificate exists
      const cert = await this.repository.getCertificate(certId);

      if (!cert) {
        res.status(404).json({
          error: 'Not Found',
          message: `Certificate not found: ${certId}`,
        });
        certificateOperations.labels('revoke', 'failed').inc();
        span.end();
        return;
      }

      // Revoke certificate
      await this.repository.revokeCertificate(certId);

      // Record success metric
      certificateOperations.labels('revoke', 'success').inc();

      logger.info({ certId }, 'Certificate revoked successfully');

      res.json({
        message: 'Certificate revoked successfully',
        certId,
      });

      span.end();
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      certificateOperations.labels('revoke', 'failed').inc();

      logger.error({ error, certId: req.params.id }, 'Failed to revoke certificate');

      res.status(500).json({
        error: 'Revoke Failed',
        message: (error as Error).message,
      });
    }
  }

  /**
   * Start API server
   *
   * @param port - HTTP port to listen on
   */
  async start(port: number): Promise<void> {
    return new Promise((resolve) => {
      this.app.listen(port, () => {
        logger.info({ port }, 'API server started');
        resolve();
      });
    });
  }

  /**
   * Get Express app instance (for testing)
   */
  getApp(): express.Application {
    return this.app;
  }
}
