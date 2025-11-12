import express, { Request, Response, NextFunction } from 'express';
import * as dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import {
  logger,
  getMetrics,
  initObservability,
  shutdownObservability,
  activeCertificates,
  certificateExpirationDays,
  certificateLoadTime,
} from './observability.js';
import {
  loadCertificateFromFile,
  assertCertificateValid,
  type ParsedCertificate,
} from './certificate-parser.js';
import { signUBLInvoice, signXMLDocument } from './xmldsig-signer.js';
import { generateZKI, verifyZKI, formatZKI, type ZKIParams } from './zki-generator.js';
import { verifyXMLSignature, verifyUBLInvoiceSignature } from './xmldsig-verifier.js';

// Load environment variables
dotenv.config();

const app = express();
const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8088', 10);
const METRICS_PORT = parseInt(process.env.METRICS_PORT || '9096', 10);

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: 'application/xml', limit: '10mb' }));

// Request ID middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
  req.headers['x-request-id'] = req.headers['x-request-id'] || uuidv4();
  next();
});

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const requestId = req.headers['x-request-id'];
  logger.info({
    request_id: requestId,
    method: req.method,
    path: req.path,
    user_agent: req.headers['user-agent'],
  }, 'Incoming HTTP request');
  next();
});

// Global certificate cache (singleton pattern)
let defaultCertificate: ParsedCertificate | null = null;
let certificateLoadedAt: Date | null = null; // IMPROVEMENT-004: Track load timestamp

/**
 * Calculate days remaining until certificate expiration (IMPROVEMENT-004)
 */
function getDaysUntilExpiration(expirationDate: Date): number {
  const now = new Date();
  const msUntilExpiration = expirationDate.getTime() - now.getTime();
  const daysUntilExpiration = Math.ceil(msUntilExpiration / (1000 * 60 * 60 * 24));
  return daysUntilExpiration;
}

/**
 * Load default certificate on startup (IMPROVEMENT-004: Added expiration monitoring)
 */
async function loadDefaultCertificate(): Promise<void> {
  const certPath = process.env.DEFAULT_CERT_PATH;
  const certPassword = process.env.DEFAULT_CERT_PASSWORD;

  if (!certPath || !certPassword) {
    logger.warn('No default certificate configured (DEFAULT_CERT_PATH or DEFAULT_CERT_PASSWORD not set)');
    return;
  }

  try {
    logger.info({ certPath }, 'Loading default certificate');
    const startTime = Date.now();

    defaultCertificate = await loadCertificateFromFile(certPath, certPassword);
    certificateLoadedAt = new Date();

    // Validate certificate
    assertCertificateValid(defaultCertificate.info);

    // IMPROVEMENT-004: Track metrics
    const loadTimeSeconds = (Date.now() - startTime) / 1000;
    certificateLoadTime.observe(loadTimeSeconds);

    const daysRemaining = getDaysUntilExpiration(defaultCertificate.info.notAfter);
    certificateExpirationDays.set(daysRemaining);

    activeCertificates.set(1);

    logger.info({
      subject: defaultCertificate.info.subjectDN,
      issuer: defaultCertificate.info.issuer,
      notAfter: defaultCertificate.info.notAfter,
      daysUntilExpiration: daysRemaining,
      loadTimeMs: (loadTimeSeconds * 1000).toFixed(2),
    }, 'Default certificate loaded and validated');

    // IMPROVEMENT-004: Alert if certificate expiring soon
    if (daysRemaining <= 30 && daysRemaining > 0) {
      logger.warn({
        daysUntilExpiration: daysRemaining,
        expiresAt: defaultCertificate.info.notAfter,
      }, 'Certificate expiring soon - renewal required');
    } else if (daysRemaining <= 0) {
      logger.error({
        expiresAt: defaultCertificate.info.notAfter,
      }, 'Certificate has expired - immediate action required');
    }
  } catch (error) {
    logger.error({ error, certPath }, 'Failed to load default certificate');
    activeCertificates.set(0);
    certificateExpirationDays.set(-1); // Indicate error state
    throw error;
  }
}

/**
 * Health check endpoint
 */
app.get('/health', (req: Request, res: Response) => {
  const uptime = process.uptime();
  res.json({
    status: 'healthy',
    service: 'digital-signature-service',
    uptime_seconds: uptime,
    timestamp: new Date().toISOString(),
  });
});

/**
 * Readiness check endpoint (IMPROVEMENT-004: Added expiration details)
 */
app.get('/ready', (req: Request, res: Response) => {
  const isReady = defaultCertificate !== null;

  if (isReady) {
    const daysRemaining = getDaysUntilExpiration(defaultCertificate!.info.notAfter);
    const status = daysRemaining > 0 ? 'ready' : 'degraded';
    const statusCode = daysRemaining > 0 ? 200 : 503;

    res.status(statusCode).json({
      status,
      certificate_loaded: true,
      certificate_info: {
        issuer: defaultCertificate!.info.issuer,
        expires: defaultCertificate!.info.notAfter.toISOString(),
        days_remaining: daysRemaining,
        loaded_at: certificateLoadedAt?.toISOString(),
      },
      warning: daysRemaining <= 30 && daysRemaining > 0 ?
        `Certificate expiring in ${daysRemaining} days` :
        daysRemaining <= 0 ? 'Certificate has expired' : undefined,
    });
  } else {
    res.status(503).json({
      status: 'not_ready',
      certificate_loaded: false,
      message: 'Default certificate not loaded',
    });
  }
});

/**
 * Sign UBL Invoice with XMLDSig
 *
 * POST /api/v1/sign/ubl
 * Content-Type: application/xml
 * Body: UBL 2.1 Invoice XML
 *
 * Response: Signed UBL Invoice XML
 */
app.post('/api/v1/sign/ubl', async (req: Request, res: Response): Promise<void> => {
  const requestId = req.headers['x-request-id'] as string;

  try {
    if (!defaultCertificate) {
      logger.error({ request_id: requestId }, 'No certificate available for signing');
      res.status(503).json({
        error: 'Service not ready',
        message: 'No certificate loaded',
      });
      return;
    }

    const ublXml = typeof req.body === 'string' ? req.body : req.body.toString();

    if (!ublXml || ublXml.trim() === '') {
      res.status(400).json({
        error: 'Bad request',
        message: 'Request body must contain UBL Invoice XML',
      });
      return;
    }

    logger.info({ request_id: requestId }, 'Signing UBL invoice');

    const signedXml = await signUBLInvoice(ublXml, defaultCertificate);

    res.setHeader('Content-Type', 'application/xml');
    res.send(signedXml);

    logger.info({ request_id: requestId }, 'UBL invoice signed successfully');
  } catch (error) {
    logger.error({ request_id: requestId, error }, 'Failed to sign UBL invoice');
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * Sign generic XML document
 *
 * POST /api/v1/sign/xml
 * Content-Type: application/xml
 * Body: XML document
 *
 * Response: Signed XML document
 */
app.post('/api/v1/sign/xml', async (req: Request, res: Response) => {
  const requestId = req.headers['x-request-id'] as string;

  try {
    if (!defaultCertificate) {
      logger.error({ request_id: requestId }, 'No certificate available for signing');
      return res.status(503).json({
        error: 'Service not ready',
        message: 'No certificate loaded',
      });
    }

    const xmlContent = typeof req.body === 'string' ? req.body : req.body.toString();

    if (!xmlContent || xmlContent.trim() === '') {
      return res.status(400).json({
        error: 'Bad request',
        message: 'Request body must contain XML content',
      });
    }

    logger.info({ request_id: requestId }, 'Signing XML document');

    const signedXml = await signXMLDocument(xmlContent, defaultCertificate);

    res.setHeader('Content-Type', 'application/xml');
    res.send(signedXml);

    logger.info({ request_id: requestId }, 'XML document signed successfully');
  } catch (error) {
    logger.error({ request_id: requestId, error }, 'Failed to sign XML document');
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * Generate ZKI code for B2C fiscalization
 *
 * POST /api/v1/sign/zki
 * Content-Type: application/json
 * Body: { oib, issueDateTime, invoiceNumber, businessPremises, cashRegister, totalAmount }
 *
 * Response: { zki, zki_formatted }
 */
app.post('/api/v1/sign/zki', async (req: Request, res: Response) => {
  const requestId = req.headers['x-request-id'] as string;

  try {
    if (!defaultCertificate) {
      logger.error({ request_id: requestId }, 'No certificate available for ZKI generation');
      return res.status(503).json({
        error: 'Service not ready',
        message: 'No certificate loaded',
      });
    }

    const params: ZKIParams = req.body;

    // Validate required fields
    const requiredFields = ['oib', 'issueDateTime', 'invoiceNumber', 'businessPremises', 'cashRegister', 'totalAmount'];
    const missingFields = requiredFields.filter((field) => !params[field as keyof ZKIParams]);

    if (missingFields.length > 0) {
      return res.status(400).json({
        error: 'Bad request',
        message: `Missing required fields: ${missingFields.join(', ')}`,
      });
    }

    logger.info({ request_id: requestId }, 'Generating ZKI code');

    const zki = await generateZKI(params, defaultCertificate);
    const zkiFormatted = formatZKI(zki);

    res.json({
      zki,
      zki_formatted: zkiFormatted,
    });

    logger.info({ request_id: requestId }, 'ZKI code generated successfully');
  } catch (error) {
    logger.error({ request_id: requestId, error }, 'Failed to generate ZKI code');
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * Verify ZKI code
 *
 * POST /api/v1/verify/zki
 * Content-Type: application/json
 * Body: { zki, oib, issueDateTime, invoiceNumber, businessPremises, cashRegister, totalAmount }
 *
 * Response: { isValid }
 */
app.post('/api/v1/verify/zki', async (req: Request, res: Response) => {
  const requestId = req.headers['x-request-id'] as string;

  try {
    if (!defaultCertificate) {
      logger.error({ request_id: requestId }, 'No certificate available for ZKI verification');
      return res.status(503).json({
        error: 'Service not ready',
        message: 'No certificate loaded',
      });
    }

    const { zki, ...params } = req.body;

    if (!zki) {
      return res.status(400).json({
        error: 'Bad request',
        message: 'ZKI code is required',
      });
    }

    logger.info({ request_id: requestId }, 'Verifying ZKI code');

    const isValid = await verifyZKI(zki, params as ZKIParams, defaultCertificate);

    res.json({ isValid });

    logger.info({ request_id: requestId, isValid }, 'ZKI verification completed');
  } catch (error) {
    logger.error({ request_id: requestId, error }, 'Failed to verify ZKI code');
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * Verify XMLDSig signature in XML document
 *
 * POST /api/v1/verify/xml
 * Content-Type: application/xml
 * Body: Signed XML document
 *
 * Response: { isValid, errors, certificateInfo }
 */
app.post('/api/v1/verify/xml', async (req: Request, res: Response) => {
  const requestId = req.headers['x-request-id'] as string;

  try {
    const signedXml = typeof req.body === 'string' ? req.body : req.body.toString();

    if (!signedXml || signedXml.trim() === '') {
      return res.status(400).json({
        error: 'Bad request',
        message: 'Request body must contain signed XML',
      });
    }

    logger.info({ request_id: requestId }, 'Verifying XML signature');

    const result = await verifyXMLSignature(signedXml);

    res.json(result);

    logger.info({ request_id: requestId, isValid: result.isValid }, 'XML signature verification completed');
  } catch (error) {
    logger.error({ request_id: requestId, error }, 'Failed to verify XML signature');
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * Verify UBL Invoice signature
 *
 * POST /api/v1/verify/ubl
 * Content-Type: application/xml
 * Body: Signed UBL Invoice XML
 *
 * Response: { isValid, errors, certificateInfo }
 */
app.post('/api/v1/verify/ubl', async (req: Request, res: Response) => {
  const requestId = req.headers['x-request-id'] as string;

  try {
    const signedXml = typeof req.body === 'string' ? req.body : req.body.toString();

    if (!signedXml || signedXml.trim() === '') {
      return res.status(400).json({
        error: 'Bad request',
        message: 'Request body must contain signed UBL Invoice XML',
      });
    }

    logger.info({ request_id: requestId }, 'Verifying UBL invoice signature');

    const result = await verifyUBLInvoiceSignature(signedXml);

    res.json(result);

    logger.info({ request_id: requestId, isValid: result.isValid }, 'UBL invoice signature verification completed');
  } catch (error) {
    logger.error({ request_id: requestId, error }, 'Failed to verify UBL invoice signature');
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
});

/**
 * Get certificate information (IMPROVEMENT-004: Added expiration tracking)
 *
 * GET /api/v1/certificates
 */
app.get('/api/v1/certificates', (req: Request, res: Response) => {
  if (!defaultCertificate) {
    return res.status(404).json({
      error: 'Not found',
      message: 'No certificate loaded',
    });
  }

  const daysRemaining = getDaysUntilExpiration(defaultCertificate.info.notAfter);

  res.json({
    certificate: {
      subject: defaultCertificate.info.subjectDN,
      issuer: defaultCertificate.info.issuerDN,
      serialNumber: defaultCertificate.info.serialNumber,
      notBefore: defaultCertificate.info.notBefore.toISOString(),
      notAfter: defaultCertificate.info.notAfter.toISOString(),
      days_remaining: daysRemaining,
      loaded_at: certificateLoadedAt?.toISOString(),
    },
  });
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  const requestId = req.headers['x-request-id'] as string;
  logger.error({ request_id: requestId, error: err }, 'Unhandled error');

  res.status(500).json({
    error: 'Internal server error',
    message: err.message,
  });
});

// Metrics server
const metricsApp = express();

metricsApp.get('/metrics', async (req: Request, res: Response) => {
  try {
    const metrics = await getMetrics();
    res.setHeader('Content-Type', 'text/plain');
    res.send(metrics);
  } catch (error) {
    logger.error({ error }, 'Failed to generate metrics');
    res.status(500).send('Failed to generate metrics');
  }
});

/**
 * Start HTTP server
 */
async function startServer(): Promise<void> {
  try {
    // Initialize observability
    initObservability();

    // Load default certificate
    await loadDefaultCertificate();

    // Start HTTP server
    app.listen(HTTP_PORT, () => {
      logger.info({ port: HTTP_PORT }, 'HTTP server started');
    });

    // Start metrics server
    metricsApp.listen(METRICS_PORT, () => {
      logger.info({ port: METRICS_PORT }, 'Metrics server started');
    });

  } catch (error) {
    logger.error({ error }, 'Failed to start server');
    process.exit(1);
  }
}

/**
 * Graceful shutdown
 */
async function shutdown(signal: string): Promise<void> {
  logger.info({ signal }, 'Received shutdown signal');

  // Shutdown observability
  shutdownObservability();

  // Clear certificate
  defaultCertificate = null;
  activeCertificates.set(0);

  logger.info('Shutdown complete');
  process.exit(0);
}

// Handle shutdown signals
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Start server
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().catch((error) => {
    logger.error({ error }, 'Fatal error during startup');
    process.exit(1);
  });
}

export { app, startServer };
