/**
 * Porezna API Mock Service
 * Production-grade mock for Croatian Tax Authority API
 *
 * Features:
 * - OAuth 2.0 authentication flow
 * - Batch submission endpoints
 * - Async processing simulation
 * - Webhook callbacks for status updates
 * - Rate limiting simulation
 * - Chaos engineering integration
 */

import express from 'express';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import crypto from 'crypto';

// Configuration
interface MockConfig {
  port: number;
  latency: { min: number; max: number };
  errorRate: number;
  chaosMode: 'off' | 'light' | 'moderate' | 'extreme';
  webhookEnabled: boolean;
  rateLimit: number; // requests per minute
}

// OAuth token
interface OAuthToken {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  scope: string[];
}

// Batch submission
interface BatchSubmission {
  id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  submittedAt: Date;
  processedAt?: Date;
  invoiceCount: number;
  successCount: number;
  failureCount: number;
  results: Array<{
    invoiceId: string;
    status: 'success' | 'failed';
    jir?: string;
    error?: string;
  }>;
}

class PoreznaMockService {
  private app: express.Application;
  private config: MockConfig;
  private logger: winston.Logger;
  private tokens: Map<string, OAuthToken> = new Map();
  private batches: Map<string, BatchSubmission> = new Map();
  private requestCounts: Map<string, { count: number; resetAt: Date }> = new Map();
  private metrics: {
    requests: number;
    errors: number;
    totalLatency: number;
    startTime: Date;
  };

  constructor(config: Partial<MockConfig> = {}) {
    this.app = express();
    this.config = {
      port: config.port || 8450,
      latency: config.latency || { min: 100, max: 300 },
      errorRate: config.errorRate || 0.01,
      chaosMode: config.chaosMode || 'off',
      webhookEnabled: config.webhookEnabled ?? true,
      rateLimit: config.rateLimit || 60
    };

    this.metrics = {
      requests: 0,
      errors: 0,
      totalLatency: 0,
      startTime: new Date()
    };

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({ filename: 'porezna-mock.log' })
      ]
    });

    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(bodyParser.json());

    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - start;
        this.metrics.requests++;
        this.metrics.totalLatency += duration;
        this.logger.info(`${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
      });
      next();
    });

    // Rate limiting
    this.app.use((req, res, next) => {
      if (req.path === '/health' || req.path.startsWith('/mock')) {
        return next();
      }

      const clientId = this.extractClientId(req);
      if (!this.checkRateLimit(clientId)) {
        return res.status(429).json({
          error: 'RATE_LIMIT_EXCEEDED',
          message: `Rate limit of ${this.config.rateLimit} requests per minute exceeded`,
          retryAfter: 60
        });
      }

      next();
    });
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'operational',
        uptime: Date.now() - this.metrics.startTime.getTime(),
        metrics: {
          requests: this.metrics.requests,
          errors: this.metrics.errors,
          avgLatency: this.metrics.requests > 0
            ? Math.round(this.metrics.totalLatency / this.metrics.requests)
            : 0
        },
        config: {
          chaosMode: this.config.chaosMode,
          errorRate: this.config.errorRate
        }
      });
    });

    // OAuth 2.0 Token endpoint
    this.app.post('/oauth/token', async (req, res) => {
      await this.applyLatency();

      const { grant_type, client_id, client_secret, refresh_token } = req.body;

      if (!client_id || !client_secret) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing client_id or client_secret'
        });
      }

      if (grant_type === 'client_credentials') {
        const token = this.generateToken(client_id, ['invoice:submit', 'invoice:query']);
        this.tokens.set(token.accessToken, token);

        return res.json({
          access_token: token.accessToken,
          refresh_token: token.refreshToken,
          token_type: 'Bearer',
          expires_in: 3600,
          scope: token.scope.join(' ')
        });
      } else if (grant_type === 'refresh_token') {
        if (!refresh_token) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing refresh_token'
          });
        }

        // Find existing token by refresh token
        const existingToken = Array.from(this.tokens.values())
          .find(t => t.refreshToken === refresh_token);

        if (!existingToken) {
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid refresh token'
          });
        }

        const newToken = this.generateToken(client_id, existingToken.scope);
        this.tokens.set(newToken.accessToken, newToken);

        return res.json({
          access_token: newToken.accessToken,
          refresh_token: newToken.refreshToken,
          token_type: 'Bearer',
          expires_in: 3600,
          scope: newToken.scope.join(' ')
        });
      }

      res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only client_credentials and refresh_token are supported'
      });
    });

    // Submit batch invoices
    this.app.post('/api/v1/invoices/batch', this.requireAuth.bind(this), async (req, res) => {
      await this.applyLatency();

      const { invoices, webhookUrl } = req.body;

      if (!invoices || !Array.isArray(invoices)) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'invoices must be an array'
        });
      }

      const batchId = uuidv4();
      const batch: BatchSubmission = {
        id: batchId,
        status: 'pending',
        submittedAt: new Date(),
        invoiceCount: invoices.length,
        successCount: 0,
        failureCount: 0,
        results: []
      };

      this.batches.set(batchId, batch);

      // Simulate async processing
      this.processBatchAsync(batchId, invoices, webhookUrl);

      res.status(202).json({
        batchId,
        status: 'accepted',
        invoiceCount: invoices.length,
        statusUrl: `/api/v1/batches/${batchId}`,
        estimatedCompletionTime: new Date(Date.now() + invoices.length * 1000).toISOString()
      });
    });

    // Get batch status
    this.app.get('/api/v1/batches/:batchId', this.requireAuth.bind(this), async (req, res) => {
      await this.applyLatency();

      const batch = this.batches.get(req.params.batchId);
      if (!batch) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Batch not found'
        });
      }

      res.json({
        batchId: batch.id,
        status: batch.status,
        submittedAt: batch.submittedAt,
        processedAt: batch.processedAt,
        invoiceCount: batch.invoiceCount,
        successCount: batch.successCount,
        failureCount: batch.failureCount,
        results: batch.results
      });
    });

    // Query invoice status
    this.app.get('/api/v1/invoices/:invoiceId', this.requireAuth.bind(this), async (req, res) => {
      await this.applyLatency();

      // Search across all batches
      let found = false;
      for (const batch of this.batches.values()) {
        const result = batch.results.find(r => r.invoiceId === req.params.invoiceId);
        if (result) {
          found = true;
          return res.json({
            invoiceId: result.invoiceId,
            status: result.status,
            jir: result.jir,
            error: result.error,
            batchId: batch.id,
            submittedAt: batch.submittedAt,
            processedAt: batch.processedAt
          });
        }
      }

      if (!found) {
        return res.status(404).json({
          error: 'NOT_FOUND',
          message: 'Invoice not found'
        });
      }
    });

    // Mock configuration endpoint
    this.app.post('/mock/config', (req, res) => {
      const updates = req.body;
      if (updates.chaosMode) this.config.chaosMode = updates.chaosMode;
      if (updates.errorRate !== undefined) this.config.errorRate = updates.errorRate;
      if (updates.latency) this.config.latency = updates.latency;
      if (updates.rateLimit) this.config.rateLimit = updates.rateLimit;

      this.logger.info('Mock configuration updated:', updates);
      res.json({ success: true, config: this.config });
    });

    // Reset state endpoint
    this.app.post('/mock/reset', (req, res) => {
      this.tokens.clear();
      this.batches.clear();
      this.requestCounts.clear();
      this.metrics = {
        requests: 0,
        errors: 0,
        totalLatency: 0,
        startTime: new Date()
      };
      this.logger.info('Mock state reset');
      res.json({ success: true, message: 'State reset successfully' });
    });
  }

  private async processBatchAsync(
    batchId: string,
    invoices: any[],
    webhookUrl?: string
  ): Promise<void> {
    const batch = this.batches.get(batchId);
    if (!batch) return;

    batch.status = 'processing';

    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, invoices.length * 500));

    for (const invoice of invoices) {
      const success = Math.random() > 0.05; // 95% success rate
      const result = {
        invoiceId: invoice.id || uuidv4(),
        status: success ? 'success' as const : 'failed' as const,
        jir: success ? this.generateJIR() : undefined,
        error: success ? undefined : 'Validation failed: Invalid OIB format'
      };

      batch.results.push(result);
      if (success) {
        batch.successCount++;
      } else {
        batch.failureCount++;
      }
    }

    batch.status = 'completed';
    batch.processedAt = new Date();

    // Send webhook if enabled
    if (webhookUrl && this.config.webhookEnabled) {
      this.sendWebhook(webhookUrl, batch);
    }

    this.logger.info(`Batch ${batchId} processed: ${batch.successCount}/${batch.invoiceCount} successful`);
  }

  private async sendWebhook(url: string, batch: BatchSubmission): Promise<void> {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Porezna-Signature': this.generateWebhookSignature(batch)
        },
        body: JSON.stringify({
          event: 'batch.completed',
          batchId: batch.id,
          status: batch.status,
          invoiceCount: batch.invoiceCount,
          successCount: batch.successCount,
          failureCount: batch.failureCount,
          timestamp: new Date().toISOString()
        })
      });

      if (response.ok) {
        this.logger.info(`Webhook sent successfully to ${url}`);
      } else {
        this.logger.warn(`Webhook failed: ${response.status}`);
      }
    } catch (error) {
      this.logger.error(`Webhook error: ${error}`);
    }
  }

  private generateWebhookSignature(batch: BatchSubmission): string {
    const secret = 'mock-webhook-secret';
    const payload = JSON.stringify({ batchId: batch.id, status: batch.status });
    return crypto.createHmac('sha256', secret).update(payload).digest('hex');
  }

  private requireAuth(req: any, res: any, next: any): void {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Missing or invalid Authorization header'
      });
    }

    const token = authHeader.substring(7);
    const tokenData = this.tokens.get(token);

    if (!tokenData) {
      return res.status(401).json({
        error: 'INVALID_TOKEN',
        message: 'Token not found or expired'
      });
    }

    if (tokenData.expiresAt < new Date()) {
      return res.status(401).json({
        error: 'TOKEN_EXPIRED',
        message: 'Token has expired'
      });
    }

    next();
  }

  private generateToken(clientId: string, scope: string[]): OAuthToken {
    return {
      accessToken: uuidv4(),
      refreshToken: uuidv4(),
      expiresAt: new Date(Date.now() + 3600 * 1000), // 1 hour
      scope
    };
  }

  private generateJIR(): string {
    return `${this.randomHex(8)}-${this.randomHex(4)}-${this.randomHex(4)}-${this.randomHex(4)}-${this.randomHex(12)}`;
  }

  private randomHex(length: number): string {
    return crypto.randomBytes(length / 2).toString('hex');
  }

  private extractClientId(req: any): string {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return req.ip || 'unknown';
  }

  private checkRateLimit(clientId: string): boolean {
    const now = new Date();
    let record = this.requestCounts.get(clientId);

    if (!record || record.resetAt < now) {
      record = {
        count: 0,
        resetAt: new Date(now.getTime() + 60 * 1000) // 1 minute
      };
      this.requestCounts.set(clientId, record);
    }

    record.count++;
    return record.count <= this.config.rateLimit;
  }

  private async applyLatency(): Promise<void> {
    const { min, max } = this.config.latency;
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  public start(): void {
    this.app.listen(this.config.port, () => {
      this.logger.info(`Porezna Mock Service started on port ${this.config.port}`);
      this.logger.info(`Chaos mode: ${this.config.chaosMode}`);
      this.logger.info(`Rate limit: ${this.config.rateLimit} req/min`);
    });
  }
}

// Start the service
if (require.main === module) {
  const config: Partial<MockConfig> = {
    port: parseInt(process.env.POREZNA_PORT || '8450'),
    chaosMode: (process.env.CHAOS_MODE as any) || 'off',
    errorRate: parseFloat(process.env.ERROR_RATE || '0.01'),
    rateLimit: parseInt(process.env.RATE_LIMIT || '60')
  };

  const service = new PoreznaMockService(config);
  service.start();
}

export { PoreznaMockService, MockConfig, BatchSubmission };
