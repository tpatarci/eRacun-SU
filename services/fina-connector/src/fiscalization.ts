import {
  logger,
  fiscalizationTotal,
  fiscalizationDuration,
  retryAttempts,
  jirReceived,
  createSpan,
  setSpanError,
  endSpanSuccess,
} from './observability.js';
import type {
  FINAInvoice,
  FINAFiscalizationRequest,
  FINAFiscalizationResponse,
  FINAError,
} from './types.js';
import { FINASOAPClient } from './soap-client.js';
import { SignatureServiceClient } from './signature-integration.js';
import { SOAPEnvelopeBuilder } from './soap-envelope-builder.js';

/**
 * Fiscalization Service Configuration
 */
export interface FiscalizationConfig {
  /** Max retry attempts for transient failures */
  maxRetries: number;
  /** Enable offline queueing on FINA unavailability */
  offlineQueueEnabled: boolean;
  /** Retry delay base (milliseconds) */
  retryDelayBase: number;
}

/**
 * Fiscalization Result
 */
export interface FiscalizationResult {
  /** Success flag */
  success: boolean;
  /** JIR (Unique Invoice Identifier) if successful */
  jir?: string;
  /** Error details if failure */
  error?: FINAError;
  /** Number of retry attempts */
  retryCount: number;
  /** Processing duration (milliseconds) */
  durationMs: number;
  /** Whether queued offline */
  queuedOffline: boolean;
}

/**
 * FINA Fiscalization Service
 *
 * Main orchestrator for B2C invoice fiscalization:
 * 1. Generate ZKI code via digital-signature-service
 * 2. Sign XML envelope via digital-signature-service
 * 3. Submit to FINA via SOAP client
 * 4. Handle retries and offline queueing
 */
export class FiscalizationService {
  private soapClient: FINASOAPClient;
  private signatureClient: SignatureServiceClient;
  private config: FiscalizationConfig;
  private soapEnvelopeBuilder: SOAPEnvelopeBuilder;

  constructor(
    soapClient: FINASOAPClient,
    signatureClient: SignatureServiceClient,
    config: FiscalizationConfig
  ) {
    this.soapClient = soapClient;
    this.signatureClient = signatureClient;
    this.config = config;
    this.soapEnvelopeBuilder = new SOAPEnvelopeBuilder();
  }

  /**
   * Fiscalize B2C invoice with FINA
   *
   * @param request - Fiscalization request
   * @returns Fiscalization result with JIR
   */
  async fiscalizeInvoice(
    request: FINAFiscalizationRequest
  ): Promise<FiscalizationResult> {
    const span = createSpan('fiscalize_invoice', {
      invoice_number: request.racun.brojRacuna,
      premises: request.racun.oznPoslProstora,
      device: request.racun.oznNapUr,
    });

    const startTime = Date.now();
    let retryCount = 0;
    let queuedOffline = false;

    try {
      logger.info({
        invoiceNumber: request.racun.brojRacuna,
        premises: request.racun.oznPoslProstora,
        device: request.racun.oznNapUr,
        totalAmount: request.racun.ukupanIznos,
        paymentMethod: request.racun.nacinPlac,
      }, 'Starting invoice fiscalization');

      // Step 1: Generate ZKI code if not provided
      let invoice = request.racun;
      if (!invoice.zki) {
        logger.debug({
          invoiceNumber: invoice.brojRacuna,
        }, 'Generating ZKI code');

        const zki = await this.signatureClient.generateZKI(invoice);
        invoice = { ...invoice, zki };
      }

      // Step 2: Build SOAP envelope for invoice
      const soapEnvelope = this.buildSoapEnvelope(invoice);

      // Step 3: Sign SOAP envelope with XMLDSig
      logger.debug({
        invoiceNumber: invoice.brojRacuna,
      }, 'Signing SOAP envelope with XMLDSig');

      const signedXml = await this.signatureClient.signUBLInvoice(soapEnvelope);

      // Step 4: Submit to FINA with retry logic
      const finaResponse = await this.submitWithRetry(
        invoice,
        signedXml,
        (attempt) => {
          retryCount = attempt;
        }
      );

      const durationMs = Date.now() - startTime;

      if (finaResponse.success) {
        // Success path
        fiscalizationTotal.inc({ operation: 'racuni', status: 'success' });
        fiscalizationDuration.observe(
          { operation: 'racuni' },
          durationMs / 1000
        );

        if (finaResponse.jir) {
          jirReceived.inc();
        }

        endSpanSuccess(span);

        logger.info({
          invoiceNumber: invoice.brojRacuna,
          jir: finaResponse.jir,
          retryCount,
          durationMs,
        }, 'Invoice fiscalized successfully');

        return {
          success: true,
          jir: finaResponse.jir,
          retryCount,
          durationMs,
          queuedOffline: false,
        };
      } else {
        // FINA returned business error (not network failure)
        fiscalizationTotal.inc({ operation: 'racuni', status: 'failure' });
        fiscalizationDuration.observe(
          { operation: 'racuni' },
          durationMs / 1000
        );

        setSpanError(span, new Error(finaResponse.error?.message || 'Unknown error'));
        span.end();

        logger.error({
          invoiceNumber: invoice.brojRacuna,
          error: finaResponse.error,
          retryCount,
          durationMs,
        }, 'Invoice fiscalization failed with business error');

        return {
          success: false,
          error: finaResponse.error,
          retryCount,
          durationMs,
          queuedOffline: false,
        };
      }
    } catch (error) {
      const durationMs = Date.now() - startTime;

      fiscalizationTotal.inc({ operation: 'racuni', status: 'failure' });
      fiscalizationDuration.observe(
        { operation: 'racuni' },
        durationMs / 1000
      );

      setSpanError(span, error as Error);
      span.end();

      logger.error({
        invoiceNumber: request.racun.brojRacuna,
        error,
        retryCount,
        durationMs,
      }, 'Invoice fiscalization failed with exception');

      // Check if we should queue offline
      if (this.config.offlineQueueEnabled && this.isTransientError(error as Error)) {
        queuedOffline = true;
        logger.warn({
          invoiceNumber: request.racun.brojRacuna,
        }, 'Invoice will be queued for offline processing');
      }

      return {
        success: false,
        error: {
          code: 'FISCALIZATION_ERROR',
          message: (error as Error).message,
          stack: (error as Error).stack,
        },
        retryCount,
        durationMs,
        queuedOffline,
      };
    }
  }

  /**
   * Submit invoice to FINA with retry logic
   *
   * @param invoice - Invoice data
   * @param signedXml - Signed SOAP envelope
   * @param onRetry - Callback for retry attempts
   * @returns FINA response
   */
  private async submitWithRetry(
    invoice: FINAInvoice,
    signedXml: string,
    onRetry: (attempt: number) => void
  ): Promise<FINAFiscalizationResponse> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        onRetry(attempt);

        if (attempt > 1) {
          retryAttempts.inc({
            operation: 'racuni',
            attempt: attempt.toString(),
          });

          logger.info({
            invoiceNumber: invoice.brojRacuna,
            attempt,
            maxRetries: this.config.maxRetries,
          }, 'Retrying FINA submission');
        }

        const response = await this.soapClient.fiscalizeInvoice(
          invoice,
          signedXml
        );

        // Success or business error (don't retry business errors)
        return response;
      } catch (error) {
        lastError = error as Error;

        // Check if error is retryable
        if (!this.isRetryableError(error as Error)) {
          logger.warn({
            invoiceNumber: invoice.brojRacuna,
            error: (error as Error).message,
          }, 'Non-retryable error encountered, stopping retries');

          throw error;
        }

        if (attempt < this.config.maxRetries) {
          const backoffMs = this.config.retryDelayBase * Math.pow(2, attempt - 1);
          logger.warn({
            invoiceNumber: invoice.brojRacuna,
            attempt,
            maxRetries: this.config.maxRetries,
            backoffMs,
            error: (error as Error).message,
          }, 'Transient error, will retry');

          await new Promise(resolve => setTimeout(resolve, backoffMs));
        }
      }
    }

    // All retries exhausted
    logger.error({
      invoiceNumber: invoice.brojRacuna,
      maxRetries: this.config.maxRetries,
    }, 'All retry attempts exhausted');

    throw lastError;
  }

  /**
   * Check if error is retryable (transient network/server errors)
   *
   * @param error - Error to check
   * @returns True if retryable
   */
  private isRetryableError(error: Error): boolean {
    const errorCode = (error as any).code;
    const statusCode = (error as any).statusCode;

    // Network errors
    if (errorCode === 'ETIMEDOUT' || errorCode === 'ECONNREFUSED' || errorCode === 'ENOTFOUND') {
      return true;
    }

    // 5xx server errors (but not 501 Not Implemented)
    if (statusCode && statusCode >= 500 && statusCode !== 501) {
      return true;
    }

    // 429 Rate Limit
    if (statusCode === 429) {
      return true;
    }

    return false;
  }

  /**
   * Check if error is transient (should queue offline)
   *
   * @param error - Error to check
   * @returns True if transient
   */
  private isTransientError(error: Error): boolean {
    // Same as retryable for now
    return this.isRetryableError(error);
  }

  /**
   * Build SOAP envelope for invoice
   *
   * Uses SOAPEnvelopeBuilder to generate safe, validated XML with
   * automatic escaping of all invoice field values.
   *
   * All special XML characters are escaped to prevent injection attacks:
   * - & → &amp;
   * - < → &lt;
   * - > → &gt;
   * - " → &quot;
   * - ' → &apos;
   *
   * @param invoice - Invoice data (fields automatically escaped)
   * @returns SOAP envelope XML (safe for signing and submission)
   * @throws Error if required invoice fields missing or invalid
   */
  private buildSoapEnvelope(invoice: FINAInvoice): string {
    return this.soapEnvelopeBuilder.buildRacuniRequest(invoice);
  }
}

/**
 * Create fiscalization service instance
 */
export function createFiscalizationService(
  soapClient: FINASOAPClient,
  signatureClient: SignatureServiceClient,
  config: FiscalizationConfig
): FiscalizationService {
  return new FiscalizationService(soapClient, signatureClient, config);
}
