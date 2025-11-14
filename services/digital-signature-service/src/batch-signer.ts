import pLimit from 'p-limit';
import {
  logger,
  createSpan,
  setSpanError,
  endSpanSuccess,
  batchSignatureTotal,
  batchSignatureDuration,
  batchSignatureSize,
  batchSignatureErrors,
} from './observability.js';
import { signUBLInvoice, type SignatureOptions } from './xmldsig-signer.js';
import type { ParsedCertificate } from './certificate-parser.js';

/**
 * Batch Signing Request
 */
export interface BatchSigningRequest {
  /** Array of UBL invoices to sign */
  invoices: string[];
  /** Signature options (optional) */
  options?: SignatureOptions;
  /** Max concurrent signatures (default: 10) */
  concurrency?: number;
}

/**
 * Batch Signing Result (individual invoice)
 */
export interface BatchSigningResultItem {
  /** Index of invoice in original batch */
  index: number;
  /** Success status */
  success: boolean;
  /** Signed XML (if successful) */
  signedXml?: string;
  /** Error message (if failed) */
  error?: string;
}

/**
 * Batch Signing Response
 */
export interface BatchSigningResponse {
  /** Total invoices in batch */
  total: number;
  /** Successfully signed */
  successful: number;
  /** Failed signatures */
  failed: number;
  /** Duration in milliseconds */
  duration_ms: number;
  /** Throughput (signatures per second) */
  throughput: number;
  /** Results for each invoice */
  results: BatchSigningResultItem[];
}

/**
 * Batch Signing Error
 */
export class BatchSigningError extends Error {
  constructor(message: string, public cause?: Error) {
    super(message);
    this.name = 'BatchSigningError';
  }
}

/**
 * Sign multiple UBL invoices in parallel (batch signing)
 *
 * Performance optimization for high-throughput scenarios (e.g., 278 signatures/second)
 *
 * @param request - Batch signing request
 * @param certificate - Parsed certificate with private key
 * @returns Batch signing response with results
 */
export async function signUBLBatch(
  request: BatchSigningRequest,
  certificate: ParsedCertificate
): Promise<BatchSigningResponse> {
  const span = createSpan('sign_ubl_batch', {
    batch_size: request.invoices.length,
    concurrency: request.concurrency || 10,
  });

  const startTime = Date.now();

  try {
    const { invoices, options, concurrency = 10 } = request;

    // Validate batch size
    if (!invoices || invoices.length === 0) {
      throw new BatchSigningError('Batch must contain at least one invoice');
    }

    if (invoices.length > 1000) {
      throw new BatchSigningError('Batch size exceeds maximum (1000 invoices)');
    }

    logger.info({
      batch_size: invoices.length,
      concurrency,
    }, 'Starting batch signature operation');

    // Track batch size metric
    batchSignatureSize.observe(invoices.length);

    // Create concurrency limiter (prevents memory exhaustion)
    const limit = pLimit(concurrency);

    // Process all invoices in parallel with concurrency control
    const promises = invoices.map((ublXml, index) =>
      limit(async (): Promise<BatchSigningResultItem> => {
        try {
          const signedXml = await signUBLInvoice(ublXml, certificate, options);
          return {
            index,
            success: true,
            signedXml,
          };
        } catch (error) {
          logger.warn({
            index,
            error: (error as Error).message,
          }, 'Failed to sign invoice in batch');

          batchSignatureErrors.inc({ error_type: 'individual_signature_failed' });

          return {
            index,
            success: false,
            error: (error as Error).message,
          };
        }
      })
    );

    // Wait for all signatures to complete (fail fast disabled)
    const results = await Promise.all(promises);

    // Calculate statistics
    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    const durationMs = Date.now() - startTime;
    const throughput = (successful / durationMs) * 1000; // signatures/second

    // Update metrics
    batchSignatureDuration.observe(durationMs / 1000);
    batchSignatureTotal.inc({ status: 'success' });

    endSpanSuccess(span);

    logger.info({
      total: invoices.length,
      successful,
      failed,
      duration_ms: durationMs,
      throughput: throughput.toFixed(2),
    }, 'Batch signature operation completed');

    return {
      total: invoices.length,
      successful,
      failed,
      duration_ms: durationMs,
      throughput: parseFloat(throughput.toFixed(2)),
      results,
    };
  } catch (error) {
    const durationMs = Date.now() - startTime;
    batchSignatureDuration.observe(durationMs / 1000);
    batchSignatureTotal.inc({ status: 'failure' });
    batchSignatureErrors.inc({ error_type: 'batch_operation_failed' });

    setSpanError(span, error as Error);
    span.end();

    logger.error({
      error,
      duration_ms: durationMs,
    }, 'Batch signature operation failed');

    throw new BatchSigningError(
      'Batch signature operation failed',
      error as Error
    );
  }
}

/**
 * Validate batch signing request
 *
 * @param request - Batch signing request
 * @throws BatchSigningError if validation fails
 */
export function validateBatchRequest(request: any): void {
  if (!request) {
    throw new BatchSigningError('Request body is required');
  }

  if (!Array.isArray(request.invoices)) {
    throw new BatchSigningError('Request must contain "invoices" array');
  }

  if (request.invoices.length === 0) {
    throw new BatchSigningError('Batch must contain at least one invoice');
  }

  if (request.invoices.length > 1000) {
    throw new BatchSigningError('Batch size exceeds maximum (1000 invoices)');
  }

  // Validate each invoice is a non-empty string
  for (let i = 0; i < request.invoices.length; i++) {
    const invoice = request.invoices[i];
    if (typeof invoice !== 'string' || invoice.trim() === '') {
      throw new BatchSigningError(`Invoice at index ${i} is invalid (must be non-empty string)`);
    }
  }

  // Validate concurrency (if provided)
  if (request.concurrency !== undefined) {
    const concurrency = parseInt(request.concurrency, 10);
    if (isNaN(concurrency) || concurrency < 1 || concurrency > 100) {
      throw new BatchSigningError('Concurrency must be between 1 and 100');
    }
  }
}
