/**
 * Error Classification Logic
 *
 * Classifies DLQ messages into 4 categories:
 * - TRANSIENT: Network, timeout, resource exhaustion (auto-retry)
 * - BUSINESS: Validation failure, business rule violation (manual review)
 * - TECHNICAL: Programming error, null pointer, type mismatch (manual review + engineering)
 * - UNKNOWN: Cannot classify (manual review + investigation)
 *
 * See: README.md §4 for classification rules
 */

import { DLQMessage, ErrorClassification } from './types';
import { createLogger } from './utils/logger';

const logger = createLogger('classifier');

/**
 * Classify error based on error message and stack trace
 *
 * @param dlqMessage - DLQ message with error details
 * @returns ErrorClassification enum value
 */
export function classifyError(dlqMessage: DLQMessage): ErrorClassification {
  const errorReason = (dlqMessage.error.reason || '').toLowerCase();
  const errorStack = (dlqMessage.error.exception || '').toLowerCase();

  logger.debug('Classifying error', {
    reason: errorReason.substring(0, 100),
    stack: errorStack.substring(0, 100),
  });

  // Transient errors (network, resource, rate limit)
  if (isTransientError(errorReason, errorStack)) {
    logger.info('Classified as TRANSIENT', { reason: errorReason.substring(0, 50) });
    return ErrorClassification.TRANSIENT;
  }

  // Business errors (validation, business rules)
  if (isBusinessError(errorReason, errorStack)) {
    logger.info('Classified as BUSINESS', { reason: errorReason.substring(0, 50) });
    return ErrorClassification.BUSINESS;
  }

  // Technical errors (programming errors)
  if (isTechnicalError(errorReason, errorStack)) {
    logger.info('Classified as TECHNICAL', { reason: errorReason.substring(0, 50) });
    return ErrorClassification.TECHNICAL;
  }

  // Unknown (cannot classify)
  logger.warn('Classified as UNKNOWN - review classification rules', {
    reason: errorReason.substring(0, 50),
  });
  return ErrorClassification.UNKNOWN;
}

/**
 * Check if error is transient (auto-retryable)
 *
 * Transient errors:
 * - Network timeouts (ETIMEDOUT, ECONNREFUSED)
 * - Database connection failures
 * - Rate limit exceeded (429)
 * - Resource exhaustion (ENOMEM, EMFILE)
 * - Temporary external API errors (503)
 */
function isTransientError(errorReason: string, errorStack: string): boolean {
  const transientPatterns = [
    // Network timeouts
    'timeout',
    'etimedout',
    'econnrefused',
    'econnreset',
    'enetunreach',
    'ehostunreach',

    // Database connection failures
    'connection terminated',
    'connection refused',
    'connection closed',
    'connection lost',
    'connection timeout',
    'connect timeout',

    // Rate limiting
    '429',
    'too many requests',
    'rate limit',
    'throttled',

    // Resource exhaustion
    'enomem',
    'emfile',
    'out of memory',
    'resource temporarily unavailable',

    // Temporary external API errors
    '503',
    'service unavailable',
    'temporarily unavailable',
    'try again later',

    // Circuit breaker
    'circuit breaker',
    'circuit open',
  ];

  return transientPatterns.some(
    (pattern) => errorReason.includes(pattern) || errorStack.includes(pattern)
  );
}

/**
 * Check if error is business-related (manual review)
 *
 * Business errors:
 * - XSD validation failures
 * - Schematron rule violations (BR-* codes)
 * - KPD code not found
 * - OIB validation failures
 * - Duplicate invoice detection
 */
function isBusinessError(errorReason: string, errorStack: string): boolean {
  const businessPatterns = [
    // Validation errors
    'validation',
    'invalid xml',
    'schema',
    'xsd',
    'schematron',

    // Business rule violations (Croatian CIUS)
    'br-',               // Schematron rule IDs (e.g., BR-CO-04)
    'business rule',

    // Croatian-specific validation
    'invalid oib',
    'oib',
    'kpd',
    'klasus',

    // Duplicate detection
    'duplicate',
    'already exists',
    'already submitted',

    // VAT/Tax errors
    'vat',
    'tax',
    'pdv',              // Croatian VAT (Porez na Dodanu Vrijednost)

    // FINA/Porezna errors
    'fina',
    'porezna',
    'jir',
    'zki',
  ];

  return businessPatterns.some(
    (pattern) => errorReason.includes(pattern) || errorStack.includes(pattern)
  );
}

/**
 * Check if error is technical (programming error)
 *
 * Technical errors:
 * - Null pointer exceptions
 * - Type mismatches
 * - Unhandled exceptions
 * - Memory leaks (OOM)
 */
function isTechnicalError(errorReason: string, errorStack: string): boolean {
  const technicalPatterns = [
    // Null/undefined errors
    'cannot read property',
    'cannot read properties',
    'null',
    'undefined',
    'is not a function',
    'is not defined',

    // Type errors
    'typeerror',
    'type mismatch',
    'expected',
    'got',
    'wrong type',

    // Reference errors
    'referenceerror',
    'not defined',

    // Memory issues
    'out of memory',
    'memory',
    'heap',

    // Syntax errors
    'syntaxerror',
    'unexpected token',

    // Range errors
    'rangeerror',
    'invalid array length',

    // Other programming errors
    'assertion',
    'invariant',
    'unreachable',
  ];

  return technicalPatterns.some(
    (pattern) => errorStack.includes(pattern) || errorReason.includes(pattern)
  );
}

/**
 * Extract service name from DLQ message
 *
 * @param dlqMessage - DLQ message
 * @returns Service name or 'unknown'
 */
export function extractServiceName(dlqMessage: DLQMessage): string {
  // Try to extract from queue name (e.g., 'validation.xsd.validate.dlq' → 'validation')
  const queueName = dlqMessage.original_queue || '';
  const parts = queueName.split('.');

  if (parts.length > 0 && parts[0]) {
    return parts[0];
  }

  return 'unknown';
}

/**
 * Extract invoice ID from DLQ message payload
 *
 * @param dlqMessage - DLQ message
 * @returns Invoice ID or undefined
 */
export function extractInvoiceId(dlqMessage: DLQMessage): string | undefined {
  try {
    const payload = dlqMessage.original_message.toString('utf-8');

    // Try parsing as JSON
    if (payload.startsWith('{')) {
      const json = JSON.parse(payload);
      return json.invoiceId || json.invoice_id || json.id;
    }

    // Try parsing as XML (look for <InvoiceId> or <cbc:ID>)
    if (payload.startsWith('<')) {
      const invoiceIdMatch =
        payload.match(/<InvoiceId>([^<]+)<\/InvoiceId>/) ||
        payload.match(/<cbc:ID>([^<]+)<\/cbc:ID>/);

      if (invoiceIdMatch && invoiceIdMatch[1]) {
        return invoiceIdMatch[1];
      }
    }

    return undefined;
  } catch (error) {
    logger.debug('Failed to extract invoice ID', { error });
    return undefined;
  }
}
