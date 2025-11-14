import forge from 'node-forge';
import {
  logger,
  signatureTotal,
  signatureDuration,
  signatureErrors,
  createSpan,
  setSpanError,
  endSpanSuccess,
  maskOIB,
} from './observability.js';
import type { ParsedCertificate } from './certificate-parser.js';

/**
 * ZKI Code Generation Parameters (B2C Fiscalization)
 */
export interface ZKIParams {
  /** OIB of the invoice issuer (11 digits) */
  oib: string;
  /** Issue date and time (ISO 8601 format) */
  issueDateTime: string;
  /** Invoice/receipt number */
  invoiceNumber: string;
  /** Business premises identifier */
  businessPremises: string;
  /** Cash register/POS identifier */
  cashRegister: string;
  /** Total amount (with 2 decimal places) */
  totalAmount: string;
}

/**
 * ZKI Code Error
 */
export class ZKIGenerationError extends Error {
  constructor(message: string, public cause?: Error) {
    super(message);
    this.name = 'ZKIGenerationError';
  }
}

/**
 * Validate ZKI parameters
 *
 * @param params - ZKI parameters
 * @throws ZKIGenerationError if validation fails
 */
export function validateZKIParams(params: ZKIParams): void {
  const errors: string[] = [];

  // Validate OIB (11 digits)
  if (!params.oib || !/^\d{11}$/.test(params.oib)) {
    errors.push('OIB must be 11 digits');
  }

  // Validate issue date time (ISO 8601 format)
  if (!params.issueDateTime || !isValidISODateTime(params.issueDateTime)) {
    errors.push('Issue date time must be in ISO 8601 format');
  }

  // Validate invoice number (not empty)
  if (!params.invoiceNumber || params.invoiceNumber.trim() === '') {
    errors.push('Invoice number is required');
  }

  // Validate business premises (not empty)
  if (!params.businessPremises || params.businessPremises.trim() === '') {
    errors.push('Business premises identifier is required');
  }

  // Validate cash register (not empty)
  if (!params.cashRegister || params.cashRegister.trim() === '') {
    errors.push('Cash register identifier is required');
  }

  // Validate total amount (numeric with 2 decimal places)
  if (!params.totalAmount || !isValidAmount(params.totalAmount)) {
    errors.push('Total amount must be a valid number with up to 2 decimal places');
  }

  if (errors.length > 0) {
    throw new ZKIGenerationError(
      `ZKI parameter validation failed: ${errors.join(', ')}`
    );
  }
}

/**
 * Check if string is valid ISO 8601 date time
 */
function isValidISODateTime(dateTime: string): boolean {
  try {
    const parsed = new Date(dateTime);
    return !isNaN(parsed.getTime());
  } catch {
    return false;
  }
}

/**
 * Check if amount is valid (numeric with max 2 decimal places)
 */
function isValidAmount(amount: string): boolean {
  return /^\d+(\.\d{1,2})?$/.test(amount);
}

/**
 * Generate ZKI code for B2C fiscalization
 *
 * Algorithm (per Croatian fiscalization spec):
 * 1. Concatenate: OIB + IssueDateTime + InvoiceNumber + BusinessPremises + CashRegister + TotalAmount
 * 2. Compute MD5 hash of concatenated string
 * 3. Sign MD5 hash with private key (RSA)
 * 4. Encode signature as hexadecimal
 *
 * @param params - ZKI parameters
 * @param certificate - Parsed certificate with private key
 * @returns ZKI code (32 hex characters)
 * @throws ZKIGenerationError if generation fails
 */
export async function generateZKI(
  params: ZKIParams,
  certificate: ParsedCertificate
): Promise<string> {
  const span = createSpan('generate_zki', {
    oib_masked: maskOIB(params.oib),
    invoice_number: params.invoiceNumber,
  });

  const startTime = Date.now();

  try {
    logger.info({
      oib: maskOIB(params.oib),
      issueDateTime: params.issueDateTime,
      invoiceNumber: params.invoiceNumber,
      businessPremises: params.businessPremises,
      cashRegister: params.cashRegister,
      totalAmount: params.totalAmount,
    }, 'Generating ZKI code');

    // Validate parameters
    validateZKIParams(params);

    // Concatenate parameters according to spec
    const concatenated =
      params.oib +
      params.issueDateTime +
      params.invoiceNumber +
      params.businessPremises +
      params.cashRegister +
      params.totalAmount;

    logger.debug({ concatenated }, 'Concatenated ZKI input string');

    // Compute MD5 hash
    const md5 = forge.md.md5.create();
    md5.update(concatenated, 'utf8');
    logger.debug({ input_length: concatenated.length }, 'MD5 hash prepared');

    // Sign the hash with private key
    const privateKey = certificate.privateKey;
    const signature = privateKey.sign(md5);

    // Convert signature to hex string
    const zki = forge.util.bytesToHex(signature);

    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'zki' }, duration);
    signatureTotal.inc({ operation: 'zki', status: 'success' });

    endSpanSuccess(span);

    logger.info({
      duration_ms: duration * 1000,
      zki_length: zki.length,
      oib: maskOIB(params.oib),
    }, 'ZKI code generated successfully');

    return zki;
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'zki' }, duration);
    signatureTotal.inc({ operation: 'zki', status: 'failure' });
    signatureErrors.inc({ error_type: 'zki_generation' });

    setSpanError(span, error as Error);
    span.end();

    logger.error({
      error,
      oib: maskOIB(params.oib),
    }, 'Failed to generate ZKI code');

    if (error instanceof ZKIGenerationError) {
      throw error;
    }

    throw new ZKIGenerationError(
      'Failed to generate ZKI code',
      error as Error
    );
  }
}

/**
 * Verify ZKI code
 *
 * Verifies that a ZKI code was generated using the given parameters and certificate
 *
 * @param zki - ZKI code to verify (hex string)
 * @param params - ZKI parameters
 * @param certificate - Certificate used to generate ZKI
 * @returns true if valid, false otherwise
 */
export async function verifyZKI(
  zki: string,
  params: ZKIParams,
  certificate: ParsedCertificate
): Promise<boolean> {
  const span = createSpan('verify_zki', {
    oib_masked: maskOIB(params.oib),
  });

  const startTime = Date.now();

  try {
    logger.info({
      oib: maskOIB(params.oib),
      zki_length: zki.length,
    }, 'Verifying ZKI code');

    // Validate parameters
    validateZKIParams(params);

    // Concatenate parameters
    const concatenated =
      params.oib +
      params.issueDateTime +
      params.invoiceNumber +
      params.businessPremises +
      params.cashRegister +
      params.totalAmount;

    // Compute MD5 hash
    const md5 = forge.md.md5.create();
    md5.update(concatenated, 'utf8');

    // Convert ZKI hex to bytes
    const signatureBytes = forge.util.hexToBytes(zki);

    // Verify signature using public key
    const publicKey = certificate.info.publicKey;
    const isValid = publicKey.verify(md5.digest().bytes(), signatureBytes);

    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'verify' }, duration);
    signatureTotal.inc({
      operation: 'verify',
      status: isValid ? 'success' : 'failure',
    });

    endSpanSuccess(span);

    logger.info({
      duration_ms: duration * 1000,
      isValid,
      oib: maskOIB(params.oib),
    }, 'ZKI verification completed');

    return isValid;
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'verify' }, duration);
    signatureTotal.inc({ operation: 'verify', status: 'failure' });

    setSpanError(span, error as Error);
    span.end();

    logger.error({
      error,
      oib: maskOIB(params.oib),
    }, 'Failed to verify ZKI code');

    return false;
  }
}

/**
 * Format ZKI code for display (add dashes every 8 characters)
 *
 * Example: a1b2c3d4e5f67890... → a1b2c3d4-e5f67890-...
 *
 * @param zki - ZKI code (hex string)
 * @returns Formatted ZKI code
 */
export function formatZKI(zki: string): string {
  if (!zki || zki.length === 0) {
    return '';
  }

  const chunks: string[] = [];
  for (let i = 0; i < zki.length; i += 8) {
    chunks.push(zki.slice(i, i + 8));
  }

  return chunks.join('-');
}
