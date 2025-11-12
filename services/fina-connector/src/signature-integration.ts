import axios, { AxiosInstance } from 'axios';
import {
  logger,
  createSpan,
  setSpanError,
  endSpanSuccess,
} from './observability.js';
import type { FINAInvoice } from './types.js';

/**
 * Signature Service Configuration
 */
export interface SignatureServiceConfig {
  /** Base URL of digital-signature-service */
  baseUrl: string;
  /** Request timeout (milliseconds) */
  timeout: number;
  /** Max retry attempts */
  maxRetries: number;
}

/**
 * ZKI Generation Request
 */
interface ZKIGenerationRequest {
  oib: string;
  dateTime: string;
  invoiceNumber: string;
  premises: string;
  device: string;
  totalAmount: string;
}

/**
 * ZKI Generation Response
 */
interface ZKIGenerationResponse {
  zki: string;
  formatted: string;
}

/**
 * UBL Signature Request
 */
interface UBLSignatureRequest {
  xmlDocument: string;
  certificateAlias?: string;
}

/**
 * UBL Signature Response
 */
interface UBLSignatureResponse {
  signedXml: string;
  signatureInfo: {
    algorithm: string;
    digestMethod: string;
    signatureValue: string;
    certificateInfo: {
      subject: string;
      issuer: string;
      serialNumber: string;
      validFrom: string;
      validTo: string;
    };
  };
}

/**
 * Signature Service Error
 */
export class SignatureServiceError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode?: number,
    public cause?: Error
  ) {
    super(message);
    this.name = 'SignatureServiceError';
  }
}

/**
 * Signature Service Integration
 *
 * Integrates with digital-signature-service for:
 * - ZKI code generation (B2C fiscalization)
 * - XMLDSig signature generation (UBL invoices)
 */
export class SignatureServiceClient {
  private client: AxiosInstance;
  private config: SignatureServiceConfig;

  constructor(config: SignatureServiceConfig) {
    this.config = config;
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Generate ZKI code for B2C invoice
   *
   * @param invoice - FINA invoice data
   * @returns ZKI code (32 hex characters)
   */
  async generateZKI(invoice: FINAInvoice): Promise<string> {
    const span = createSpan('generate_zki', {
      invoice_number: invoice.brojRacuna,
    });

    try {
      logger.info({
        invoiceNumber: invoice.brojRacuna,
        premises: invoice.oznPoslProstora,
        device: invoice.oznNapUr,
      }, 'Generating ZKI code');

      const request: ZKIGenerationRequest = {
        oib: invoice.oib,
        dateTime: invoice.datVrijeme,
        invoiceNumber: invoice.brojRacuna,
        premises: invoice.oznPoslProstora,
        device: invoice.oznNapUr,
        totalAmount: invoice.ukupanIznos,
      };

      const response = await this.retryWithBackoff<ZKIGenerationResponse>(
        () => this.client.post('/api/v1/sign/zki', request)
      );

      const zki = response.zki;

      endSpanSuccess(span);

      logger.info({
        invoiceNumber: invoice.brojRacuna,
        zkiLength: zki.length,
      }, 'ZKI code generated successfully');

      return zki;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({
        invoiceNumber: invoice.brojRacuna,
        error,
      }, 'Failed to generate ZKI code');

      throw new SignatureServiceError(
        'Failed to generate ZKI code',
        'ZKI_GENERATION_FAILED',
        (error as any).response?.status,
        error as Error
      );
    }
  }

  /**
   * Sign UBL invoice with XMLDSig
   *
   * @param xmlDocument - UBL XML document (unsigned)
   * @param certificateAlias - Certificate alias (optional)
   * @returns Signed XML document
   */
  async signUBLInvoice(
    xmlDocument: string,
    certificateAlias?: string
  ): Promise<string> {
    const span = createSpan('sign_ubl_invoice');

    try {
      logger.info({
        xmlLength: xmlDocument.length,
        certificateAlias,
      }, 'Signing UBL invoice with XMLDSig');

      const request: UBLSignatureRequest = {
        xmlDocument,
        certificateAlias,
      };

      const response = await this.retryWithBackoff<UBLSignatureResponse>(
        () => this.client.post('/api/v1/sign/ubl', request)
      );

      const signedXml = response.signedXml;

      endSpanSuccess(span);

      logger.info({
        signedXmlLength: signedXml.length,
        signatureAlgorithm: response.signatureInfo.algorithm,
        certificateSubject: response.signatureInfo.certificateInfo.subject,
      }, 'UBL invoice signed successfully');

      return signedXml;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({
        error,
        xmlLength: xmlDocument.length,
      }, 'Failed to sign UBL invoice');

      throw new SignatureServiceError(
        'Failed to sign UBL invoice',
        'UBL_SIGNING_FAILED',
        (error as any).response?.status,
        error as Error
      );
    }
  }

  /**
   * Verify UBL invoice signature
   *
   * @param signedXml - Signed XML document
   * @returns True if signature is valid
   */
  async verifySignature(signedXml: string): Promise<boolean> {
    const span = createSpan('verify_signature');

    try {
      logger.debug({
        signedXmlLength: signedXml.length,
      }, 'Verifying UBL invoice signature');

      const response = await this.retryWithBackoff<{ valid: boolean }>(
        () => this.client.post('/api/v1/verify/ubl', { signedXml })
      );

      endSpanSuccess(span);

      logger.debug({
        valid: response.valid,
      }, 'Signature verification completed');

      return response.valid;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({
        error,
      }, 'Failed to verify signature');

      throw new SignatureServiceError(
        'Failed to verify signature',
        'SIGNATURE_VERIFICATION_FAILED',
        (error as any).response?.status,
        error as Error
      );
    }
  }

  /**
   * Get certificate information
   *
   * @returns Certificate details
   */
  async getCertificateInfo(): Promise<any> {
    const span = createSpan('get_certificate_info');

    try {
      logger.debug('Fetching certificate information');

      const response = await this.retryWithBackoff<any>(
        () => this.client.get('/api/v1/certificates')
      );

      endSpanSuccess(span);

      logger.debug({
        certificateCount: response.certificates?.length || 0,
      }, 'Certificate information fetched');

      return response;
    } catch (error) {
      setSpanError(span, error as Error);
      span.end();

      logger.error({
        error,
      }, 'Failed to fetch certificate information');

      throw new SignatureServiceError(
        'Failed to fetch certificate information',
        'CERTIFICATE_INFO_FAILED',
        (error as any).response?.status,
        error as Error
      );
    }
  }

  /**
   * Health check for signature service
   *
   * @returns True if service is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.client.get('/health');
      return true;
    } catch (error) {
      logger.warn({
        error,
        serviceUrl: this.config.baseUrl,
      }, 'Signature service health check failed');
      return false;
    }
  }

  /**
   * Retry with exponential backoff
   *
   * @param operation - Operation to retry
   * @returns Operation result
   */
  private async retryWithBackoff<T>(
    operation: () => Promise<{ data: T }>
  ): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        const response = await operation();
        return response.data;
      } catch (error) {
        lastError = error as Error;

        // Don't retry on 4xx errors (client errors)
        const statusCode = (error as any).response?.status;
        if (statusCode && statusCode >= 400 && statusCode < 500) {
          throw error;
        }

        if (attempt < this.config.maxRetries) {
          const backoffMs = Math.pow(2, attempt) * 1000; // 2s, 4s, 8s
          logger.warn({
            attempt,
            maxRetries: this.config.maxRetries,
            backoffMs,
            error: (error as Error).message,
          }, 'Retrying signature service operation');

          await new Promise(resolve => setTimeout(resolve, backoffMs));
        }
      }
    }

    throw lastError;
  }
}

/**
 * Create signature service client
 */
export function createSignatureServiceClient(
  config: SignatureServiceConfig
): SignatureServiceClient {
  return new SignatureServiceClient(config);
}
