import { SignedXml } from 'xml-crypto';
import * as xml2js from 'xml2js';
import forge from 'node-forge';
import {
  logger,
  signatureTotal,
  signatureDuration,
  xmldsigValidations,
  signatureErrors,
  createSpan,
  setSpanError,
  endSpanSuccess,
} from './observability.js';

/**
 * Signature Verification Result
 */
export interface VerificationResult {
  /** Whether the signature is valid */
  isValid: boolean;
  /** Verification errors (if any) */
  errors: string[];
  /** Certificate information from signature */
  certificateInfo?: {
    subject: string;
    issuer: string;
    serialNumber: string;
    notBefore: Date;
    notAfter: Date;
  };
  /** Signature timestamp (if present) */
  signatureTimestamp?: Date;
}

/**
 * Signature Verification Error
 */
export class SignatureVerificationError extends Error {
  constructor(message: string, public cause?: Error) {
    super(message);
    this.name = 'SignatureVerificationError';
  }
}

/**
 * Extract certificate from signed XML
 *
 * @param signedXml - Signed XML document
 * @returns Certificate in PEM format, or null if not found
 */
export function extractCertificateFromXML(signedXml: string): string | null {
  const span = createSpan('extract_certificate_from_xml');

  try {
    // Parse XML to find X509Certificate element
    const certMatch = signedXml.match(
      /<(?:\w+:)?X509Certificate>([^<]+)<\/(?:\w+:)?X509Certificate>/
    );

    if (!certMatch || !certMatch[1]) {
      logger.warn('No X509Certificate found in signed XML');
      endSpanSuccess(span);
      return null;
    }

    const certBase64 = certMatch[1].trim();

    // Convert to PEM format
    const certPEM =
      '-----BEGIN CERTIFICATE-----\n' +
      certBase64.match(/.{1,64}/g)?.join('\n') +
      '\n-----END CERTIFICATE-----';

    endSpanSuccess(span);

    logger.debug('Certificate extracted from XML successfully');

    return certPEM;
  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Failed to extract certificate from XML');
    return null;
  }
}

/**
 * Parse certificate information
 *
 * @param certPEM - Certificate in PEM format
 * @returns Certificate information
 */
export function parseCertificateInfo(certPEM: string): VerificationResult['certificateInfo'] {
  try {
    const cert = forge.pki.certificateFromPem(certPEM);

    const subjectAttrs = cert.subject.attributes.map(
      (attr) => `${attr.shortName}=${attr.value}`
    );
    const issuerAttrs = cert.issuer.attributes.map(
      (attr) => `${attr.shortName}=${attr.value}`
    );

    return {
      subject: subjectAttrs.join(', '),
      issuer: issuerAttrs.join(', '),
      serialNumber: cert.serialNumber,
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
    };
  } catch (error) {
    logger.error({ error }, 'Failed to parse certificate information');
    return undefined;
  }
}

/**
 * Verify XMLDSig signature in XML document
 *
 * @param signedXml - Signed XML document
 * @param trustedCertificates - Optional array of trusted root CA certificates (PEM format)
 * @returns Verification result
 */
export async function verifyXMLSignature(
  signedXml: string,
  trustedCertificates?: string[]
): Promise<VerificationResult> {
  const span = createSpan('verify_xml_signature', {
    has_trusted_certs: !!trustedCertificates,
    trusted_cert_count: trustedCertificates?.length || 0,
  });

  const startTime = Date.now();

  const result: VerificationResult = {
    isValid: false,
    errors: [],
  };

  try {
    logger.info('Verifying XMLDSig signature');

    // Extract signature element
    const signatureMatch = signedXml.match(
      /<Signature[^>]*xmlns="http:\/\/www\.w3\.org\/2000\/09\/xmldsig#"[^>]*>[\s\S]*?<\/Signature>/
    );

    if (!signatureMatch) {
      result.errors.push('No XMLDSig signature found in document');
      xmldsigValidations.inc({ result: 'invalid' });
      endSpanSuccess(span);
      return result;
    }

    // Extract certificate from signature
    const certPEM = extractCertificateFromXML(signedXml);

    if (certPEM) {
      result.certificateInfo = parseCertificateInfo(certPEM);

      // Validate certificate dates
      if (result.certificateInfo) {
        const now = new Date();

        if (result.certificateInfo.notBefore > now) {
          result.errors.push(
            `Certificate not yet valid (valid from ${result.certificateInfo.notBefore.toISOString()})`
          );
        }

        if (result.certificateInfo.notAfter < now) {
          result.errors.push(
            `Certificate expired (expired on ${result.certificateInfo.notAfter.toISOString()})`
          );
        }
      }

      // Verify certificate chain against trusted CAs (if provided)
      if (trustedCertificates && trustedCertificates.length > 0) {
        const chainValid = verifyCertificateChain(certPEM, trustedCertificates);

        if (!chainValid) {
          result.errors.push('Certificate chain validation failed');
        }
      }
    }

    // Verify signature using xml-crypto
    const sig = new SignedXml();

    // Load signature from XML
    sig.loadSignature(signatureMatch[0]);

    // Verify signature
    const isSignatureValid = sig.checkSignature(signedXml);

    if (!isSignatureValid) {
      result.errors.push('Signature verification failed');

      // Add detailed validation errors from xml-crypto
      if (sig.validationErrors && sig.validationErrors.length > 0) {
        sig.validationErrors.forEach((err) => {
          result.errors.push(`Validation error: ${err}`);
        });
      }
    }

    // Overall result is valid if signature is valid and no errors
    result.isValid = isSignatureValid && result.errors.length === 0;

    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'verify' }, duration);
    signatureTotal.inc({
      operation: 'verify',
      status: result.isValid ? 'success' : 'failure',
    });
    xmldsigValidations.inc({
      result: result.isValid ? 'valid' : 'invalid',
    });

    endSpanSuccess(span);

    logger.info({
      duration_ms: duration * 1000,
      isValid: result.isValid,
      errorCount: result.errors.length,
    }, 'XMLDSig verification completed');

    return result;
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'verify' }, duration);
    signatureTotal.inc({ operation: 'verify', status: 'failure' });
    signatureErrors.inc({ error_type: 'verification' });

    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Failed to verify XMLDSig signature');

    result.errors.push(`Verification error: ${(error as Error).message}`);

    return result;
  }
}

/**
 * Verify certificate chain against trusted root CAs
 *
 * @param certPEM - Certificate to verify (PEM format)
 * @param trustedCertificates - Array of trusted root CA certificates (PEM format)
 * @returns true if chain is valid, false otherwise
 */
export function verifyCertificateChain(
  certPEM: string,
  trustedCertificates: string[]
): boolean {
  const span = createSpan('verify_certificate_chain');

  try {
    logger.debug('Verifying certificate chain');

    // Parse certificate
    const cert = forge.pki.certificateFromPem(certPEM);

    // Parse trusted CAs
    const caStore = forge.pki.createCaStore();

    for (const trustedCert of trustedCertificates) {
      try {
        const caCert = forge.pki.certificateFromPem(trustedCert);
        caStore.addCertificate(caCert);
      } catch (error) {
        logger.warn({ error }, 'Failed to parse trusted CA certificate');
      }
    }

    // Verify certificate chain
    try {
      forge.pki.verifyCertificateChain(caStore, [cert]);
      endSpanSuccess(span);
      logger.debug('Certificate chain verification succeeded');
      return true;
    } catch (error) {
      logger.warn({ error }, 'Certificate chain verification failed');
      endSpanSuccess(span);
      return false;
    }
  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Error during certificate chain verification');
    return false;
  }
}

/**
 * Verify UBL Invoice signature
 *
 * @param ublXml - Signed UBL invoice XML
 * @param trustedCertificates - Optional array of trusted root CA certificates
 * @returns Verification result
 */
export async function verifyUBLInvoiceSignature(
  ublXml: string,
  trustedCertificates?: string[]
): Promise<VerificationResult> {
  const span = createSpan('verify_ubl_invoice_signature');

  try {
    logger.info('Verifying UBL invoice signature');

    // Parse XML to verify it's a UBL Invoice
    const parser = new xml2js.Parser();
    const parsed = await parser.parseStringPromise(ublXml);

    if (!parsed.Invoice) {
      return {
        isValid: false,
        errors: ['Document is not a valid UBL Invoice'],
      };
    }

    // Verify XMLDSig signature
    const result = await verifyXMLSignature(ublXml, trustedCertificates);

    endSpanSuccess(span);

    logger.info({
      isValid: result.isValid,
      errorCount: result.errors.length,
    }, 'UBL invoice signature verification completed');

    return result;
  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Failed to verify UBL invoice signature');

    return {
      isValid: false,
      errors: [`Verification error: ${(error as Error).message}`],
    };
  }
}
