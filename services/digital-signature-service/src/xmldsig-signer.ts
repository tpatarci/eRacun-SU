import { SignedXml } from 'xml-crypto';
import * as xml2js from 'xml2js';
import {
  logger,
  signatureTotal,
  signatureDuration,
  signatureErrors,
  createSpan,
  setSpanError,
  endSpanSuccess,
} from './observability.js';
import type { ParsedCertificate } from './certificate-parser.js';

/**
 * XMLDSig Signature Options
 */
export interface SignatureOptions {
  /** Canonicalization method (default: Exclusive C14N) */
  canonicalizationAlgorithm?: string;
  /** Signature algorithm (default: RSA-SHA256) */
  signatureAlgorithm?: string;
  /** Digest algorithm (default: SHA-256) */
  digestAlgorithm?: string;
  /** Transform algorithms */
  transforms?: string[];
  /** Reference URI (default: empty string for enveloped) */
  referenceUri?: string;
  /** IMPROVEMENT-017: Signature location XPath (default: UBL Invoice element) */
  signatureLocationXPath?: string;
  /** IMPROVEMENT-017: Signature insertion action (default: 'append') */
  signatureLocationAction?: 'append' | 'prepend' | 'before' | 'after';
}

/**
 * Default XMLDSig options for FINA compliance
 */
export const DEFAULT_SIGNATURE_OPTIONS: Required<SignatureOptions> = {
  canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  transforms: [
    'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
    'http://www.w3.org/2001/10/xml-exc-c14n#',
  ],
  referenceUri: '',
  // IMPROVEMENT-017: Configurable signature location (was hard-coded to //*[local-name()="Invoice"])
  signatureLocationXPath: '//*[local-name()="Invoice"]',
  signatureLocationAction: 'append',
};

/**
 * XML Signature Error
 */
export class XMLSignatureError extends Error {
  constructor(message: string, public cause?: Error) {
    super(message);
    this.name = 'XMLSignatureError';
  }
}

/**
 * Sign XML document with XMLDSig enveloped signature
 *
 * @param xmlContent - XML document to sign
 * @param certificate - Parsed certificate with private key
 * @param options - Signature options (optional)
 * @returns Signed XML document
 * @throws XMLSignatureError if signing fails
 */
export async function signXMLDocument(
  xmlContent: string,
  certificate: ParsedCertificate,
  options: SignatureOptions = {}
): Promise<string> {
  const span = createSpan('sign_xml_document', {
    has_certificate: !!certificate,
    xml_length: xmlContent.length,
  });

  const startTime = Date.now();

  try {
    logger.info('Signing XML document with XMLDSig');

    // Merge options with defaults
    const opts = { ...DEFAULT_SIGNATURE_OPTIONS, ...options };

    // Create SignedXml instance
    const sig = new SignedXml({
      privateKey: certificate.privateKeyPEM,
      publicCert: certificate.certificatePEM,
      canonicalizationAlgorithm: opts.canonicalizationAlgorithm,
      signatureAlgorithm: opts.signatureAlgorithm,
    });

    // Add reference to document
    sig.addReference({
      xpath: opts.referenceUri || '/*',
      transforms: opts.transforms,
      digestAlgorithm: opts.digestAlgorithm,
    });

    // Compute signature
    // IMPROVEMENT-017: Use configurable XPath for signature location
    sig.computeSignature(xmlContent, {
      location: {
        reference: opts.signatureLocationXPath || '//*[local-name()="Invoice"]',
        action: opts.signatureLocationAction || 'append'
      },
      prefix: 'ds',
    });

    // Get signed XML
    const signedXml = sig.getSignedXml();

    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'sign' }, duration);
    signatureTotal.inc({ operation: 'sign', status: 'success' });

    endSpanSuccess(span);

    logger.info({
      duration_ms: duration * 1000,
      signed_xml_length: signedXml.length,
    }, 'XML document signed successfully');

    return signedXml;
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'sign' }, duration);
    signatureTotal.inc({ operation: 'sign', status: 'failure' });
    signatureErrors.inc({ error_type: 'signature_generation' });

    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Failed to sign XML document');

    throw new XMLSignatureError(
      'Failed to sign XML document',
      error as Error
    );
  }
}

/**
 * Sign UBL Invoice with XMLDSig
 *
 * Adds signature to UBL Extensions section according to Croatian e-invoice requirements
 *
 * @param ublXml - UBL 2.1 invoice XML
 * @param certificate - Parsed certificate with private key
 * @param options - Signature options (optional)
 * @returns Signed UBL invoice
 * @throws XMLSignatureError if signing fails
 */
export async function signUBLInvoice(
  ublXml: string,
  certificate: ParsedCertificate,
  options: SignatureOptions = {}
): Promise<string> {
  const span = createSpan('sign_ubl_invoice');

  try {
    logger.info('Signing UBL invoice');

    // IMPROVEMENT-018: Parse XML once (instead of twice), then properly manipulate structure
    // IMPROVEMENT-016: Use proper XML object manipulation instead of string slicing
    const parser = new xml2js.Parser();
    const parsed = await parser.parseStringPromise(ublXml);

    // Verify it's a UBL Invoice
    if (!parsed.Invoice) {
      throw new Error('Document is not a valid UBL Invoice');
    }

    // Add UBLExtensions if not present (using proper object manipulation, not string slicing)
    if (!parsed.Invoice.ext_UBLExtensions && !parsed.Invoice['ext:UBLExtensions']) {
      parsed.Invoice.ext_UBLExtensions = [{
        ext_UBLExtension: [{
          ext_ExtensionContent: ['']
        }],
        $: { 'xmlns:ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2' }
      }];

      // Move UBLExtensions to first position (correct structure)
      const extensions = parsed.Invoice.ext_UBLExtensions;
      delete parsed.Invoice.ext_UBLExtensions;
      parsed.Invoice.ext_UBLExtensions = extensions;
    }

    // Rebuild XML from parsed object
    const builder = new xml2js.Builder();
    const xmlToSign = builder.buildObject(parsed);

    // Sign the document
    const signedXml = await signXMLDocument(xmlToSign, certificate, options);

    endSpanSuccess(span);

    logger.info('UBL invoice signed successfully');

    return signedXml;
  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Failed to sign UBL invoice');

    throw new XMLSignatureError(
      'Failed to sign UBL invoice',
      error as Error
    );
  }
}

/**
 * Create detached signature (signature in separate XML document)
 *
 * @param contentToSign - Content to sign (XML or other)
 * @param certificate - Parsed certificate with private key
 * @param options - Signature options (optional)
 * @returns Detached signature XML
 * @throws XMLSignatureError if signing fails
 */
export async function createDetachedSignature(
  contentToSign: string,
  certificate: ParsedCertificate,
  contentUri: string = '',
  options: SignatureOptions = {}
): Promise<string> {
  const span = createSpan('create_detached_signature');

  const startTime = Date.now();

  try {
    logger.info({ contentUri }, 'Creating detached signature');

    // Merge options with defaults
    const opts = { ...DEFAULT_SIGNATURE_OPTIONS, ...options };

    // Create SignedXml instance
    const sig = new SignedXml({
      privateKey: certificate.privateKeyPEM,
      canonicalizationAlgorithm: opts.canonicalizationAlgorithm,
      signatureAlgorithm: opts.signatureAlgorithm,
    });

    // Add reference (for detached, URI points to external content)
    sig.addReference({
      xpath: contentUri,
      transforms: opts.transforms,
      digestAlgorithm: opts.digestAlgorithm,
    });

    // Compute signature on the content
    sig.computeSignature(contentToSign, {
      prefix: 'ds',
    });

    // Get signature XML (without the content)
    const signatureXml = sig.getSignatureXml();

    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'sign' }, duration);
    signatureTotal.inc({ operation: 'sign', status: 'success' });

    endSpanSuccess(span);

    logger.info({
      duration_ms: duration * 1000,
    }, 'Detached signature created successfully');

    return signatureXml;
  } catch (error) {
    const duration = (Date.now() - startTime) / 1000;
    signatureDuration.observe({ operation: 'sign' }, duration);
    signatureTotal.inc({ operation: 'sign', status: 'failure' });
    signatureErrors.inc({ error_type: 'signature_generation' });

    setSpanError(span, error as Error);
    span.end();

    logger.error({ error }, 'Failed to create detached signature');

    throw new XMLSignatureError(
      'Failed to create detached signature',
      error as Error
    );
  }
}
