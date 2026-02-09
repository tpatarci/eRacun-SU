import * as fs from 'fs/promises';
import * as path from 'path';
import {
  signXMLDocument,
  signUBLInvoice,
  createDetachedSignature,
  XMLSignatureError,
  DEFAULT_SIGNATURE_OPTIONS,
  loadCertificateFromFile,
} from '../../../src/signing';
import type { SignatureOptions } from '../../../src/signing';

describe('XMLDSig Signer', () => {
  let testCertificate: Awaited<ReturnType<typeof loadCertificateFromFile>>;

  beforeAll(async () => {
    const certPath = path.join(__dirname, '../../fixtures/test-cert.p12');
    testCertificate = await loadCertificateFromFile(certPath, 'test123');
  });

  describe('signXMLDocument', () => {
    it('should sign XML with <ds:Signature> element (Test 3.1)', async () => {
      const xml = '<Invoice>test</Invoice>';
      const signedXml = await signXMLDocument(xml, testCertificate);

      expect(signedXml).toContain('<ds:Signature');
      expect(signedXml).toContain('</ds:Signature>');
    });

    it('should produce valid parseable XML (Test 3.2)', async () => {
      const xml = '<Invoice>test</Invoice>';
      const signedXml = await signXMLDocument(xml, testCertificate);

      // Basic XML well-formedness check
      expect(signedXml).toMatch(/^<[^>]+>/);
      expect(signedXml).toMatch(/<\/[^>]+>$/);
    });

    it('should contain required signature elements (Test 3.3)', async () => {
      const xml = '<Invoice>test</Invoice>';
      const signedXml = await signXMLDocument(xml, testCertificate);

      expect(signedXml).toContain('<ds:SignedInfo>');
      expect(signedXml).toContain('</ds:SignedInfo>');
      expect(signedXml).toContain('<ds:SignatureValue>');
      expect(signedXml).toContain('</ds:SignatureValue>');
      expect(signedXml).toContain('<ds:Reference');
    });

    it('should support custom signature options', async () => {
      const xml = '<Invoice>test</Invoice>';
      const options: Partial<SignatureOptions> = {
        signatureLocationXPath: '//*[local-name()="Invoice"]',
        signatureLocationAction: 'append',
      };
      const signedXml = await signXMLDocument(xml, testCertificate, options);

      expect(signedXml).toContain('<ds:Signature');
    });
  });

  describe('signUBLInvoice', () => {
    it('should sign UBL invoice structure', async () => {
      const ublXml = `
        <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
          <ID>TEST-001</ID>
          <IssueDate>2026-01-15</IssueDate>
        </Invoice>
      `;
      const signedXml = await signUBLInvoice(ublXml, testCertificate);

      expect(signedXml).toContain('<ds:Signature');
      expect(signedXml).toContain('Invoice');
    });

    it('should throw error for non-UBL document', async () => {
      const notUblXml = '<NotInvoice>test</NotInvoice>';

      await expect(signUBLInvoice(notUblXml, testCertificate))
        .rejects.toThrow('Failed to sign UBL invoice');
    });
  });

  describe('createDetachedSignature', () => {
    it('should create detached signature', async () => {
      const content = '<Invoice>test</Invoice>';
      // Use a valid XPath for detached signature
      const signature = await createDetachedSignature(content, testCertificate, '/*');

      expect(signature).toContain('<ds:Signature');
      expect(signature).toContain('<ds:SignatureValue>');
      // Detached signature should NOT contain the original content
      expect(signature).not.toContain('<Invoice>test</Invoice>');
    });
  });

  describe('XMLSignatureError', () => {
    it('should create error with message', () => {
      const error = new XMLSignatureError('Test error');
      expect(error.message).toBe('Test error');
      expect(error.name).toBe('XMLSignatureError');
    });

    it('should support cause error', () => {
      const cause = new Error('Underlying error');
      const error = new XMLSignatureError('Test error', cause);
      expect(error.cause).toBe(cause);
    });
  });

  describe('DEFAULT_SIGNATURE_OPTIONS', () => {
    it('should have all required options', () => {
      expect(DEFAULT_SIGNATURE_OPTIONS.canonicalizationAlgorithm).toBe(
        'http://www.w3.org/2001/10/xml-exc-c14n#'
      );
      expect(DEFAULT_SIGNATURE_OPTIONS.signatureAlgorithm).toBe(
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
      );
      expect(DEFAULT_SIGNATURE_OPTIONS.digestAlgorithm).toBe(
        'http://www.w3.org/2001/04/xmlenc#sha256'
      );
      expect(DEFAULT_SIGNATURE_OPTIONS.transforms).toContain(
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
      );
    });
  });

  describe('No observability (Test 3.9)', () => {
    it('should have no opentelemetry or prom-client imports', async () => {
      const fs = require('fs');
      const content = fs.readFileSync('src/signing/xmldsig-signer.ts', 'utf8');

      expect(content).not.toContain('opentelemetry');
      expect(content).not.toContain('prom-client');
      expect(content).not.toContain('createSpan');
      expect(content).not.toContain('signatureTotal');
      expect(content).not.toContain('signatureDuration');
      expect(content).not.toContain('signatureErrors');
    });
  });
});
