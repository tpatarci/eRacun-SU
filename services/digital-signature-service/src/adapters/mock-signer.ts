/**
 * Mock XML Digital Signature Service
 *
 * Perfect mock implementation for XMLDSig signing and verification
 * Used for development and testing
 */

import { createSign, createVerify, createHash, generateKeyPairSync } from 'crypto';
import type {
  IXMLSigner,
  SigningOptions,
  SignedXML,
  VerificationResult,
  KeyPair,
  MockCertificate,
} from './interfaces.js';

/**
 * Mock XML Signer Implementation
 *
 * Provides realistic simulation of XMLDSig operations:
 * - RSA-SHA256 digital signatures
 * - Enveloped signature creation
 * - Signature verification
 * - Mock X.509 certificates
 * - Canonical XML (simplified)
 */
export class MockXMLSigner implements IXMLSigner {
  private readonly keyPair: KeyPair;
  private readonly certificate: MockCertificate;
  private readonly signatureRegistry: Map<string, string> = new Map();

  constructor() {
    // Generate mock RSA key pair for testing
    const keys = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    this.keyPair = {
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
    };

    this.certificate = this.generateMockCertificate();
  }

  /**
   * Sign XML document with XMLDSig enveloped signature
   */
  async signXML(xml: string, options: SigningOptions = {}): Promise<SignedXML> {
    // Simulate processing delay
    await this.simulateProcessing(20);

    // Calculate digest of the XML content
    const digest = this.calculateDigest(xml);

    // Create SignedInfo element
    const signedInfo = this.createSignedInfo(digest, options);

    // Canonicalize SignedInfo
    const canonicalSignedInfo = this.canonicalize(signedInfo);

    // Sign the canonicalized SignedInfo
    const signatureValue = this.signData(canonicalSignedInfo);

    // Build complete signature element
    const signatureElement = this.buildSignatureElement(
      signedInfo,
      signatureValue,
      this.certificate.pem
    );

    // Insert signature into XML document
    const signedXML = this.insertSignature(xml, signatureElement);

    // Store signature for verification
    const xmlHash = this.calculateHash(xml);
    this.signatureRegistry.set(xmlHash, signatureValue);

    return {
      xml: signedXML,
      signature: signatureValue,
      certificate: this.certificate.pem,
      timestamp: new Date().toISOString(),
      algorithm: 'RSA-SHA256',
    };
  }

  /**
   * Verify XML signature
   */
  async verifyXMLSignature(signedXML: string): Promise<VerificationResult> {
    // Simulate processing delay
    await this.simulateProcessing(30);

    try {
      // Extract signature value from XML
      const signatureMatch = signedXML.match(
        /<SignatureValue[^>]*>([^<]+)<\/SignatureValue>/
      );
      if (!signatureMatch) {
        return {
          valid: false,
          error: 'No signature found in document',
        };
      }

      const signatureValue = signatureMatch[1];

      // Extract SignedInfo element
      const signedInfoMatch = signedXML.match(
        /<SignedInfo[^>]*>(.*?)<\/SignedInfo>/s
      );
      if (!signedInfoMatch) {
        return {
          valid: false,
          error: 'No SignedInfo element found',
        };
      }

      const signedInfo = `<SignedInfo>${signedInfoMatch[1]}</SignedInfo>`;

      // Canonicalize SignedInfo
      const canonicalSignedInfo = this.canonicalize(signedInfo);

      // Verify signature
      const valid = this.verifySignature(canonicalSignedInfo, signatureValue);

      if (valid) {
        return {
          valid: true,
          signer: this.certificate.subject,
          timestamp: new Date().toISOString(),
          algorithm: 'RSA-SHA256',
        };
      }

      return {
        valid: false,
        error: 'Signature verification failed',
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get certificate information
   */
  getCertificateInfo(): MockCertificate {
    return { ...this.certificate };
  }

  /**
   * Create SignedInfo element
   */
  private createSignedInfo(digest: string, options: SigningOptions): string {
    const canonMethod =
      options.canonicalizationAlgorithm || 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const sigMethod =
      options.signatureAlgorithm ||
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const digestMethod =
      options.digestAlgorithm || 'http://www.w3.org/2001/04/xmlenc#sha256';
    const refUri = options.referenceUri || '';

    return `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <CanonicalizationMethod Algorithm="${canonMethod}"/>
  <SignatureMethod Algorithm="${sigMethod}"/>
  <Reference URI="${refUri}">
    <Transforms>
      <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <Transform Algorithm="${canonMethod}"/>
    </Transforms>
    <DigestMethod Algorithm="${digestMethod}"/>
    <DigestValue>${digest}</DigestValue>
  </Reference>
</SignedInfo>`;
  }

  /**
   * Build complete Signature element
   */
  private buildSignatureElement(
    signedInfo: string,
    signatureValue: string,
    certificate: string
  ): string {
    // Extract certificate body (remove PEM headers)
    const certBody = certificate
      .replace(/-----BEGIN CERTIFICATE-----/, '')
      .replace(/-----END CERTIFICATE-----/, '')
      .replace(/\s/g, '');

    return `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
${signedInfo}
  <SignatureValue>${signatureValue}</SignatureValue>
  <KeyInfo>
    <X509Data>
      <X509Certificate>${certBody}</X509Certificate>
    </X509Data>
  </KeyInfo>
</Signature>`;
  }

  /**
   * Insert signature into XML document
   */
  private insertSignature(xml: string, signature: string): string {
    // Find the root element closing tag
    // For UBL Invoice, insert before </Invoice>
    const match = xml.match(/<\/[^>]+>[\s]*$/);
    if (match) {
      const insertPosition = xml.lastIndexOf(match[0]);
      return (
        xml.substring(0, insertPosition) +
        '\n' +
        signature +
        '\n' +
        xml.substring(insertPosition)
      );
    }

    // Fallback: append to end
    return xml + '\n' + signature;
  }

  /**
   * Calculate SHA-256 digest
   */
  private calculateDigest(data: string): string {
    const hash = createHash('sha256');
    hash.update(data);
    return hash.digest('base64');
  }

  /**
   * Calculate hash for signature registry
   */
  private calculateHash(data: string): string {
    const hash = createHash('md5');
    hash.update(data);
    return hash.digest('hex');
  }

  /**
   * Sign data with private key
   */
  private signData(data: string): string {
    const signer = createSign('RSA-SHA256');
    signer.update(data);
    return signer.sign(this.keyPair.privateKey, 'base64');
  }

  /**
   * Verify signature with public key
   */
  private verifySignature(data: string, signature: string): boolean {
    try {
      const verifier = createVerify('RSA-SHA256');
      verifier.update(data);
      return verifier.verify(this.keyPair.publicKey, signature, 'base64');
    } catch {
      return false;
    }
  }

  /**
   * Canonicalize XML (simplified for mock)
   */
  private canonicalize(xml: string): string {
    // Simplified canonicalization:
    // - Remove extra whitespace between elements
    // - Normalize attribute order (not implemented in this mock)
    // - Remove XML declaration
    // - Remove comments

    return xml
      .replace(/<\?xml[^?]*\?>/g, '')
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/>\s+</g, '><')
      .trim();
  }

  /**
   * Generate mock X.509 certificate
   */
  private generateMockCertificate(): MockCertificate {
    const now = new Date();
    const validTo = new Date(now.getFullYear() + 5, now.getMonth(), now.getDate());

    return {
      subject: 'CN=Mock eRačun Service, O=Mock Organization, C=HR',
      issuer: 'CN=Mock CA, O=Mock Authority, C=HR',
      serialNumber: `MOCK-${Date.now()}`,
      validFrom: now,
      validTo,
      pem: this.generateMockPEM(),
    };
  }

  /**
   * Generate mock PEM certificate
   */
  private generateMockPEM(): string {
    // Generate realistic-looking mock certificate
    // In production, this would be a real X.509 certificate
    const randomData = Buffer.from(
      Array.from({ length: 64 }, () => Math.floor(Math.random() * 256))
    ).toString('base64');

    return `-----BEGIN CERTIFICATE-----
${randomData}
-----END CERTIFICATE-----`;
  }

  /**
   * Simulate processing time
   */
  private simulateProcessing(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

/**
 * Create mock XML signer instance
 */
export function createMockXMLSigner(): IXMLSigner {
  return new MockXMLSigner();
}
