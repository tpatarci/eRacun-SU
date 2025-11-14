import { describe, it, expect, beforeAll } from '@jest/globals';
import forge from 'node-forge';
import { InvoiceGenerator } from '../../../../shared/test-fixtures/src/InvoiceGenerator';
import { XMLGenerator } from '../../../../shared/test-fixtures/src/XMLGenerator';
import { signUBLInvoice, signXMLDocument } from '../../src/xmldsig-signer.js';
import type { ParsedCertificate } from '../../src/certificate-parser.js';

let certificate: ParsedCertificate;

beforeAll(() => {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(cert.validity.notBefore.getTime() + 365 * 24 * 3600 * 1000);
  const attrs = [{ name: 'commonName', value: 'Fixture Signer' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey);

  certificate = {
    info: {
      subjectDN: '/CN=Fixture Signer',
      issuerDN: '/CN=Fixture Signer',
      serialNumber: cert.serialNumber,
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
      issuer: 'Fixture Signer',
      publicKey: cert.publicKey as forge.pki.rsa.PublicKey,
      certificate: cert,
    },
    privateKey: keys.privateKey,
    certificatePEM: forge.pki.certificateToPem(cert),
    privateKeyPEM: forge.pki.privateKeyToPem(keys.privateKey),
  };
});

describe('XMLDSig signer – shared fixture contract', () => {
  it('embeds a ds:Signature element for fixture invoices per XMLDSIG_GUIDE', async () => {
    const invoice = InvoiceGenerator.generateValidInvoice();
    const xml = XMLGenerator.generateUBL21XML(invoice);

    const signed = await signUBLInvoice(xml, certificate);

    expect(signed).toContain('<ds:Signature');
    expect(signed).toContain('http://www.w3.org/2000/09/xmldsig#enveloped-signature');
    expect(signed).toContain('http://www.w3.org/2001/10/xml-exc-c14n#');
  });

  it('preserves canonicalization defaults documented in XMLDSIG_GUIDE', async () => {
    const invoice = InvoiceGenerator.generateValidInvoice();
    const xml = XMLGenerator.generateUBL21XML(invoice);

    const signed = await signXMLDocument(xml, certificate);

    expect(signed).toContain('rsa-sha256');
    expect(signed).toContain('xml-exc-c14n');
  });
});
