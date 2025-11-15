import fc from 'fast-check';
import { describe, it, expect } from '@jest/globals';
import forge from 'node-forge';
import {
  signXMLDocument,
  DEFAULT_SIGNATURE_OPTIONS,
} from '../../src/xmldsig-signer.js';
import {
  verifyXMLSignature,
  parseCertificateInfo,
  normalizeSerialNumber,
} from '../../src/xmldsig-verifier.js';
import { generateZKI, type ZKIParams } from '../../src/zki-generator.js';
import type { ParsedCertificate } from '../../src/certificate-parser.js';
import {
  invoicePropertyArb,
  certificateMetadataArb,
  type InvoicePropertySample,
  type CertificateMetadataSample,
} from '../../../../shared/testing/property-generators';

const baseKeyPair = forge.pki.rsa.generateKeyPair(2048);
const defaultCertificate = createParsedCertificate({
  subject: {
    commonName: 'Default Subject',
    organization: 'eRacun QA',
    organizationalUnit: 'Property Tests',
    locality: 'Zagreb',
    country: 'HR',
  },
  issuer: {
    commonName: 'Default Issuer',
    organization: 'eRacun QA',
    organizationalUnit: 'PKI',
    locality: 'Zagreb',
    country: 'HR',
  },
  serialNumber: '01',
  notBefore: new Date('2024-01-01T00:00:00Z'),
  notAfter: new Date('2027-01-01T00:00:00Z'),
});

const fcConfig = { numRuns: 30, interruptAfterTimeLimit: 5000 } as const;

function createParsedCertificate(metadata: CertificateMetadataSample): ParsedCertificate {
  const cert = forge.pki.createCertificate();
  cert.publicKey = baseKeyPair.publicKey;
  cert.serialNumber = metadata.serialNumber;
  cert.validity.notBefore = metadata.notBefore;
  cert.validity.notAfter = metadata.notAfter;
  cert.setSubject(toForgeAttributes(metadata.subject));
  cert.setIssuer(toForgeAttributes(metadata.issuer));
  cert.sign(baseKeyPair.privateKey);

  return {
    info: {
      subjectDN: toDistinguishedName(metadata.subject),
      issuerDN: toDistinguishedName(metadata.issuer),
      serialNumber: metadata.serialNumber,
      notBefore: metadata.notBefore,
      notAfter: metadata.notAfter,
      issuer: metadata.issuer.commonName,
      publicKey: baseKeyPair.publicKey,
      certificate: cert,
    },
    privateKey: baseKeyPair.privateKey,
    certificatePEM: forge.pki.certificateToPem(cert),
    privateKeyPEM: forge.pki.privateKeyToPem(baseKeyPair.privateKey),
  };
}

describe('Digital signature service property tests', () => {
  it('produces stable canonicalized signatures for identical payloads', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample) => {
        const signedOnce = await signXMLDocument(sample.xml, defaultCertificate);
        const signedTwice = await signXMLDocument(sample.xml, defaultCertificate);

        expect(signedOnce).toEqual(signedTwice);
        expect(signedOnce).toContain(DEFAULT_SIGNATURE_OPTIONS.canonicalizationAlgorithm);
      }),
      fcConfig
    );
  });

  it('verifies canonicalized payloads and rejects tampering', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample) => {
        const signedXml = await signXMLDocument(sample.xml, defaultCertificate);
        const verification = await verifyXMLSignature(signedXml);
        expect(verification.isValid).toBe(true);

        const tamperedTotal = (Number(sample.totalAmount) + 0.01).toFixed(2);
        const tamperedXml = signedXml.replace(sample.totalAmount, tamperedTotal);
        const tamperedResult = await verifyXMLSignature(tamperedXml);
        expect(tamperedResult.isValid).toBe(false);
        expect(tamperedResult.errors.length).toBeGreaterThan(0);
      }),
      fcConfig
    );
  });

  it('keeps ZKI generation idempotent for identical fiscal parameters', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample) => {
        const params = buildZkiParams(sample);
        const first = await generateZKI(params, defaultCertificate);
        const second = await generateZKI(params, defaultCertificate);

        expect(second).toEqual(first);
      }),
      fcConfig
    );
  });

  it('changes ZKI output whenever fiscal payload changes', async () => {
    await fc.assert(
      fc.asyncProperty(invoicePropertyArb, async (sample) => {
        const params = buildZkiParams(sample);
        const mutated: ZKIParams = {
          ...params,
          totalAmount: (Number(params.totalAmount) + 0.01).toFixed(2),
        };

        const original = await generateZKI(params, defaultCertificate);
        const changed = await generateZKI(mutated, defaultCertificate);

        expect(changed).not.toEqual(original);
      }),
      fcConfig
    );
  });

  it('preserves certificate metadata ordering during parsing', async () => {
    await fc.assert(
      fc.property(certificateMetadataArb, (metadata) => {
        const parsedCert = createParsedCertificate(metadata);
        const info = parseCertificateInfo(parsedCert.certificatePEM);

        expect(normalizeSerialNumber(info?.serialNumber ?? '')).toEqual(
          normalizeSerialNumber(metadata.serialNumber)
        );
        expect(info?.subject).toContain(metadata.subject.commonName);
        expect(info?.issuer).toContain(metadata.issuer.commonName);
      }),
      fcConfig
    );
  });
});

function buildZkiParams(sample: InvoicePropertySample): ZKIParams {
  const digits = sample.invoiceId.replace(/\D/g, '').padEnd(11, '0').slice(0, 11);
  return {
    oib: digits,
    issueDateTime: sample.submissionTimestamp,
    invoiceNumber: sample.invoiceId.split('-')[0],
    businessPremises: `POS-${sample.submissionChannel}`,
    cashRegister: `REG-${sample.invoiceId.slice(0, 4)}`,
    totalAmount: sample.totalAmount,
  };
}

function toDistinguishedName(party: CertificateMetadataSample['subject']): string {
  return `CN=${party.commonName}, O=${party.organization}, OU=${party.organizationalUnit}, L=${party.locality}, C=${party.country}`;
}

function toForgeAttributes(party: CertificateMetadataSample['subject']): forge.pki.CertificateField[] {
  return [
    { name: 'commonName', value: party.commonName },
    { name: 'organizationName', value: party.organization },
    { shortName: 'OU', value: party.organizationalUnit },
    { name: 'localityName', value: party.locality },
    { name: 'countryName', value: party.country },
  ];
}
