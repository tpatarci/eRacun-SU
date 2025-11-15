import fc from 'fast-check';
import { createHash } from 'crypto';

export type SubmissionChannel = 'B2B' | 'B2C';
export type ConfirmationType = 'JIR' | 'UUID';

export interface InvoicePropertySample {
  invoiceId: string;
  xml: string;
  base64Xml: string;
  submissionChannel: SubmissionChannel;
  confirmationReference: {
    type: ConfirmationType;
    value: string;
  };
  submissionTimestamp: string;
  issueDate: string;
  totalAmount: string;
  currency: string;
  note: string;
}

export interface CertificatePartyMetadata {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  locality: string;
  country: string;
}

export interface CertificateMetadataSample {
  subject: CertificatePartyMetadata;
  issuer: CertificatePartyMetadata;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
}

export interface PayloadDigestSample {
  payload: Buffer;
  digest: string;
}

const countryCodeArb = fc.constantFrom(
  'HR',
  'DE',
  'SI',
  'AT',
  'IT',
  'HU',
  'FR',
  'BE'
);

const partyMetadataArb = fc.record<CertificatePartyMetadata>({
  commonName: fc.string({ minLength: 3, maxLength: 32 }),
  organization: fc.string({ minLength: 3, maxLength: 32 }),
  organizationalUnit: fc.string({ minLength: 2, maxLength: 32 }),
  locality: fc.string({ minLength: 2, maxLength: 32 }),
  country: countryCodeArb,
}).map((party: CertificatePartyMetadata) => ({
  ...party,
  commonName: sanitizeDnFragment(party.commonName),
  organization: sanitizeDnFragment(party.organization),
  organizationalUnit: sanitizeDnFragment(party.organizationalUnit),
  locality: sanitizeDnFragment(party.locality),
}));

const isoDateRangeStart = new Date('2020-01-01T00:00:00Z').getTime();
const isoDateRangeEnd = new Date('2035-12-31T23:59:59Z').getTime();

export const certificateMetadataArb: fc.Arbitrary<CertificateMetadataSample> = fc
  .record<CertificateMetadataSample>({
    subject: partyMetadataArb,
    issuer: partyMetadataArb,
    serialNumber: fc.hexaString({ minLength: 8, maxLength: 32 }),
    notBefore: fc.date({ min: new Date('2020-01-01'), max: new Date('2030-12-31') }),
    notAfter: fc.date({ min: new Date('2031-01-01'), max: new Date('2036-12-31') }),
  })
  .map((sample: CertificateMetadataSample) => ({
    ...sample,
    notBefore: clampDate(sample.notBefore, isoDateRangeStart, isoDateRangeEnd),
    notAfter: clampDate(sample.notAfter, isoDateRangeStart, isoDateRangeEnd),
  }));

export const payloadDigestArb: fc.Arbitrary<PayloadDigestSample> = fc
  .uint8Array({ minLength: 32, maxLength: 4096 })
  .map((payload: Uint8Array) => {
    const buffer = Buffer.from(payload);
    return {
      payload: buffer,
      digest: createHash('sha512').update(buffer).digest('hex'),
    };
  });

const amountArb = fc
  .double({
    min: 0.01,
    max: 500000,
    noDefaultInfinity: true,
    noNaN: true,
  })
  .map((value: number) => value.toFixed(2));

const noteArb = fc
  .string({ minLength: 8, maxLength: 96 })
  .map((note: string) => sanitizeXmlContent(note));

export const invoicePropertyArb: fc.Arbitrary<InvoicePropertySample> = fc
  .record({
    invoiceId: fc.uuid(),
    submissionChannel: fc.constantFrom<SubmissionChannel>('B2B', 'B2C'),
    confirmationReference: fc.oneof(
      fc.record({
        type: fc.constant<ConfirmationType>('JIR'),
        value: fc.hexaString({ minLength: 10, maxLength: 20 }),
      }),
      fc.record({
        type: fc.constant<ConfirmationType>('UUID'),
        value: fc.uuid(),
      })
    ),
    submissionTimestamp: fc
      .date({ min: new Date('2024-01-01'), max: new Date('2030-12-31') })
      .map((date: Date) => date.toISOString()),
    issueDate: fc
      .date({ min: new Date('2024-01-01'), max: new Date('2030-12-31') })
      .map((date: Date) => date.toISOString().split('T')[0]),
    totalAmount: amountArb,
    currency: fc.constantFrom('EUR', 'USD', 'GBP'),
    note: noteArb,
  })
  .map((sample: Omit<InvoicePropertySample, 'xml' | 'base64Xml'>) => {
    const xml = buildUBLInvoiceXml(sample);
    return {
      ...sample,
      xml,
      base64Xml: Buffer.from(xml, 'utf-8').toString('base64'),
    };
  });

function buildUBLInvoiceXml(sample: Omit<InvoicePropertySample, 'xml' | 'base64Xml'>): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">\n  <cbc:ID>${sample.invoiceId}</cbc:ID>\n  <cbc:IssueDate>${sample.issueDate}</cbc:IssueDate>\n  <cbc:Note>${sample.note}</cbc:Note>\n  <cbc:DocumentCurrencyCode>${sample.currency}</cbc:DocumentCurrencyCode>\n  <cbc:PayableAmount currencyID="${sample.currency}">${sample.totalAmount}</cbc:PayableAmount>\n</Invoice>`;
}

function sanitizeXmlContent(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function sanitizeDnFragment(value: string): string {
  return value.replace(/[=,]/g, '-');
}

function clampDate(date: Date, minMs: number, maxMs: number): Date {
  const clamped = new Date(Math.min(Math.max(date.getTime(), minMs), maxMs));
  return clamped;
}
