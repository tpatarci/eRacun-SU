#!/usr/bin/env ts-node
/**
 * Synthetic Invoice Data Generator
 * 
 * Generates realistic Croatian UBL 2.1 invoices for load testing and benchmarking.
 * Uses Faker library for randomized data generation.
 * 
 * Usage:
 *   npm run generate-invoices -- --count 100000 --output services/archive-service/fixtures
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { faker } from '@faker-js/faker/locale/hr';

interface InvoiceOptions {
  count: number;
  output: string;
  batchSize?: number;
}

// Croatian test OIBs (valid format, test data)
const TEST_OIBS = [
  '12345678901',
  '98765432109',
  '11111111117',
  '22222222225',
  '33333333333',
  '44444444441',
  '55555555559',
  '66666666667',
  '77777777775',
  '88888888883',
];

// Croatian company name suffixes
const COMPANY_SUFFIXES = ['d.o.o.', 'j.d.o.o.', 'd.d.', 'obrt'];

// KPD codes (KLASUS 2025 - sample)
const KPD_CODES = [
  { code: '26.20.11', name: 'Prijenosna računala (laptopi)' },
  { code: '26.30.22', name: 'Pametni telefoni' },
  { code: '32.50.11', name: 'Medicinski i kirurški instrumenti' },
  { code: '10.51.11', name: 'Mliječni proizvodi' },
  { code: '46.90.11', name: 'Trgovina na veliko raznom robom' },
  { code: '62.01.11', name: 'Računalno programiranje' },
  { code: '63.11.11', name: 'Obrada podataka i hosting' },
  { code: '71.11.11', name: 'Arhitektonske usluge' },
  { code: '43.21.11', name: 'Elektroinstalaterski radovi' },
  { code: '56.10.11', name: 'Djelatnosti restorana' },
];

// VAT rates in Croatia
const VAT_RATES = [
  { rate: 0.25, code: 'S', category: 'StandardRate' },
  { rate: 0.13, code: 'S', category: 'ReducedRate' },
  { rate: 0.05, code: 'S', category: 'SuperReducedRate' },
  { rate: 0.00, code: 'Z', category: 'ZeroRatedGoods' },
];

function generateOIB(): string {
  return faker.helpers.arrayElement(TEST_OIBS);
}

function generateCompanyName(): string {
  const base = faker.company.name();
  const suffix = faker.helpers.arrayElement(COMPANY_SUFFIXES);
  return `${base} ${suffix}`;
}

function generateAddress(): string {
  const street = faker.location.streetAddress();
  const city = faker.location.city();
  const zipCode = faker.location.zipCode('#####');
  return `${street}, ${zipCode} ${city}, Hrvatska`;
}

function generateInvoiceNumber(): string {
  const year = faker.date.recent({ days: 365 }).getFullYear();
  const sequence = faker.number.int({ min: 1, max: 99999 });
  return `${year}/${sequence.toString().padStart(5, '0')}`;
}

function generateInvoiceLine(index: number) {
  const kpd = faker.helpers.arrayElement(KPD_CODES);
  const quantity = faker.number.int({ min: 1, max: 100 });
  const price = faker.number.float({ min: 10, max: 10000, fractionDigits: 2 });
  const vat = faker.helpers.arrayElement(VAT_RATES);
  const netAmount = quantity * price;
  const vatAmount = netAmount * vat.rate;
  const grossAmount = netAmount + vatAmount;

  return `
    <cac:InvoiceLine>
      <cbc:ID>${index}</cbc:ID>
      <cbc:InvoicedQuantity unitCode="H87">${quantity}</cbc:InvoicedQuantity>
      <cbc:LineExtensionAmount currencyID="EUR">${netAmount.toFixed(2)}</cbc:LineExtensionAmount>
      <cac:Item>
        <cbc:Description>${kpd.name}</cbc:Description>
        <cbc:Name>${kpd.name}</cbc:Name>
        <cac:CommodityClassification>
          <cbc:ItemClassificationCode listID="KLASUS">${kpd.code}</cbc:ItemClassificationCode>
        </cac:CommodityClassification>
      </cac:Item>
      <cac:Price>
        <cbc:PriceAmount currencyID="EUR">${price.toFixed(2)}</cbc:PriceAmount>
      </cac:Price>
      <cac:TaxTotal>
        <cbc:TaxAmount currencyID="EUR">${vatAmount.toFixed(2)}</cbc:TaxAmount>
        <cac:TaxSubtotal>
          <cbc:TaxableAmount currencyID="EUR">${netAmount.toFixed(2)}</cbc:TaxableAmount>
          <cbc:TaxAmount currencyID="EUR">${vatAmount.toFixed(2)}</cbc:TaxAmount>
          <cac:TaxCategory>
            <cbc:ID>${vat.code}</cbc:ID>
            <cbc:Percent>${(vat.rate * 100).toFixed(2)}</cbc:Percent>
            <cac:TaxScheme>
              <cbc:ID>VAT</cbc:ID>
            </cac:TaxScheme>
          </cac:TaxCategory>
        </cac:TaxSubtotal>
      </cac:TaxTotal>
    </cac:InvoiceLine>`;
}

function generateUBLInvoice(index: number): string {
  const issuerOIB = generateOIB();
  const recipientOIB = generateOIB();
  const operatorOIB = generateOIB();
  const issuerName = generateCompanyName();
  const recipientName = generateCompanyName();
  const issuerAddress = generateAddress();
  const recipientAddress = generateAddress();
  const invoiceNumber = generateInvoiceNumber();
  const issueDate = faker.date.recent({ days: 365 }).toISOString().split('T')[0];
  const dueDate = faker.date.soon({ days: 30 }).toISOString().split('T')[0];
  
  const lineCount = faker.number.int({ min: 1, max: 20 });
  const lines = Array.from({ length: lineCount }, (_, i) => generateInvoiceLine(i + 1));
  
  // Calculate totals (simplified - in real implementation would sum from lines)
  const netTotal = faker.number.float({ min: 100, max: 100000, fractionDigits: 2 });
  const vatTotal = netTotal * 0.25; // Simplified - use weighted average
  const grossTotal = netTotal + vatTotal;

  return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0</cbc:CustomizationID>
  <cbc:ID>${invoiceNumber}</cbc:ID>
  <cbc:IssueDate>${issueDate}</cbc:IssueDate>
  <cbc:DueDate>${dueDate}</cbc:DueDate>
  <cbc:InvoiceTypeCode>380</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">${issuerOIB}</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>${issuerName}</cbc:Name>
      </cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>${issuerAddress}</cbc:StreetName>
        <cac:Country>
          <cbc:IdentificationCode>HR</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
    </cac:Party>
  </cac:AccountingSupplierParty>
  
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification>
        <cbc:ID schemeID="HR:OIB">${recipientOIB}</cbc:ID>
      </cac:PartyIdentification>
      <cac:PartyName>
        <cbc:Name>${recipientName}</cbc:Name>
      </cac:PartyName>
      <cac:PostalAddress>
        <cbc:StreetName>${recipientAddress}</cbc:StreetName>
        <cac:Country>
          <cbc:IdentificationCode>HR</cbc:IdentificationCode>
        </cac:Country>
      </cac:PostalAddress>
    </cac:Party>
  </cac:AccountingCustomerParty>
  
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="EUR">${vatTotal.toFixed(2)}</cbc:TaxAmount>
  </cac:TaxTotal>
  
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="EUR">${netTotal.toFixed(2)}</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="EUR">${netTotal.toFixed(2)}</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="EUR">${grossTotal.toFixed(2)}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="EUR">${grossTotal.toFixed(2)}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
  
  ${lines.join('\n')}
</Invoice>`;
}

async function generateInvoices(options: InvoiceOptions): Promise<void> {
  const { count, output, batchSize = 1000 } = options;
  
  console.log(`Generating ${count} synthetic invoices...`);
  console.log(`Output directory: ${output}`);
  console.log(`Batch size: ${batchSize}`);
  
  mkdirSync(output, { recursive: true });
  
  const batches = Math.ceil(count / batchSize);
  let generated = 0;
  
  for (let batch = 0; batch < batches; batch++) {
    const batchStart = batch * batchSize;
    const batchEnd = Math.min(batchStart + batchSize, count);
    const batchCount = batchEnd - batchStart;
    
    console.log(`\nBatch ${batch + 1}/${batches}: Generating invoices ${batchStart + 1} to ${batchEnd}...`);
    
    const invoices = [];
    for (let i = batchStart; i < batchEnd; i++) {
      invoices.push(generateUBLInvoice(i + 1));
      generated++;
      
      if ((generated % 10000) === 0) {
        console.log(`  Progress: ${generated}/${count} (${((generated / count) * 100).toFixed(1)}%)`);
      }
    }
    
    const batchFilename = `invoices-batch-${batch.toString().padStart(4, '0')}.json`;
    const batchPath = join(output, batchFilename);
    
    writeFileSync(batchPath, JSON.stringify(invoices, null, 2));
    console.log(`  Saved: ${batchFilename} (${batchCount} invoices)`);
  }
  
  console.log(`\n✅ Generated ${generated} invoices successfully!`);
  console.log(`📁 Location: ${output}`);
  console.log(`📊 Total batches: ${batches}`);
  console.log(`💾 Average batch size: ${Math.round(generated / batches)} invoices`);
}

// CLI Entry Point
const args = process.argv.slice(2);
const countIndex = args.indexOf('--count');
const outputIndex = args.indexOf('--output');
const batchIndex = args.indexOf('--batch-size');

const count = countIndex !== -1 ? parseInt(args[countIndex + 1], 10) : 1000;
const output = outputIndex !== -1 ? args[outputIndex + 1] : 'services/archive-service/fixtures';
const batchSize = batchIndex !== -1 ? parseInt(args[batchIndex + 1], 10) : 1000;

if (countIndex === -1 || outputIndex === -1) {
  console.log('Usage: ts-node generate-synthetic-invoices.ts --count <number> --output <directory> [--batch-size <number>]');
  console.log('\nExample:');
  console.log('  ts-node generate-synthetic-invoices.ts --count 100000 --output services/archive-service/fixtures --batch-size 1000');
  process.exit(1);
}

generateInvoices({ count, output, batchSize }).catch((error) => {
  console.error('Error generating invoices:', error);
  process.exit(1);
});
