/**
 * Invoice Data Generator
 * Generates realistic Croatian invoice data for testing
 */

import { faker } from '@faker-js/faker';
import { StructuredInvoice, LineItem } from '../types/ai-types';

/**
 * Croatian VAT rates
 */
export const CROATIAN_VAT_RATES = [0.25, 0.13, 0.05, 0.0];

/**
 * Generate valid Croatian OIB (Osobni identifikacijski broj)
 * 11-digit personal identification number
 */
export function generateOIB(): string {
  const digits: number[] = [];

  // Generate first 10 random digits
  for (let i = 0; i < 10; i++) {
    digits.push(faker.number.int({ min: 0, max: 9 }));
  }

  // Calculate check digit using ISO 7064, MOD 11-10
  let checksum = 10;
  for (const digit of digits) {
    checksum = ((checksum + digit) % 10 || 10) * 2 % 11;
  }

  const checkDigit = (11 - checksum) % 10;
  digits.push(checkDigit);

  return digits.join('');
}

/**
 * Generate realistic invoice number
 * Format: YYYY-NNN where NNN is sequential number
 */
export function generateInvoiceNumber(year?: number): string {
  const invoiceYear = year || new Date().getFullYear();
  const sequentialNumber = faker.number.int({ min: 1, max: 9999 });
  return `${invoiceYear}-${sequentialNumber.toString().padStart(4, '0')}`;
}

/**
 * Generate line item with KPD code
 */
export function generateLineItem(): LineItem {
  const quantity = faker.number.int({ min: 1, max: 100 });
  const price = faker.number.float({ min: 10, max: 1000, precision: 0.01 });
  const vatRate = faker.helpers.arrayElement(CROATIAN_VAT_RATES);
  const netTotal = quantity * price;
  const vatAmount = netTotal * vatRate;
  const total = netTotal + vatAmount;

  // Croatian KPD codes (KLASUS 2025)
  const kpdCodes = [
    '012210', // Vegetables
    '103220', // Computer equipment
    '252910', // Metal products
    '331400', // Repair services
    '461900', // Wholesale trade
    '551000', // Hotels and accommodation
    '621100', // Computer programming
    '711100', // Architectural services
    '771200', // Vehicle rental
    '900400'  // Arts and entertainment
  ];

  return {
    description: faker.commerce.productName(),
    quantity,
    price,
    vat: vatRate,
    total,
    kpdCode: faker.helpers.arrayElement(kpdCodes)
  };
}

/**
 * Generate structured invoice with realistic data
 */
export function generateInvoice(overrides?: Partial<StructuredInvoice>): StructuredInvoice {
  const lineItemCount = faker.number.int({ min: 1, max: 10 });
  const lineItems = Array.from({ length: lineItemCount }, () => generateLineItem());

  const netAmount = lineItems.reduce((sum, item) => sum + (item.quantity * item.price), 0);
  const vatAmount = lineItems.reduce((sum, item) => sum + (item.quantity * item.price * item.vat), 0);
  const totalAmount = netAmount + vatAmount;

  const invoice: StructuredInvoice = {
    invoiceNumber: generateInvoiceNumber(),
    issueDate: faker.date.recent({ days: 30 }).toISOString().split('T')[0],
    supplierOIB: generateOIB(),
    recipientOIB: generateOIB(),
    totalAmount: parseFloat(totalAmount.toFixed(2)),
    vatAmount: parseFloat(vatAmount.toFixed(2)),
    netAmount: parseFloat(netAmount.toFixed(2)),
    currency: 'EUR', // Croatia uses EUR since 2023
    lineItems,
    paymentTerms: faker.helpers.arrayElement([
      'Net 30',
      'Net 15',
      'Due on receipt',
      'Net 45',
      '2/10 Net 30'
    ]),
    deliveryDate: faker.date.future({ years: 0.1 }).toISOString().split('T')[0]
  };

  return { ...invoice, ...overrides };
}

/**
 * Generate valid UBL 2.1 XML invoice
 */
export function generateValidUBL(): string {
  const invoice = generateInvoice();

  // Simplified UBL 2.1 structure for testing
  return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>${invoice.invoiceNumber}</cbc:ID>
  <cbc:IssueDate>${invoice.issueDate}</cbc:IssueDate>
  <cbc:DocumentCurrencyCode>${invoice.currency}</cbc:DocumentCurrencyCode>

  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>${invoice.supplierOIB}</cbc:CompanyID>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>${invoice.recipientOIB}</cbc:CompanyID>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="${invoice.currency}">${invoice.netAmount.toFixed(2)}</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="${invoice.currency}">${invoice.netAmount.toFixed(2)}</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="${invoice.currency}">${invoice.totalAmount.toFixed(2)}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="${invoice.currency}">${invoice.totalAmount.toFixed(2)}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>

  ${invoice.lineItems.map((item, idx) => `
  <cac:InvoiceLine>
    <cbc:ID>${idx + 1}</cbc:ID>
    <cbc:InvoicedQuantity unitCode="EA">${item.quantity}</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="${invoice.currency}">${(item.quantity * item.price).toFixed(2)}</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>${item.description}</cbc:Description>
      <cac:CommodityClassification>
        <cbc:ItemClassificationCode listID="KLASUS">${item.kpdCode}</cbc:ItemClassificationCode>
      </cac:CommodityClassification>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="${invoice.currency}">${item.price.toFixed(2)}</cbc:PriceAmount>
    </cac:Price>
    <cac:TaxTotal>
      <cbc:TaxAmount currencyID="${invoice.currency}">${(item.quantity * item.price * item.vat).toFixed(2)}</cbc:TaxAmount>
      <cac:TaxSubtotal>
        <cbc:TaxableAmount currencyID="${invoice.currency}">${(item.quantity * item.price).toFixed(2)}</cbc:TaxableAmount>
        <cbc:TaxAmount currencyID="${invoice.currency}">${(item.quantity * item.price * item.vat).toFixed(2)}</cbc:TaxAmount>
        <cac:TaxCategory>
          <cbc:Percent>${(item.vat * 100).toFixed(0)}</cbc:Percent>
          <cac:TaxScheme>
            <cbc:ID>VAT</cbc:ID>
          </cac:TaxScheme>
        </cac:TaxCategory>
      </cac:TaxSubtotal>
    </cac:TaxTotal>
  </cac:InvoiceLine>
  `).join('')}
</Invoice>`;
}

/**
 * Invoice Builder for Test Data
 * Provides fluent API for creating test invoices
 */
export class InvoiceBuilder {
  private invoice: Partial<StructuredInvoice> = {};

  static create(): InvoiceBuilder {
    return new InvoiceBuilder();
  }

  static createValid(): InvoiceBuilder {
    const builder = new InvoiceBuilder();
    builder.invoice = generateInvoice();
    return builder;
  }

  withInvoiceNumber(number: string): this {
    this.invoice.invoiceNumber = number;
    return this;
  }

  withAmount(amount: number): this {
    this.invoice.totalAmount = amount;
    return this;
  }

  withSupplier(oib: string): this {
    this.invoice.supplierOIB = oib;
    return this;
  }

  withRecipient(oib: string): this {
    this.invoice.recipientOIB = oib;
    return this;
  }

  withDate(date: string): this {
    this.invoice.issueDate = date;
    return this;
  }

  withLineItems(items: LineItem[]): this {
    this.invoice.lineItems = items;
    return this;
  }

  build(): StructuredInvoice {
    return generateInvoice(this.invoice);
  }
}
