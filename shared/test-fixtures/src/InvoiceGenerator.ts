/**
 * Invoice Test Data Generator
 * Generates valid and invalid UBL invoices for testing
 */

import { faker } from '@faker-js/faker';
import {
  UBLInvoice,
  Party,
  Address,
  LineItem,
  VATBreakdown
} from '@eracun/contracts';

export class InvoiceGenerator {
  /**
   * Generate a fully valid UBL invoice
   */
  static generateValidInvoice(): UBLInvoice {
    const supplierOIB = this.generateValidOIB();
    const buyerOIB = this.generateValidOIB();

    const lineItems = this.generateLineItems(2);
    const amounts = this.calculateAmounts(lineItems);

    return {
      id: faker.string.uuid(),
      invoiceNumber: `INV-${faker.string.alphanumeric(8).toUpperCase()}`,
      issueDate: faker.date.recent({ days: 30 }).toISOString().split('T')[0],
      dueDate: faker.date.future({ years: 0.1 }).toISOString().split('T')[0],
      oib: {
        supplier: supplierOIB,
        buyer: buyerOIB
      },
      supplier: this.generateParty(supplierOIB),
      buyer: this.generateParty(buyerOIB),
      lineItems,
      amounts,
      metadata: {
        source: faker.helpers.arrayElement(['email', 'api', 'sftp', 'manual']),
        receivedAt: new Date().toISOString(),
        processingId: faker.string.uuid()
      }
    };
  }

  /**
   * Generate invoice with invalid OIB (wrong check digit)
   */
  static generateInvoiceWithInvalidOIB(): UBLInvoice {
    const invoice = this.generateValidInvoice();
    invoice.oib.supplier = '11111111111'; // Invalid check digit
    invoice.supplier.vatNumber = 'HR11111111111';
    return invoice;
  }

  /**
   * Generate invoice with missing KPD codes
   */
  static generateInvoiceWithMissingKPD(): UBLInvoice {
    const invoice = this.generateValidInvoice();
    invoice.lineItems[0].kpdCode = ''; // Missing required field
    return invoice;
  }

  /**
   * Generate invoice with invalid VAT calculation
   */
  static generateInvoiceWithInvalidVAT(): UBLInvoice {
    const invoice = this.generateValidInvoice();
    // Corrupt VAT amount
    invoice.amounts.vat[0].amount = 999999;
    invoice.amounts.gross = invoice.amounts.net + 999999;
    return invoice;
  }

  /**
   * Generate invoice with invalid KPD code format
   */
  static generateInvoiceWithInvalidKPDFormat(): UBLInvoice {
    const invoice = this.generateValidInvoice();
    invoice.lineItems[0].kpdCode = '12345'; // Only 5 digits instead of 6
    return invoice;
  }

  /**
   * Generate invoice with negative amounts
   */
  static generateInvoiceWithNegativeAmounts(): UBLInvoice {
    const invoice = this.generateValidInvoice();
    invoice.lineItems[0].netAmount = -1000;
    invoice.lineItems[0].grossAmount = -1250;
    return invoice;
  }

  /**
   * Generate valid Croatian OIB with proper check digit
   */
  static generateValidOIB(): string {
    const digits = Array.from({ length: 10 }, () => Math.floor(Math.random() * 10));
    const checkDigit = this.calculateOIBCheckDigit(digits);
    return digits.join('') + checkDigit;
  }

  /**
   * Calculate OIB check digit using ISO 7064, MOD 11-10 algorithm
   */
  private static calculateOIBCheckDigit(digits: number[]): number {
    let a = 10;
    for (const digit of digits) {
      a = ((a + digit) % 10 || 10) * 2 % 11;
    }
    return (11 - a) % 10;
  }

  /**
   * Generate party (supplier or buyer)
   */
  private static generateParty(oib: string): Party {
    return {
      name: faker.company.name(),
      address: this.generateAddress(),
      vatNumber: `HR${oib}`,
      email: faker.internet.email(),
      phone: faker.phone.number(),
      registrationNumber: faker.string.numeric(8)
    };
  }

  /**
   * Generate Croatian address
   */
  private static generateAddress(): Address {
    return {
      street: faker.location.streetAddress(),
      city: faker.helpers.arrayElement(['Zagreb', 'Split', 'Rijeka', 'Osijek', 'Zadar']),
      postalCode: faker.string.numeric(5),
      country: 'HR' // ISO 3166-1 alpha-2
    };
  }

  /**
   * Generate line items
   */
  private static generateLineItems(count: number = 2): LineItem[] {
    const items: LineItem[] = [];

    for (let i = 0; i < count; i++) {
      const quantity = faker.number.int({ min: 1, max: 10 });
      const unitPrice = faker.number.float({ min: 100, max: 1000, fractionDigits: 2 });
      const vatRate = faker.helpers.arrayElement([0, 5, 13, 25] as const);
      const netAmount = quantity * unitPrice;
      const vatAmount = netAmount * (vatRate / 100);
      const grossAmount = netAmount + vatAmount;

      items.push({
        id: `line-${i + 1}`,
        description: faker.commerce.productName(),
        quantity,
        unit: 'EA', // Each (UN/ECE Rec 20)
        unitPrice,
        kpdCode: this.generateValidKPDCode(),
        vatRate,
        vatAmount,
        netAmount,
        grossAmount
      });
    }

    return items;
  }

  /**
   * Generate valid KPD code (6 digits)
   */
  private static generateValidKPDCode(): string {
    // Use realistic KPD codes
    const validCodes = [
      '123456', // Professional services
      '654321', // Computer equipment
      '111111', // Consulting services
      '222222', // Software development
      '333333', // IT support
      '444444', // Training services
      '555555', // Marketing services
      '666666', // Legal services
    ];

    return faker.helpers.arrayElement(validCodes);
  }

  /**
   * Calculate amounts from line items
   */
  private static calculateAmounts(lineItems: LineItem[]): UBLInvoice['amounts'] {
    const net = lineItems.reduce((sum, item) => sum + item.netAmount, 0);

    // Group VAT by rate
    const vatByRate = new Map<number, { base: number; amount: number }>();

    for (const item of lineItems) {
      const existing = vatByRate.get(item.vatRate) || { base: 0, amount: 0 };
      vatByRate.set(item.vatRate, {
        base: existing.base + item.netAmount,
        amount: existing.amount + item.vatAmount
      });
    }

    const vat: VATBreakdown[] = Array.from(vatByRate.entries()).map(([rate, data]) => ({
      rate: rate as 0 | 5 | 13 | 25,
      base: data.base,
      amount: data.amount,
      category: this.getVATCategory(rate as 0 | 5 | 13 | 25)
    }));

    const totalVAT = vat.reduce((sum, v) => sum + v.amount, 0);
    const gross = net + totalVAT;

    return {
      net: Math.round(net * 100) / 100,
      vat,
      gross: Math.round(gross * 100) / 100,
      currency: 'EUR'
    };
  }

  /**
   * Get VAT category based on rate
   */
  private static getVATCategory(rate: 0 | 5 | 13 | 25): 'STANDARD' | 'REDUCED' | 'SUPER_REDUCED' | 'EXEMPT' {
    switch (rate) {
      case 25:
        return 'STANDARD';
      case 13:
        return 'REDUCED';
      case 5:
        return 'SUPER_REDUCED';
      case 0:
        return 'EXEMPT';
    }
  }

  /**
   * Generate batch of invoices
   */
  static generateBatch(count: number): UBLInvoice[] {
    return Array.from({ length: count }, () => this.generateValidInvoice());
  }

  /**
   * Generate invoice with specific characteristics
   */
  static generateCustomInvoice(overrides: Partial<UBLInvoice>): UBLInvoice {
    const base = this.generateValidInvoice();
    return { ...base, ...overrides };
  }
}
