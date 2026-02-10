/**
 * Test Data Generator
 * Generates realistic test data for Croatian e-invoice system
 *
 * Features:
 * - Valid OIB generation with checksum
 * - Valid IBAN generation (Croatian format)
 * - Realistic invoice data
 * - Deterministic generation with seed
 * - Croatian company names and addresses
 */

export interface InvoiceData {
  id: string;
  issuerOib: string;
  recipientOib: string;
  issueDate: string;
  dueDate: string;
  items: LineItem[];
  total: number;
  vat: number;
  currency: 'HRK' | 'EUR';
}

export interface LineItem {
  description: string;
  quantity: number;
  unitPrice: number;
  vatRate: number;
  total: number;
  kpdCode?: string;
}

export class DataGenerator {
  private seed: number;

  constructor(seed?: string) {
    this.seed = seed ? this.hashCode(seed) : Date.now();
  }

  /**
   * Generate valid Croatian OIB (11 digits with ISO 7064 checksum)
   */
  public generateOIB(): string {
    const digits = [];
    for (let i = 0; i < 10; i++) {
      digits.push(this.randomInt(0, 9));
    }

    // Calculate ISO 7064, MOD 11-10 checksum
    const checksum = this.calculateOIBChecksum(digits);
    return [...digits, checksum].join('');
  }

  /**
   * Validate OIB checksum
   */
  public validateOIB(oib: string): boolean {
    if (!/^\d{11}$/.test(oib)) return false;

    const digits = oib.split('').map(Number);
    const providedChecksum = digits[10];
    const calculatedChecksum = this.calculateOIBChecksum(digits.slice(0, 10));

    return providedChecksum === calculatedChecksum;
  }

  /**
   * Generate valid Croatian IBAN
   */
  public generateIBAN(): string {
    // Croatian IBAN: HR + 2 check digits + 17 digits
    // Format: HRkk bbbb bbbc cccc cccc c
    // k = check digits, b = bank code (7 digits), c = account number (10 digits)

    const bankCode = this.randomInt(1000000, 9999999).toString();
    const accountNumber = this.randomInt(1000000000, 9999999999).toString();
    const bban = bankCode + accountNumber;

    // Calculate IBAN check digits
    const checkDigits = this.calculateIBANChecksum('HR', bban);

    return `HR${checkDigits}${bban}`;
  }

  /**
   * Validate IBAN format and checksum
   */
  public validateIBAN(iban: string): boolean {
    if (!/^HR\d{19}$/.test(iban)) return false;

    const checkDigits = iban.slice(2, 4);
    const bban = iban.slice(4);
    const calculatedCheckDigits = this.calculateIBANChecksum('HR', bban);

    return checkDigits === calculatedCheckDigits;
  }

  /**
   * Generate realistic invoice
   */
  public generateInvoice(options: Partial<InvoiceData> = {}): InvoiceData {
    const itemCount = options.items?.length || this.randomInt(1, 10);
    const items = options.items || this.generateLineItems(itemCount);

    const total = items.reduce((sum, item) => sum + item.total, 0);
    const vat = items.reduce((sum, item) => sum + (item.total * item.vatRate), 0);

    const issueDate = options.issueDate || this.randomDate(new Date(2024, 0, 1), new Date());
    const dueDate = options.dueDate || this.addDays(new Date(issueDate), this.randomInt(15, 90));

    return {
      id: options.id || this.generateInvoiceNumber(),
      issuerOib: options.issuerOib || this.generateOIB(),
      recipientOib: options.recipientOib || this.generateOIB(),
      issueDate: issueDate.toISOString().split('T')[0],
      dueDate: dueDate.toISOString().split('T')[0],
      items,
      total: parseFloat(total.toFixed(2)),
      vat: parseFloat(vat.toFixed(2)),
      currency: options.currency || 'EUR'
    };
  }

  /**
   * Generate line items
   */
  private generateLineItems(count: number): LineItem[] {
    const items: LineItem[] = [];
    const products = [
      'Laptop računalo',
      'Programska licenca',
      'Konzultantske usluge',
      'Web hosting',
      'Održavanje softvera',
      'Grafički dizajn',
      'Pisač',
      'Monitor',
      'Tipkovnica',
      'Računovodstvene usluge'
    ];

    const vatRates = [0.25, 0.13, 0.05, 0]; // Croatian VAT rates

    for (let i = 0; i < count; i++) {
      const quantity = this.randomInt(1, 10);
      const unitPrice = parseFloat((this.randomInt(50, 5000) + this.random()).toFixed(2));
      const vatRate = vatRates[this.randomInt(0, vatRates.length - 1)];
      const subtotal = quantity * unitPrice;
      const total = subtotal * (1 + vatRate);

      items.push({
        description: products[this.randomInt(0, products.length - 1)],
        quantity,
        unitPrice,
        vatRate,
        total: parseFloat(total.toFixed(2)),
        kpdCode: this.generateKPDCode()
      });
    }

    return items;
  }

  /**
   * Generate KLASUS KPD code (6 digits)
   */
  private generateKPDCode(): string {
    return this.randomInt(100000, 999999).toString();
  }

  /**
   * Generate invoice number
   */
  private generateInvoiceNumber(): string {
    const year = new Date().getFullYear();
    const sequential = this.randomInt(1, 9999).toString().padStart(4, '0');
    return `${year}-${sequential}`;
  }

  /**
   * Calculate OIB checksum (ISO 7064, MOD 11-10)
   */
  private calculateOIBChecksum(digits: number[]): number {
    let a = 10;
    for (const digit of digits) {
      a = a + digit;
      a = a % 10;
      if (a === 0) a = 10;
      a = (a * 2) % 11;
    }
    const checksum = (11 - a) % 10;
    return checksum;
  }

  /**
   * Calculate IBAN check digits
   */
  private calculateIBANChecksum(countryCode: string, bban: string): string {
    // Move country code to end, replace letters with numbers (A=10, B=11, ...)
    const rearranged = bban + countryCode.split('').map(c => c.charCodeAt(0) - 55).join('') + '00';

    // Calculate mod 97
    let remainder = BigInt(rearranged) % 97n;
    const checkDigits = 98 - Number(remainder);

    return checkDigits.toString().padStart(2, '0');
  }

  /**
   * Random integer between min and max (inclusive)
   */
  private randomInt(min: number, max: number): number {
    return Math.floor(this.random() * (max - min + 1)) + min;
  }

  /**
   * Random float between 0 and 1
   */
  private random(): number {
    // Linear Congruential Generator (LCG)
    this.seed = (this.seed * 1103515245 + 12345) & 0x7fffffff;
    return this.seed / 0x7fffffff;
  }

  /**
   * Random date between start and end
   */
  private randomDate(start: Date, end: Date): Date {
    const startTime = start.getTime();
    const endTime = end.getTime();
    const randomTime = startTime + this.random() * (endTime - startTime);
    return new Date(randomTime);
  }

  /**
   * Add days to date
   */
  private addDays(date: Date, days: number): Date {
    const result = new Date(date);
    result.setDate(result.getDate() + days);
    return result;
  }

  /**
   * Hash string to number
   */
  private hashCode(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }
}

/**
 * Pre-generated valid OIBs for testing
 */
export const SAMPLE_OIBS = [
  '12345678903', // Valid OIB
  '98765432109', // Valid OIB
  '11111111107', // Valid OIB
  '22222222205', // Valid OIB
  '33333333303', // Valid OIB
];

export default DataGenerator;
