/**
 * Mock OCR Service
 * Simulates text extraction from PDFs
 */

import { injectable } from 'inversify';
import {
  IOCRService,
  TextExtractionResult,
  StructuredDataResult,
  TableExtractionResult
} from '@eracun/adapters';

@injectable()
export class MockOCRService implements IOCRService {
  async extractText(pdf: Buffer): Promise<TextExtractionResult> {
    await this.simulateNetworkDelay(500, 1500);

    // 92% success rate
    const success = Math.random() > 0.08;

    if (success) {
      return {
        success: true,
        text: this.generateMockText(),
        confidence: 0.85 + Math.random() * 0.15, // 0.85-1.0
        language: 'hr',
        pageCount: 1,
        processingTime: Math.random() * 1000 + 500
      };
    } else {
      return {
        success: false,
        text: '',
        confidence: 0,
        pageCount: 1,
        processingTime: Math.random() * 500 + 200,
        error: 'Failed to extract text: PDF is corrupted or scanned image quality is too low'
      };
    }
  }

  async extractStructuredData(pdf: Buffer): Promise<StructuredDataResult> {
    await this.simulateNetworkDelay(800, 2000);

    // 85% success rate (structured extraction is harder)
    const success = Math.random() > 0.15;

    if (success) {
      return {
        success: true,
        data: {
          invoiceNumber: `INV-${Math.floor(Math.random() * 10000)}`,
          issueDate: new Date().toISOString().split('T')[0],
          dueDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          supplierName: 'Test d.o.o.',
          supplierOIB: this.generateValidOIB(),
          buyerName: 'Buyer d.o.o.',
          buyerOIB: this.generateValidOIB(),
          totalAmount: Math.random() * 10000 + 100,
          vatAmount: Math.random() * 2500 + 25,
          currency: 'EUR',
          lineItems: [
            {
              description: 'Professional services',
              quantity: 1,
              unitPrice: 1000,
              totalPrice: 1000,
              confidence: 0.9
            }
          ]
        },
        confidence: 0.75 + Math.random() * 0.2, // 0.75-0.95
      };
    } else {
      return {
        success: false,
        data: {},
        confidence: 0,
        error: 'Failed to extract structured data: Could not identify invoice fields'
      };
    }
  }

  async extractTables(pdf: Buffer): Promise<TableExtractionResult> {
    await this.simulateNetworkDelay(600, 1800);

    // 88% success rate
    const success = Math.random() > 0.12;

    if (success) {
      return {
        success: true,
        tables: [
          {
            headers: ['Description', 'Quantity', 'Unit Price', 'Total'],
            rows: [
              ['Professional services', '1', '1000.00', '1000.00'],
              ['Consulting', '5', '200.00', '1000.00']
            ],
            confidence: 0.88
          }
        ]
      };
    } else {
      return {
        success: false,
        tables: [],
        error: 'No tables detected in document'
      };
    }
  }

  async healthCheck(): Promise<boolean> {
    await this.simulateNetworkDelay(50, 100);
    // 98% uptime
    return Math.random() > 0.02;
  }

  private generateMockText(): string {
    return `
RAČUN / INVOICE
Broj/No: INV-${Math.floor(Math.random() * 10000)}
Datum/Date: ${new Date().toISOString().split('T')[0]}

Izdavatelj/Issuer:
Test d.o.o.
OIB: ${this.generateValidOIB()}

Kupac/Buyer:
Buyer d.o.o.
OIB: ${this.generateValidOIB()}

Artikli/Items:
1. Professional services - 1000.00 EUR
2. Consulting - 1000.00 EUR

Ukupno/Total: 2000.00 EUR
PDV 25%: 500.00 EUR
Ukupno za plaćanje/Total: 2500.00 EUR
    `.trim();
  }

  private generateValidOIB(): string {
    // Generate valid Croatian OIB with check digit
    const digits = Array.from({ length: 10 }, () => Math.floor(Math.random() * 10));
    let a = 10;
    for (const digit of digits) {
      a = ((a + digit) % 10 || 10) * 2 % 11;
    }
    const checkDigit = (11 - a) % 10;
    return digits.join('') + checkDigit;
  }

  private async simulateNetworkDelay(min: number = 100, max: number = 500): Promise<void> {
    const delay = Math.random() * (max - min) + min;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}
