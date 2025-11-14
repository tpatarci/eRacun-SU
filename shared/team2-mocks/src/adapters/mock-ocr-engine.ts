/**
 * Mock OCR Engine
 * Simulates realistic OCR behavior for testing without external dependencies
 */

import { IOCREngine } from './interfaces';
import {
  TextResult,
  TableResult,
  Language,
  OCROptions,
  OCRScenario,
  TextBlock
} from '../types/ocr-types';
import { generateInvoice, InvoiceBuilder } from '../generators/invoice-generator';

export class MockOCREngine implements IOCREngine {
  private readonly scenarios: Map<string, OCRScenario>;
  private currentConfidence = 0.92;

  constructor() {
    this.scenarios = this.loadScenarios();
  }

  /**
   * Extract text from image buffer
   * Simulates OCR processing with realistic delays and confidence scores
   */
  async extractText(image: Buffer, options?: OCROptions): Promise<TextResult> {
    // Simulate processing time based on image size
    const processingTime = this.calculateProcessingTime(image);
    await this.simulateProcessing(processingTime);

    // Detect scenario based on image characteristics
    const scenario = this.detectScenario(image, options);

    // Generate realistic text blocks
    const blocks = this.generateTextBlocks(scenario);

    return {
      text: blocks.map(b => b.text).join('\n'),
      confidence: scenario.confidence,
      language: scenario.language,
      blocks,
      processingTime,
      metadata: {
        pageCount: 1,
        resolution: '300dpi',
        colorSpace: 'RGB'
      }
    };
  }

  /**
   * Extract tables from image buffer
   * Simulates table detection and extraction
   */
  async extractTables(image: Buffer): Promise<TableResult[]> {
    // Simulate processing
    await this.simulateProcessing(500);

    // Generate realistic invoice line items table
    const items = this.generateLineItems();

    return [{
      headers: ['Opis', 'Količina', 'Cijena (EUR)', 'PDV (%)', 'Ukupno (EUR)'],
      rows: items.map(item => [
        item.description,
        item.quantity.toString(),
        item.price.toFixed(2),
        (item.vat * 100).toFixed(0),
        item.total.toFixed(2)
      ]),
      confidence: 0.89,
      boundingBox: {
        x: 50,
        y: 300,
        width: 700,
        height: 400
      }
    }];
  }

  /**
   * Detect language from image buffer
   */
  async detectLanguage(image: Buffer): Promise<Language> {
    await this.simulateProcessing(100);

    // 85% Croatian, 10% English, 5% other
    const random = Math.random();
    if (random < 0.85) return Language.CROATIAN;
    if (random < 0.95) return Language.ENGLISH;
    return Language.GERMAN;
  }

  /**
   * Get overall confidence score
   */
  async getConfidence(): Promise<number> {
    return this.currentConfidence;
  }

  /**
   * Extract barcodes from image (optional feature)
   */
  async extractBarcodes(image: Buffer): Promise<string[]> {
    await this.simulateProcessing(200);

    // 30% chance of finding a barcode
    if (Math.random() < 0.3) {
      return [`HR-INV-${Date.now()}`];
    }

    return [];
  }

  /**
   * Load predefined OCR scenarios
   */
  private loadScenarios(): Map<string, OCRScenario> {
    const scenarios = new Map<string, OCRScenario>();

    scenarios.set('high-quality', {
      name: 'High Quality Scan',
      text: 'High quality document with clear text',
      confidence: 0.98,
      language: Language.CROATIAN,
      oibConfidence: 0.99,
      hasTable: true,
      hasBarcode: false
    });

    scenarios.set('medium-quality', {
      name: 'Medium Quality Scan',
      text: 'Medium quality document with some blur',
      confidence: 0.87,
      language: Language.CROATIAN,
      oibConfidence: 0.85,
      hasTable: true,
      hasBarcode: false
    });

    scenarios.set('low-quality', {
      name: 'Low Quality Scan',
      text: 'Low quality document with poor resolution',
      confidence: 0.65,
      language: Language.CROATIAN,
      oibConfidence: 0.60,
      hasTable: false,
      hasBarcode: false
    });

    scenarios.set('skewed', {
      name: 'Skewed Document',
      text: 'Document scanned at an angle',
      confidence: 0.75,
      language: Language.CROATIAN,
      oibConfidence: 0.70,
      hasTable: true,
      hasBarcode: false
    });

    scenarios.set('multilingual', {
      name: 'Multilingual Document',
      text: 'Document with mixed languages',
      confidence: 0.82,
      language: Language.CROATIAN,
      oibConfidence: 0.85,
      hasTable: true,
      hasBarcode: true
    });

    return scenarios;
  }

  /**
   * Detect scenario based on image characteristics
   */
  private detectScenario(image: Buffer, options?: OCROptions): OCRScenario {
    const sizeInMB = image.length / (1024 * 1024);

    // Larger images typically have better quality
    if (sizeInMB > 2) {
      return this.scenarios.get('high-quality')!;
    } else if (sizeInMB > 1) {
      return this.scenarios.get('medium-quality')!;
    } else if (sizeInMB > 0.5) {
      return this.scenarios.get('skewed')!;
    } else {
      return this.scenarios.get('low-quality')!;
    }
  }

  /**
   * Generate realistic text blocks from invoice data
   */
  private generateTextBlocks(scenario: OCRScenario): TextBlock[] {
    const invoice = generateInvoice();
    const blocks: TextBlock[] = [];

    // Header block
    blocks.push({
      text: `RAČUN / INVOICE`,
      boundingBox: { x: 100, y: 50, width: 400, height: 40 },
      confidence: scenario.confidence,
      language: scenario.language
    });

    // Invoice number
    blocks.push({
      text: `Broj računa: ${invoice.invoiceNumber}`,
      boundingBox: { x: 100, y: 100, width: 300, height: 30 },
      confidence: scenario.confidence,
      language: scenario.language
    });

    // Date
    blocks.push({
      text: `Datum: ${invoice.issueDate}`,
      boundingBox: { x: 100, y: 140, width: 200, height: 30 },
      confidence: scenario.confidence,
      language: scenario.language
    });

    // Supplier OIB
    blocks.push({
      text: `OIB Dobavljača: ${invoice.supplierOIB}`,
      boundingBox: { x: 100, y: 180, width: 250, height: 30 },
      confidence: scenario.oibConfidence || scenario.confidence,
      language: scenario.language
    });

    // Recipient OIB
    blocks.push({
      text: `OIB Primatelja: ${invoice.recipientOIB}`,
      boundingBox: { x: 100, y: 220, width: 250, height: 30 },
      confidence: scenario.oibConfidence || scenario.confidence,
      language: scenario.language
    });

    // Total amount
    blocks.push({
      text: `Ukupno za plaćanje: ${invoice.totalAmount.toFixed(2)} ${invoice.currency}`,
      boundingBox: { x: 500, y: 700, width: 250, height: 40 },
      confidence: scenario.confidence,
      language: scenario.language
    });

    // VAT amount
    blocks.push({
      text: `PDV: ${invoice.vatAmount.toFixed(2)} ${invoice.currency}`,
      boundingBox: { x: 500, y: 660, width: 200, height: 30 },
      confidence: scenario.confidence,
      language: scenario.language
    });

    return blocks;
  }

  /**
   * Generate line items for table extraction
   */
  private generateLineItems(): Array<{
    description: string;
    quantity: number;
    price: number;
    vat: number;
    total: number;
  }> {
    const invoice = generateInvoice();
    return invoice.lineItems;
  }

  /**
   * Calculate realistic processing time based on image size
   */
  private calculateProcessingTime(image: Buffer): number {
    const sizeInMB = image.length / (1024 * 1024);
    // Base time + size-dependent time
    return Math.min(100 + sizeInMB * 500, 5000); // 100-5000ms
  }

  /**
   * Simulate processing delay
   */
  private simulateProcessing(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
