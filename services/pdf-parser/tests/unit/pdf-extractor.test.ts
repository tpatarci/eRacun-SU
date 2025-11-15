/**
 * PDF Extractor Module Tests
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import type pdfParse from 'pdf-parse';

import { PDFExtractor, createPDFExtractorFromEnv } from '../../src/pdf-extractor';

type PdfParseFn = typeof pdfParse;

let mockPdfParse: jest.MockedFunction<PdfParseFn>;

describe('PDFExtractor', () => {
  let extractor: PDFExtractor;

  beforeEach(() => {
    jest.clearAllMocks();
    mockPdfParse = jest.fn() as jest.MockedFunction<PdfParseFn>;
    extractor = new PDFExtractor(
      {
        maxFileSize: 10 * 1024 * 1024,
        maxPages: 100,
        minTextLength: 100,
      },
      mockPdfParse
    );
  });

  describe('Constructor', () => {
    it('should create extractor with default config when no parameters provided', () => {
      const defaultExtractor = new PDFExtractor({}, mockPdfParse);
      const config = defaultExtractor.getConfig();

      expect(config.maxFileSize).toBe(10 * 1024 * 1024);
      expect(config.maxPages).toBe(100);
      expect(config.minTextLength).toBe(100);
    });
  });

  describe('extractPDF', () => {
    it('should extract text from native PDF', async () => {
      const mockPdfBuffer = Buffer.from('mock pdf content');
      mockPdfParse.mockResolvedValue({
        numpages: 2,
        text: `INVOICE - RAČUN

Invoice Number: R-2024-00123
Date: 12.11.2024
Due Date: 26.11.2024

Vendor Information:
Company Name: Test Company d.o.o.
Address: Ilica 123, 10000 Zagreb, Croatia
OIB: 12345678901
IBAN: HR1234567890123456789

Customer Information:
Customer Name: Example Client d.o.o.
Address: Savska 45, 10000 Zagreb, Croatia
OIB: 98765432109

Line Items:
1. Consulting Services - Project Management - Quantity: 40 hours - Rate: 100.00 EUR - Amount: 4,000.00 EUR
2. Software Development - Backend Implementation - Quantity: 60 hours - Rate: 120.00 EUR - Amount: 7,200.00 EUR
3. Quality Assurance Testing - Quantity: 20 hours - Rate: 80.00 EUR - Amount: 1,600.00 EUR

Subtotal: 12,800.00 EUR
VAT (25%): 3,200.00 EUR
Total Amount: 16,000.00 EUR

Payment Terms: Net 14 days
Bank Details: Privredna banka Zagreb
Reference Number: HR00 123-456-789

This is extracted PDF text with sufficient content for native PDF detection. This document contains multiple paragraphs and detailed information that would be typical of a real invoice or business document with plenty of text content spread across multiple pages.`,
        info: {
          Title: 'Test Invoice',
          Author: 'Test Company',
          CreationDate: 'D:20241112120000',
        },
      } as any);

      const result = await extractor.extractPDF(mockPdfBuffer, 'test.pdf');

      expect(result.text).toContain('extracted PDF text');
      expect(result.pageCount).toBe(2);
      expect(result.isScanned).toBe(false);
      expect(result.quality).toBe('high');
      expect(result.metadata.title).toBe('Test Invoice');
      expect(result.metadata.author).toBe('Test Company');
    });

    it('should detect scanned PDF with low text content', async () => {
      const mockPdfBuffer = Buffer.from('mock scanned pdf');
      mockPdfParse.mockResolvedValue({
        numpages: 3,
        text: 'abc', // Very little text
        info: {},
      } as any);

      const result = await extractor.extractPDF(mockPdfBuffer, 'scanned.pdf');

      expect(result.isScanned).toBe(true);
      expect(result.quality).toBe('low');
    });

    it('should detect scanned PDF with low meaningful text ratio', async () => {
      const mockPdfBuffer = Buffer.from('mock scanned pdf');
      // Text with lots of whitespace/garbage (scanned PDF artifact)
      const garbageText = '   \n\n\n   \t\t\t   \n   ';
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: garbageText,
        info: {},
      } as any);

      const result = await extractor.extractPDF(mockPdfBuffer);

      expect(result.isScanned).toBe(true);
    });

    it('should detect scanned PDF with very low meaningful text ratio below threshold', async () => {
      // Create text with < minTextLength and extremely low meaningful ratio
      // 'a' + 9 spaces, repeated 8 times = 80 chars total, 8 meaningful
      const lowMeaningfulText = ('a' + ' '.repeat(9)).repeat(8);
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: lowMeaningfulText,
        info: {},
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.isScanned).toBe(true);
    });

    it('should assess high quality for text-rich PDFs', async () => {
      const longText = 'A'.repeat(600) + '\nStructured content';
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: longText,
        info: {},
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.quality).toBe('high');
    });

    it('should assess medium quality for moderate text', async () => {
      const mediumText = 'A'.repeat(300);
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: mediumText,
        info: {},
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.quality).toBe('medium');
    });

    it('should assess low quality for minimal text', async () => {
      const shortText = 'ABC';
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: shortText,
        info: {},
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.quality).toBe('low');
    });

    it('should assess low quality for documents with low chars per page', async () => {
      // 150 chars per page (between 100-200, should be low quality)
      const text = 'A'.repeat(150);
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: text,
        info: {},
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.quality).toBe('low');
    });

    it('should throw error for files exceeding size limit', async () => {
      const largePdfBuffer = Buffer.alloc(11 * 1024 * 1024); // 11 MB

      await expect(extractor.extractPDF(largePdfBuffer)).rejects.toThrow('exceeds maximum');
    });

    it('should throw error for empty files', async () => {
      const emptyBuffer = Buffer.alloc(0);

      await expect(extractor.extractPDF(emptyBuffer)).rejects.toThrow('empty');
    });

    it('should handle encrypted PDFs', async () => {
      mockPdfParse.mockRejectedValue(new Error('Invalid password'));

      await expect(extractor.extractPDF(Buffer.from('encrypted pdf'))).rejects.toThrow(
        'password-protected'
      );
    });

    it('should handle corrupt PDFs', async () => {
      mockPdfParse.mockRejectedValue(new Error('Invalid PDF structure'));

      await expect(extractor.extractPDF(Buffer.from('corrupt'))).rejects.toThrow('corrupt');
    });

    it('should handle non-Error exceptions during PDF parsing', async () => {
      // Reject with a non-Error value (e.g., string)
      mockPdfParse.mockRejectedValue('Some string error');

      await expect(extractor.extractPDF(Buffer.from('pdf'))).rejects.toThrow('PDF extraction failed: Unknown error');
    });

    it('should parse PDF creation date', async () => {
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: 'Test content',
        info: {
          CreationDate: 'D:20241112143000',
        },
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.metadata.creationDate).toBeInstanceOf(Date);
      expect(result.metadata.creationDate?.getFullYear()).toBe(2024);
      expect(result.metadata.creationDate?.getMonth()).toBe(10); // November (0-indexed)
      expect(result.metadata.creationDate?.getDate()).toBe(12);
    });

    it('should handle invalid PDF creation date format', async () => {
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: 'Test content',
        info: {
          CreationDate: 'invalid-date-format',
        },
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.metadata.creationDate).toBeUndefined();
    });

    it('should handle non-string PDF creation date (triggers catch block)', async () => {
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: 'Test content',
        info: {
          CreationDate: 12345 as any, // Non-string value causes .replace() to throw
        },
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      // Catch block returns undefined
      expect(result.metadata.creationDate).toBeUndefined();
    });

    it('should handle PDF with no metadata', async () => {
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: 'Content',
        info: {},
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.metadata.title).toBeUndefined();
      expect(result.metadata.author).toBeUndefined();
      expect(result.metadata.modificationDate).toBeUndefined();
    });

    it('should parse PDF modification date when present', async () => {
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: 'Content',
        info: {
          ModDate: 'D:20241115120000',
        },
      } as any);

      const result = await extractor.extractPDF(Buffer.from('pdf'));

      expect(result.metadata.modificationDate).toBeInstanceOf(Date);
      expect(result.metadata.modificationDate?.getFullYear()).toBe(2024);
    });

    it('should record file size', async () => {
      const buffer = Buffer.from('pdf content');
      mockPdfParse.mockResolvedValue({
        numpages: 1,
        text: 'Content',
        info: {},
      } as any);

      const result = await extractor.extractPDF(buffer);

      expect(result.size).toBe(buffer.length);
    });
  });

  describe('getConfig', () => {
    it('should return configuration', () => {
      const config = extractor.getConfig();

      expect(config.maxFileSize).toBe(10 * 1024 * 1024);
      expect(config.maxPages).toBe(100);
      expect(config.minTextLength).toBe(100);
    });

    it('should return a copy of config', () => {
      const config = extractor.getConfig();
      config.maxFileSize = 999;

      const configAgain = extractor.getConfig();
      expect(configAgain.maxFileSize).toBe(10 * 1024 * 1024);
    });
  });

  describe('setConfig', () => {
    it('should update max file size', () => {
      extractor.setConfig({ maxFileSize: 5 * 1024 * 1024 });

      const config = extractor.getConfig();
      expect(config.maxFileSize).toBe(5 * 1024 * 1024);
    });

    it('should update max pages', () => {
      extractor.setConfig({ maxPages: 50 });

      const config = extractor.getConfig();
      expect(config.maxPages).toBe(50);
    });

    it('should merge with existing config', () => {
      const originalConfig = extractor.getConfig();

      extractor.setConfig({ maxFileSize: 1024 });

      const updatedConfig = extractor.getConfig();
      expect(updatedConfig.maxFileSize).toBe(1024);
      expect(updatedConfig.maxPages).toBe(originalConfig.maxPages);
    });
  });

  describe('createPDFExtractorFromEnv', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      jest.resetModules();
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should create extractor with default config when no env vars set', () => {
      const extractor = createPDFExtractorFromEnv(mockPdfParse);
      const config = extractor.getConfig();

      expect(config.maxFileSize).toBe(10 * 1024 * 1024);
      expect(config.maxPages).toBe(100);
    });

    it('should create extractor with custom max file size from env', () => {
      process.env.PDF_MAX_FILE_SIZE = '5242880';

      const extractor = createPDFExtractorFromEnv(mockPdfParse);
      const config = extractor.getConfig();

      expect(config.maxFileSize).toBe(5242880);
    });

    it('should create extractor with custom max pages from env', () => {
      process.env.PDF_MAX_PAGES = '50';

      const extractor = createPDFExtractorFromEnv(mockPdfParse);
      const config = extractor.getConfig();

      expect(config.maxPages).toBe(50);
    });

    it('should create extractor with custom min text length from env', () => {
      process.env.PDF_MIN_TEXT_LENGTH = '200';

      const extractor = createPDFExtractorFromEnv(mockPdfParse);
      const config = extractor.getConfig();

      expect(config.minTextLength).toBe(200);
    });

    it('should create extractor with all custom config from env', () => {
      process.env.PDF_MAX_FILE_SIZE = '1048576';
      process.env.PDF_MAX_PAGES = '25';
      process.env.PDF_MIN_TEXT_LENGTH = '150';

      const extractor = createPDFExtractorFromEnv(mockPdfParse);
      const config = extractor.getConfig();

      expect(config.maxFileSize).toBe(1048576);
      expect(config.maxPages).toBe(25);
      expect(config.minTextLength).toBe(150);
    });
  });
});
