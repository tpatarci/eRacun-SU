/**
 * File Detector Module Tests
 */

import { FileDetector } from '../../src/file-detector';

describe('FileDetector', () => {
  let detector: FileDetector;

  beforeEach(() => {
    jest.clearAllMocks();
    detector = new FileDetector({
      maxFileSize: 10 * 1024 * 1024,
      minFileSize: 1,
      supportedMimeTypes: [
        'application/pdf',
        'application/xml',
        'text/xml',
        'image/jpeg',
        'image/png',
      ],
    });
  });

  describe('Constructor', () => {
    it('should create detector with default options when no parameters provided', () => {
      const defaultDetector = new FileDetector();
      const options = defaultDetector.getValidationOptions();

      expect(options.maxFileSize).toBe(10 * 1024 * 1024);
      expect(options.minFileSize).toBe(1);
      expect(options.supportedMimeTypes).toBeDefined();
      expect(Array.isArray(options.supportedMimeTypes)).toBe(true);
    });
  });

  describe('detectFileType', () => {
    it('should detect PDF files by magic number', async () => {
      // PDF magic number: %PDF-
      const pdfBuffer = Buffer.from('%PDF-1.4\n%Test PDF content', 'utf-8');

      const result = await detector.detectFileType(pdfBuffer, 'test.pdf');

      expect(result.mimeType).toBe('application/pdf');
      expect(result.extension).toBe('pdf');
      expect(result.detectionMethod).toBe('magic-number');
      expect(result.isSupported).toBe(true);
      expect(result.size).toBe(pdfBuffer.length);
    });

    it('should detect PDF files by extension fallback', async () => {
      // Generic content (no magic number)
      const buffer = Buffer.from('Generic file content', 'utf-8');

      const result = await detector.detectFileType(buffer, 'invoice.pdf');

      expect(result.mimeType).toBe('application/pdf');
      expect(result.extension).toBe('pdf');
      expect(result.detectionMethod).toBe('extension');
      expect(result.isSupported).toBe(true);
    });

    it('should detect XML files by extension', async () => {
      const xmlBuffer = Buffer.from('<?xml version="1.0"?><root></root>', 'utf-8');

      const result = await detector.detectFileType(xmlBuffer, 'invoice.xml');

      // XML detection typically falls back to extension
      expect(result.mimeType).toMatch(/xml/);
      expect(result.isSupported).toBe(true);
    });

    it('should detect JPEG files by magic number', async () => {
      // JPEG magic number: FF D8 FF
      const jpegBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);

      const result = await detector.detectFileType(jpegBuffer, 'scan.jpg');

      expect(result.mimeType).toBe('image/jpeg');
      expect(result.detectionMethod).toBe('magic-number');
      expect(result.isSupported).toBe(true);
    });

    it('should detect PNG files by magic number', async () => {
      // PNG magic number: 89 50 4E 47 + IHDR chunk (minimum valid PNG)
      const pngBuffer = Buffer.from([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
        0x00, 0x00, 0x00, 0x0d, // IHDR chunk length
        0x49, 0x48, 0x44, 0x52, // IHDR
        0x00, 0x00, 0x00, 0x01, // width
        0x00, 0x00, 0x00, 0x01, // height
        0x08, 0x02, 0x00, 0x00, 0x00, // bit depth, color type, etc.
      ]);

      const result = await detector.detectFileType(pngBuffer, 'scan.png');

      expect(result.mimeType).toBe('image/png');
      expect(result.detectionMethod).toBe('magic-number');
      expect(result.isSupported).toBe(true);
    });

    it('should return unknown for undetectable files', async () => {
      const buffer = Buffer.from('Unknown content', 'utf-8');

      const result = await detector.detectFileType(buffer);

      expect(result.mimeType).toBe('application/octet-stream');
      expect(result.extension).toBe('bin');
      expect(result.detectionMethod).toBe('unknown');
      expect(result.isSupported).toBe(false);
    });

    it('should mark unsupported MIME types', async () => {
      // ZIP magic number: 50 4B 03 04
      const zipBuffer = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

      const result = await detector.detectFileType(zipBuffer, 'archive.zip');

      expect(result.mimeType).toBe('application/zip');
      expect(result.isSupported).toBe(false); // ZIP not in supported list
    });

    it('should validate file size limits', async () => {
      const tooLargeBuffer = Buffer.alloc(11 * 1024 * 1024); // 11 MB

      await expect(
        detector.detectFileType(tooLargeBuffer, 'large.pdf')
      ).rejects.toThrow('exceeds limit');
    });

    it('should allow files within size limits', async () => {
      const validBuffer = Buffer.from('%PDF-1.4\ntest', 'utf-8');

      const result = await detector.detectFileType(validBuffer, 'small.pdf');

      expect(result).toBeDefined();
      expect(result.size).toBeLessThan(10 * 1024 * 1024);
    });

    it('should handle empty files', async () => {
      const emptyBuffer = Buffer.alloc(0);

      await expect(
        detector.detectFileType(emptyBuffer, 'empty.txt')
      ).rejects.toThrow();
    });

    it('should handle files without filename', async () => {
      const buffer = Buffer.from('Some content', 'utf-8');

      const result = await detector.detectFileType(buffer);

      expect(result).toBeDefined();
      expect(result.mimeType).toBe('application/octet-stream');
    });

    it('should handle extension detection errors gracefully', async () => {
      // Test with no filename and undetectable content
      const buffer = Buffer.from([0x00, 0x01, 0x02, 0x03]);

      const result = await detector.detectFileType(buffer);

      expect(result.detectionMethod).toBe('unknown');
      expect(result.mimeType).toBe('application/octet-stream');
    });

    it('should handle magic number detection with invalid filename extension', async () => {
      // Valid content but weird extension
      const buffer = Buffer.from('test', 'utf-8');

      const result = await detector.detectFileType(buffer, 'test.invalidext123456789');

      expect(result).toBeDefined();
      expect(result.mimeType).toBeDefined();
    });

    it('should handle errors during magic number detection gracefully', async () => {
      // Import the fileType module to mock it
      const fileTypeModule = await import('file-type');

      // Mock fileType.fromBuffer to throw an error
      const originalFromBuffer = fileTypeModule.default.fromBuffer;
      fileTypeModule.default.fromBuffer = jest.fn().mockRejectedValue(new Error('Magic number detection failed'));

      // Test with a buffer that would normally be detected
      const buffer = Buffer.from('%PDF-1.4\ntest', 'utf-8');
      const result = await detector.detectFileType(buffer, 'test.pdf');

      // Should fall back to extension detection
      expect(result.mimeType).toBe('application/pdf');
      expect(result.detectionMethod).toBe('extension');

      // Restore original function
      fileTypeModule.default.fromBuffer = originalFromBuffer;
    });

    it('should handle corrupt buffer during magic number detection', async () => {
      // Import the fileType module to mock it
      const fileTypeModule = await import('file-type');

      // Mock fileType.fromBuffer to throw an error
      const originalFromBuffer = fileTypeModule.default.fromBuffer;
      fileTypeModule.default.fromBuffer = jest.fn().mockImplementation(() => {
        throw new Error('Invalid buffer format');
      });

      // Test with any buffer
      const buffer = Buffer.from('some content', 'utf-8');
      const result = await detector.detectFileType(buffer, 'document.xml');

      // Should fall back to extension detection
      expect(result.detectionMethod).toBe('extension');
      expect(result.mimeType).toMatch(/xml/);

      // Restore original function
      fileTypeModule.default.fromBuffer = originalFromBuffer;
    });
  });

  describe('getValidationOptions', () => {
    it('should return validation options', () => {
      const options = detector.getValidationOptions();

      expect(options.maxFileSize).toBe(10 * 1024 * 1024);
      expect(options.minFileSize).toBe(1);
      expect(options.supportedMimeTypes).toContain('application/pdf');
    });

    it('should return a copy of options', () => {
      const options = detector.getValidationOptions();
      options.maxFileSize = 999;

      const optionsAgain = detector.getValidationOptions();
      expect(optionsAgain.maxFileSize).toBe(10 * 1024 * 1024);
    });
  });

  describe('setValidationOptions', () => {
    it('should update max file size', () => {
      detector.setValidationOptions({
        maxFileSize: 5 * 1024 * 1024,
      });

      const options = detector.getValidationOptions();
      expect(options.maxFileSize).toBe(5 * 1024 * 1024);
    });

    it('should update supported MIME types', () => {
      detector.setValidationOptions({
        supportedMimeTypes: ['application/pdf'],
      });

      const options = detector.getValidationOptions();
      expect(options.supportedMimeTypes).toEqual(['application/pdf']);
    });

    it('should merge with existing options', () => {
      const originalOptions = detector.getValidationOptions();

      detector.setValidationOptions({
        maxFileSize: 1024,
      });

      const updatedOptions = detector.getValidationOptions();
      expect(updatedOptions.maxFileSize).toBe(1024);
      expect(updatedOptions.minFileSize).toBe(originalOptions.minFileSize);
      expect(updatedOptions.supportedMimeTypes).toEqual(originalOptions.supportedMimeTypes);
    });
  });

  describe('Custom Validation', () => {
    it('should allow all MIME types when list is empty', async () => {
      const permissiveDetector = new FileDetector({
        maxFileSize: 10 * 1024 * 1024,
        minFileSize: 1,
        supportedMimeTypes: [], // Empty = allow all
      });

      const zipBuffer = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
      const result = await permissiveDetector.detectFileType(zipBuffer, 'archive.zip');

      expect(result.isSupported).toBe(true);
    });

    it('should enforce minimum file size', async () => {
      const strictDetector = new FileDetector({
        maxFileSize: 10 * 1024 * 1024,
        minFileSize: 100,
        supportedMimeTypes: ['application/pdf'],
      });

      const tinyBuffer = Buffer.from('tiny', 'utf-8');

      await expect(
        strictDetector.detectFileType(tinyBuffer, 'tiny.pdf')
      ).rejects.toThrow();
    });
  });

  describe('createFileDetectorFromEnv', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      jest.resetModules();
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should create detector with default options when no env vars set', () => {
      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      expect(options.maxFileSize).toBe(10 * 1024 * 1024);
      expect(options.minFileSize).toBe(1);
      expect(options.supportedMimeTypes).toContain('application/pdf');
    });

    it('should create detector with custom supported MIME types from env', () => {
      process.env.SUPPORTED_MIME_TYPES = 'application/pdf,image/jpeg';

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      expect(options.supportedMimeTypes).toEqual(['application/pdf', 'image/jpeg']);
    });

    it('should create detector with custom max file size from env', () => {
      process.env.MAX_FILE_SIZE = '5242880'; // 5MB

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      expect(options.maxFileSize).toBe(5242880);
    });

    it('should create detector with custom min file size from env', () => {
      process.env.MIN_FILE_SIZE = '100';

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      expect(options.minFileSize).toBe(100);
    });

    it('should trim whitespace from MIME types in env', () => {
      process.env.SUPPORTED_MIME_TYPES = ' application/pdf , image/jpeg ';

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      expect(options.supportedMimeTypes).toEqual(['application/pdf', 'image/jpeg']);
    });

    it('should create detector with all custom options', () => {
      process.env.SUPPORTED_MIME_TYPES = 'application/pdf';
      process.env.MAX_FILE_SIZE = '1048576'; // 1MB
      process.env.MIN_FILE_SIZE = '10';

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      expect(options.supportedMimeTypes).toEqual(['application/pdf']);
      expect(options.maxFileSize).toBe(1048576);
      expect(options.minFileSize).toBe(10);
    });

    it('should handle empty string environment variables', () => {
      process.env.SUPPORTED_MIME_TYPES = '';
      process.env.MAX_FILE_SIZE = '';
      process.env.MIN_FILE_SIZE = '';

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      // Empty strings are falsy, so defaults are used
      expect(options.supportedMimeTypes).toEqual([
        'application/pdf',
        'application/xml',
        'text/xml',
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/tiff',
      ]);
      expect(options.maxFileSize).toBe(10 * 1024 * 1024);
      expect(options.minFileSize).toBe(1);
    });

    it('should handle whitespace-only SUPPORTED_MIME_TYPES', () => {
      process.env.SUPPORTED_MIME_TYPES = '   ';

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      // Should result in single empty string after trim
      expect(options.supportedMimeTypes).toEqual(['']);
    });

    it('should handle non-numeric MAX_FILE_SIZE', () => {
      process.env.MAX_FILE_SIZE = 'not-a-number';

      const { createFileDetectorFromEnv } = require('../../src/file-detector');
      const detector = createFileDetectorFromEnv();
      const options = detector.getValidationOptions();

      // parseInt of non-numeric string returns NaN
      expect(options.maxFileSize).toBeNaN();
    });
  });
});
