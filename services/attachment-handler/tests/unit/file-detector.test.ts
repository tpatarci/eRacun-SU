/**
 * Unit Tests for File Detector
 */

import { detectMimeType } from '../../src/file-detector';

describe('File Detector', () => {
  describe('detectMimeType', () => {
    it('should detect PDF from magic bytes', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4\ntest');
      const mimeType = await detectMimeType(pdfBuffer, 'test.pdf');
      expect(mimeType).toBe('application/pdf');
    });

    it('should detect ZIP from magic bytes', async () => {
      const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]);
      const mimeType = await detectMimeType(zipBuffer, 'test.zip');
      expect(mimeType).toBe('application/zip');
    });

    it('should detect JPEG from magic bytes', async () => {
      const jpegBuffer = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
      const mimeType = await detectMimeType(jpegBuffer, 'image.jpg');
      expect(mimeType).toBe('image/jpeg');
    });

    it('should detect PNG from magic bytes', async () => {
      const pngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
      const mimeType = await detectMimeType(pngBuffer, 'image.png');
      expect(mimeType).toBe('image/png');
    });

    it('should detect XML from magic bytes', async () => {
      const xmlBuffer = Buffer.from('<?xml version="1.0"?>');
      const mimeType = await detectMimeType(xmlBuffer, 'data.xml');
      expect(mimeType).toContain('xml');
    });

    it('should fall back to extension for unknown magic bytes', async () => {
      const unknownBuffer = Buffer.from('unknown content');
      const mimeType = await detectMimeType(unknownBuffer, 'test.txt');
      expect(mimeType).toBe('text/plain');
    });

    it('should return octet-stream for unknown files', async () => {
      const unknownBuffer = Buffer.from('???');
      const mimeType = await detectMimeType(unknownBuffer, 'unknown.xyz');
      expect(mimeType).toBe('application/octet-stream');
    });

    it('should handle empty buffer', async () => {
      const emptyBuffer = Buffer.from([]);
      const mimeType = await detectMimeType(emptyBuffer, 'empty.txt');
      expect(mimeType).toBeDefined();
    });

    it('should detect RAR archives', async () => {
      const rarBuffer = Buffer.from('Rar!\x1A\x07\x00');
      const mimeType = await detectMimeType(rarBuffer, 'archive.rar');
      expect(mimeType).toBe('application/x-rar-compressed');
    });

    it('should handle case-insensitive extensions', async () => {
      const buffer = Buffer.from('test');
      const mimeType = await detectMimeType(buffer, 'TEST.PDF');
      expect(mimeType).toBeDefined();
    });

    it('should detect TIFF images', async () => {
      const tiffBuffer = Buffer.from([0x49, 0x49, 0x2A, 0x00]); // Little-endian TIFF
      const mimeType = await detectMimeType(tiffBuffer, 'image.tiff');
      expect(mimeType).toContain('tiff');
    });

    it('should detect GIF images', async () => {
      const gifBuffer = Buffer.from('GIF89a');
      const mimeType = await detectMimeType(gifBuffer, 'image.gif');
      expect(mimeType).toBe('image/gif');
    });

    it('should handle binary data', async () => {
      const binaryBuffer = Buffer.from([0x00, 0xFF, 0xAA, 0x55]);
      const mimeType = await detectMimeType(binaryBuffer, 'data.bin');
      expect(mimeType).toBeDefined();
    });
  });
});
