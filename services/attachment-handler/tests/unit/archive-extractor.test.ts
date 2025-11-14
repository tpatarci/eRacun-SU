/**
 * Unit Tests for Archive Extractor
 */

import { ArchiveExtractor } from '../../src/archive-extractor';
import AdmZip from 'adm-zip';

describe('ArchiveExtractor', () => {
  let extractor: ArchiveExtractor;

  beforeEach(() => {
    extractor = new ArchiveExtractor({ maxNestingLevel: 3, maxTotalSize: 100 * 1024 * 1024 });
  });

  describe('extract', () => {
    it('should extract ZIP archive', async () => {
      const zip = new AdmZip();
      zip.addFile('test.txt', Buffer.from('test content'));
      const zipBuffer = zip.toBuffer();

      const result = await extractor.extract(zipBuffer, 'test.zip');

      expect(result.success).toBe(true);
      expect(result.files.length).toBe(1);
      expect(result.files[0].filename).toBe('test.txt');
      expect(result.files[0].content.toString()).toBe('test content');
    });

    it('should extract multiple files from ZIP', async () => {
      const zip = new AdmZip();
      zip.addFile('file1.txt', Buffer.from('content 1'));
      zip.addFile('file2.txt', Buffer.from('content 2'));
      zip.addFile('file3.pdf', Buffer.from('%PDF-1.4'));
      const zipBuffer = zip.toBuffer();

      const result = await extractor.extract(zipBuffer, 'archive.zip');

      expect(result.success).toBe(true);
      expect(result.files.length).toBe(3);
      const filenames = result.files.map(f => f.filename).sort();
      expect(filenames).toContain('file1.txt');
      expect(filenames).toContain('file2.txt');
      expect(filenames).toContain('file3.pdf');
    });

    it('should handle nested ZIP archives', async () => {
      const innerZip = new AdmZip();
      innerZip.addFile('inner.txt', Buffer.from('inner content'));
      
      const outerZip = new AdmZip();
      outerZip.addFile('inner.zip', innerZip.toBuffer());
      outerZip.addFile('outer.txt', Buffer.from('outer content'));
      const outerBuffer = outerZip.toBuffer();

      const result = await extractor.extract(outerBuffer, 'nested.zip');

      expect(result.success).toBe(true);
      expect(result.files.length).toBeGreaterThanOrEqual(2);
    });

    it('should enforce max nesting level', async () => {
      const limitedExtractor = new ArchiveExtractor({ maxNestingLevel: 1 });

      const innerZip = new AdmZip();
      innerZip.addFile('deep.txt', Buffer.from('deep content'));
      
      const outerZip = new AdmZip();
      outerZip.addFile('inner.zip', innerZip.toBuffer());
      const outerBuffer = outerZip.toBuffer();

      const result = await limitedExtractor.extract(outerBuffer, 'nested.zip', 1);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some(e => e.includes('nesting level'))).toBe(true);
    });

    it('should handle corrupt ZIP', async () => {
      const corruptBuffer = Buffer.from('not a zip file');

      const result = await extractor.extract(corruptBuffer, 'corrupt.zip');

      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle empty ZIP', async () => {
      const zip = new AdmZip();
      const zipBuffer = zip.toBuffer();

      const result = await extractor.extract(zipBuffer, 'empty.zip');

      expect(result.success).toBe(true);
      expect(result.files.length).toBe(0);
    });

    it('should track extracted file metadata', async () => {
      const zip = new AdmZip();
      zip.addFile('file1.txt', Buffer.from('12345'));
      zip.addFile('file2.txt', Buffer.from('67890'));
      const zipBuffer = zip.toBuffer();

      const result = await extractor.extract(zipBuffer, 'test.zip');

      expect(result.metadata.totalFiles).toBe(2);
      expect(result.metadata.totalSize).toBeGreaterThan(0);
    });
  });
});
