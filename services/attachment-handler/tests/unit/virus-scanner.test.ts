/**
 * Unit Tests for Virus Scanner
 */

import { VirusScanner } from '../../src/virus-scanner';

describe('VirusScanner', () => {
  let scanner: VirusScanner;

  beforeEach(() => {
    scanner = new VirusScanner();
  });

  describe('scan', () => {
    it('should scan clean file', async () => {
      const cleanBuffer = Buffer.from('normal file content');
      const result = await scanner.scan(cleanBuffer, 'clean.txt');

      expect(result.clean).toBe(true);
      expect(result.threats).toHaveLength(0);
      expect(result.scanner).toBe('MockScanner');
      expect(result.timestamp).toBeInstanceOf(Date);
    });

    it('should detect EICAR test file', async () => {
      const eicarBuffer = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
      const result = await scanner.scan(eicarBuffer, 'eicar.txt');

      expect(result.clean).toBe(false);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]).toContain('EICAR');
    });

    it('should detect malicious script patterns', async () => {
      const scriptBuffer = Buffer.from('<script>alert("xss")</script>');
      const result = await scanner.scan(scriptBuffer, 'malicious.html');

      expect(result.clean).toBe(false);
      expect(result.threats.some(t => t.includes('script'))).toBe(true);
    });

    it('should detect executable patterns', async () => {
      const exeBuffer = Buffer.from('MZ\x90\x00\x03'); // DOS header
      const result = await scanner.scan(exeBuffer, 'program.exe');

      expect(result.clean).toBe(false);
      expect(result.threats.some(t => t.includes('executable'))).toBe(true);
    });

    it('should detect suspicious macro patterns', async () => {
      const macroBuffer = Buffer.from('Auto_Open()\nShell("calc")');
      const result = await scanner.scan(macroBuffer, 'document.docm');

      expect(result.clean).toBe(false);
      expect(result.threats.some(t => t.toLowerCase().includes('macro'))).toBe(true);
    });

    it('should handle large files', async () => {
      const largeBuffer = Buffer.alloc(10 * 1024 * 1024, 'a'); // 10MB
      const result = await scanner.scan(largeBuffer, 'large.bin');

      expect(result).toHaveProperty('clean');
      expect(result).toHaveProperty('threats');
    });

    it('should handle empty files', async () => {
      const emptyBuffer = Buffer.from([]);
      const result = await scanner.scan(emptyBuffer, 'empty.txt');

      expect(result.clean).toBe(true);
      expect(result.threats).toHaveLength(0);
    });

    it('should include scan timestamp', async () => {
      const buffer = Buffer.from('test');
      const beforeScan = new Date();
      const result = await scanner.scan(buffer, 'test.txt');
      const afterScan = new Date();

      expect(result.timestamp.getTime()).toBeGreaterThanOrEqual(beforeScan.getTime());
      expect(result.timestamp.getTime()).toBeLessThanOrEqual(afterScan.getTime());
    });

    it('should handle binary data', async () => {
      const binaryBuffer = Buffer.from([0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF]);
      const result = await scanner.scan(binaryBuffer, 'binary.bin');

      expect(result).toHaveProperty('clean');
      expect(result.scanner).toBe('MockScanner');
    });

    it('should scan PDF files', async () => {
      const pdfBuffer = Buffer.from('%PDF-1.4\n%test content');
      const result = await scanner.scan(pdfBuffer, 'document.pdf');

      expect(result.clean).toBe(true);
    });

    it('should detect suspicious keywords', async () => {
      const suspiciousBuffer = Buffer.from('eval(atob("malicious code"))');
      const result = await scanner.scan(suspiciousBuffer, 'suspicious.js');

      expect(result.threats.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect obfuscated code', async () => {
      const obfuscatedBuffer = Buffer.from('eval(unescape("%75%6E%65%73%63%61%70%65"))');
      const result = await scanner.scan(obfuscatedBuffer, 'obfuscated.js');

      expect(result.threats.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle various file types safely', async () => {
      const results = await Promise.all([
        scanner.scan(Buffer.from('%PDF-1.4'), 'test.pdf'),
        scanner.scan(Buffer.from('<?xml version="1.0"?>'), 'test.xml'),
        scanner.scan(Buffer.from('test text'), 'test.txt'),
        scanner.scan(Buffer.from([0xFF, 0xD8, 0xFF]), 'test.jpg')
      ]);

      expect(results.every(r => r !== null)).toBe(true);
      expect(results.every(r => r.scanner === 'MockScanner')).toBe(true);
    });
  });
});
