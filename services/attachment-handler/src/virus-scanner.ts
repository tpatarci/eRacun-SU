/**
 * Virus Scanner
 * Mock implementation for development, production should use ClamAV or similar
 */

import crypto from 'crypto';
import pino from 'pino';
import { VirusScanResult } from './types';

const logger = pino({ name: 'virus-scanner' });

/**
 * Known virus signatures (simplified for mock)
 */
const VIRUS_SIGNATURES = [
  'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR', // EICAR test file
  'VIRUS_SIGNATURE_MOCK'
];

export class VirusScanner {
  private scannerName: string;
  private enabled: boolean;

  constructor(scannerName = 'MockVirusScanner', enabled = true) {
    this.scannerName = scannerName;
    this.enabled = enabled;
  }

  /**
   * Scan buffer for viruses
   */
  async scan(buffer: Buffer, filename: string): Promise<VirusScanResult> {
    if (!this.enabled) {
      logger.debug({ filename }, 'Virus scanning disabled, skipping');
      return {
        clean: true,
        threats: [],
        scanner: this.scannerName,
        timestamp: new Date()
      };
    }

    logger.debug({ filename, size: buffer.length }, 'Starting virus scan');

    // Simulate scan delay (realistic behavior)
    const scanTime = Math.min(50 + buffer.length / 100000, 1000);
    await this.delay(scanTime);

    // Check for known virus signatures
    const threats = this.detectThreats(buffer);

    // Random chance of false positive (1% in mock)
    if (Math.random() < 0.01 && threats.length === 0) {
      threats.push('Heuristic.SuspiciousPattern.Mock');
    }

    const result: VirusScanResult = {
      clean: threats.length === 0,
      threats,
      scanner: this.scannerName,
      timestamp: new Date()
    };

    if (!result.clean) {
      logger.warn({ filename, threats }, 'Virus detected!');
    } else {
      logger.debug({ filename }, 'File is clean');
    }

    return result;
  }

  /**
   * Scan multiple files in batch
   */
  async scanBatch(files: Array<{ buffer: Buffer; filename: string }>): Promise<VirusScanResult[]> {
    logger.info({ count: files.length }, 'Starting batch virus scan');

    const results: VirusScanResult[] = [];

    for (const file of files) {
      const result = await this.scan(file.buffer, file.filename);
      results.push(result);
    }

    const infected = results.filter(r => !r.clean).length;
    logger.info({ total: files.length, infected }, 'Batch scan complete');

    return results;
  }

  /**
   * Check if scanner is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Test with EICAR file
      const eicar = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
      const result = await this.scan(eicar, 'eicar.test');

      // Scanner should detect EICAR
      return !result.clean && result.threats.length > 0;
    } catch (error) {
      logger.error({ error }, 'Health check failed');
      return false;
    }
  }

  /**
   * Detect known virus signatures in buffer
   */
  private detectThreats(buffer: Buffer): string[] {
    const threats: string[] = [];
    const content = buffer.toString('utf8', 0, Math.min(buffer.length, 10000));

    for (const signature of VIRUS_SIGNATURES) {
      if (content.includes(signature)) {
        threats.push(`VirusSignature.${this.hashSignature(signature)}`);
      }
    }

    // Check for suspicious patterns (mock heuristics)
    if (this.hasSuspiciousPatterns(buffer)) {
      threats.push('Heuristic.SuspiciousExecutable');
    }

    return threats;
  }

  /**
   * Check for suspicious patterns (simplified heuristics)
   */
  private hasSuspiciousPatterns(buffer: Buffer): boolean {
    // Check for executable signatures (PE, ELF, Mach-O)
    if (buffer.length < 4) {
      return false;
    }

    // PE executable: MZ
    if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
      return true;
    }

    // ELF executable
    if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
      return true;
    }

    // Mach-O executable
    if (buffer[0] === 0xFE && buffer[1] === 0xED && buffer[2] === 0xFA) {
      return true;
    }

    return false;
  }

  /**
   * Hash signature for identification
   */
  private hashSignature(signature: string): string {
    return crypto.createHash('md5').update(signature).digest('hex').substring(0, 8);
  }

  /**
   * Simulate processing delay
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Create virus scanner instance based on environment
 */
export function createVirusScanner(): VirusScanner {
  const env = process.env.NODE_ENV || 'development';
  const enabled = process.env.ENABLE_VIRUS_SCAN !== 'false';

  if (env === 'production') {
    // In production, use real ClamAV or similar
    logger.info('Creating production virus scanner (ClamAV)');
    // return new ClamAVScanner();
  }

  logger.info({ env, enabled }, 'Creating mock virus scanner');
  return new VirusScanner('MockVirusScanner', enabled);
}
