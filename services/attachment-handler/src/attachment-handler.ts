/**
 * Attachment Handler Service
 * Main orchestrator for attachment processing
 */

import crypto from 'crypto';
import pino from 'pino';
import { ArchiveExtractor } from './archive-extractor';
import { VirusScanner, createVirusScanner } from './virus-scanner';
import { detectMimeType, validateFileSize, isInvoiceFormat } from './file-detector';
import {
  AttachmentMetadata,
  ExtractedFile,
  ExtractionResult,
  ExtractionOptions,
  ValidationResult,
  ValidationError,
  ValidationWarning
} from './types';

const logger = pino({ name: 'attachment-handler' });

export class AttachmentHandler {
  private archiveExtractor: ArchiveExtractor;
  private virusScanner: VirusScanner;

  constructor(options: Partial<ExtractionOptions> = {}) {
    this.archiveExtractor = new ArchiveExtractor(options);
    this.virusScanner = createVirusScanner();
  }

  /**
   * Process attachment buffer
   * Main entry point for attachment processing
   */
  async processAttachment(
    buffer: Buffer,
    filename: string
  ): Promise<ExtractionResult> {
    logger.info({ filename, size: buffer.length }, 'Processing attachment');

    try {
      // Step 1: Create metadata
      const metadata = await this.createMetadata(buffer, filename);

      // Step 2: Validate file
      const validation = await this.validateFile(buffer, filename, metadata);
      if (!validation.valid) {
        const fatalError = validation.errors.find(e => e.fatal);
        if (fatalError) {
          return {
            success: false,
            files: [],
            errors: validation.errors.map(e => e.message),
            metadata: {
              totalFiles: 0,
              totalSize: 0,
              archives: 0,
              invoices: 0,
              skipped: 0
            }
          };
        }
      }

      // Step 3: Virus scan
      if (metadata.virusScanResult && !metadata.virusScanResult.clean) {
        logger.warn({ filename, threats: metadata.virusScanResult.threats }, 'Virus detected');
        return {
          success: false,
          files: [],
          errors: [`Virus detected: ${metadata.virusScanResult.threats.join(', ')}`],
          metadata: {
            totalFiles: 0,
            totalSize: 0,
            archives: 0,
            invoices: 0,
            skipped: 0
          }
        };
      }

      // Step 4: Extract if archive, otherwise return single file
      let result: ExtractionResult;

      if (metadata.isArchive) {
        logger.info({ filename }, 'Extracting archive');
        result = await this.archiveExtractor.extract(buffer, filename);
      } else {
        logger.info({ filename }, 'Processing single file');
        result = {
          success: true,
          files: [
            {
              filename,
              originalPath: filename,
              content: buffer,
              mimeType: metadata.mimeType,
              size: metadata.size,
              hash: metadata.hash
            }
          ],
          errors: [],
          metadata: {
            totalFiles: 1,
            totalSize: metadata.size,
            archives: 0,
            invoices: metadata.isInvoice ? 1 : 0,
            skipped: 0
          }
        };
      }

      logger.info({
        filename,
        success: result.success,
        filesExtracted: result.files.length,
        errors: result.errors.length
      }, 'Attachment processing complete');

      return result;

    } catch (error) {
      logger.error({ error, filename }, 'Attachment processing failed');
      return {
        success: false,
        files: [],
        errors: [`Processing failed: ${error instanceof Error ? error.message : 'Unknown error'}`],
        metadata: {
          totalFiles: 0,
          totalSize: 0,
          archives: 0,
          invoices: 0,
          skipped: 0
        }
      };
    }
  }

  /**
   * Create attachment metadata
   */
  async createMetadata(buffer: Buffer, filename: string): Promise<AttachmentMetadata> {
    const mimeType = await detectMimeType(buffer, filename);
    const hash = crypto.createHash('sha256').update(buffer).digest('hex');
    const size = buffer.length;

    const isArchive = this.isArchiveType(mimeType);
    const isInvoice = isInvoiceFormat(mimeType);

    // Virus scan
    const virusScanResult = await this.virusScanner.scan(buffer, filename);

    return {
      filename,
      mimeType,
      size,
      hash,
      isArchive,
      isInvoice,
      virusScanResult
    };
  }

  /**
   * Validate file
   */
  async validateFile(
    buffer: Buffer,
    filename: string,
    metadata: AttachmentMetadata
  ): Promise<ValidationResult> {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validate file size
    const sizeValidation = validateFileSize(buffer.length);
    if (!sizeValidation.valid) {
      errors.push({
        code: 'FILE_TOO_LARGE',
        message: sizeValidation.error!,
        field: 'size',
        fatal: true
      });
    }

    // Validate filename
    if (!filename || filename.trim().length === 0) {
      errors.push({
        code: 'INVALID_FILENAME',
        message: 'Filename is required',
        field: 'filename',
        fatal: true
      });
    }

    // Check for suspicious filenames
    if (this.hasSuspiciousFilename(filename)) {
      warnings.push({
        code: 'SUSPICIOUS_FILENAME',
        message: 'Filename contains suspicious patterns',
        field: 'filename'
      });
    }

    // Validate buffer is not empty
    if (buffer.length === 0) {
      errors.push({
        code: 'EMPTY_FILE',
        message: 'File is empty',
        field: 'content',
        fatal: true
      });
    }

    // Check if file type is supported
    const supportedTypes = [
      'application/pdf',
      'application/xml',
      'text/xml',
      'application/zip',
      'image/jpeg',
      'image/png',
      'image/tiff'
    ];

    if (!supportedTypes.includes(metadata.mimeType)) {
      warnings.push({
        code: 'UNSUPPORTED_TYPE',
        message: `File type ${metadata.mimeType} may not be supported`,
        field: 'mimeType'
      });
    }

    return {
      valid: errors.filter(e => e.fatal).length === 0,
      errors,
      warnings
    };
  }

  /**
   * Check if MIME type is an archive format
   */
  private isArchiveType(mimeType: string): boolean {
    const archiveTypes = [
      'application/zip',
      'application/x-zip-compressed',
      'application/x-rar-compressed',
      'application/x-7z-compressed',
      'application/x-tar',
      'application/gzip'
    ];

    return archiveTypes.includes(mimeType);
  }

  /**
   * Check for suspicious filename patterns
   */
  private hasSuspiciousFilename(filename: string): boolean {
    const suspicious = [
      /\.exe$/i,
      /\.bat$/i,
      /\.cmd$/i,
      /\.sh$/i,
      /\.ps1$/i,
      /\.\./,  // Path traversal
      /\\/,    // Windows path separator
      /[<>:"|?*]/ // Invalid characters
    ];

    return suspicious.some(pattern => pattern.test(filename));
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Test virus scanner
      const scannerHealth = await this.virusScanner.healthCheck();

      // Test archive extractor
      const testZip = Buffer.from([0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const extractorHealth = await this.archiveExtractor.extract(testZip, 'test.zip');

      return scannerHealth && extractorHealth !== null;
    } catch (error) {
      logger.error({ error }, 'Health check failed');
      return false;
    }
  }
}
