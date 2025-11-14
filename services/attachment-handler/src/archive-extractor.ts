/**
 * Archive Extractor
 * Handles extraction of ZIP and other archive formats
 */

import AdmZip from 'adm-zip';
import crypto from 'crypto';
import pino from 'pino';
import {
  ExtractionResult,
  ExtractedFile,
  ExtractionOptions,
  DEFAULT_EXTRACTION_OPTIONS,
  ArchiveFormat
} from './types';
import { detectMimeType } from './file-detector';

const logger = pino({ name: 'archive-extractor' });

export class ArchiveExtractor {
  private options: ExtractionOptions;

  constructor(options: Partial<ExtractionOptions> = {}) {
    this.options = { ...DEFAULT_EXTRACTION_OPTIONS, ...options };
  }

  /**
   * Extract files from archive buffer
   */
  async extract(
    buffer: Buffer,
    filename: string,
    nestingLevel = 0
  ): Promise<ExtractionResult> {
    const result: ExtractionResult = {
      success: false,
      files: [],
      errors: [],
      metadata: {
        totalFiles: 0,
        totalSize: 0,
        archives: 0,
        invoices: 0,
        skipped: 0
      }
    };

    try {
      // Check nesting level
      if (nestingLevel > (this.options.maxNestingLevel || 3)) {
        result.errors.push(`Maximum nesting level exceeded: ${nestingLevel}`);
        return result;
      }

      // Detect archive format
      const format = this.detectArchiveFormat(buffer, filename);
      if (!format) {
        result.errors.push(`Unsupported archive format: ${filename}`);
        return result;
      }

      logger.info({ filename, format, nestingLevel }, 'Extracting archive');

      // Extract based on format
      switch (format) {
        case ArchiveFormat.ZIP:
          await this.extractZip(buffer, filename, nestingLevel, result);
          break;
        case ArchiveFormat.RAR:
        case ArchiveFormat.SEVEN_ZIP:
          result.errors.push(`Format ${format} not yet implemented`);
          break;
        default:
          result.errors.push(`Unsupported format: ${format}`);
      }

      result.success = result.files.length > 0 && result.errors.length === 0;

      logger.info({
        filename,
        filesExtracted: result.files.length,
        totalSize: result.metadata.totalSize,
        errors: result.errors.length
      }, 'Archive extraction complete');

      return result;

    } catch (error) {
      logger.error({ error, filename }, 'Archive extraction failed');
      result.errors.push(`Extraction error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return result;
    }
  }

  /**
   * Extract ZIP archive
   */
  private async extractZip(
    buffer: Buffer,
    archiveName: string,
    nestingLevel: number,
    result: ExtractionResult
  ): Promise<void> {
    try {
      const zip = new AdmZip(buffer);
      const entries = zip.getEntries();

      logger.info({ archiveName, entries: entries.length }, 'Processing ZIP entries');

      for (const entry of entries) {
        // Skip directories
        if (entry.isDirectory) {
          continue;
        }

        // Check file count limit
        if (result.files.length >= (this.options.maxFiles || 100)) {
          result.errors.push('Maximum file count reached');
          result.metadata.skipped++;
          break;
        }

        try {
          // Extract entry
          const content = entry.getData();
          const size = content.length;

          // Check file size limit
          if (size > (this.options.maxFileSize || 10 * 1024 * 1024)) {
            logger.warn({ filename: entry.entryName, size }, 'File exceeds size limit, skipping');
            result.metadata.skipped++;
            continue;
          }

          // Check total size limit
          if (result.metadata.totalSize + size > (this.options.maxTotalSize || 50 * 1024 * 1024)) {
            result.errors.push('Maximum total size reached');
            result.metadata.skipped++;
            break;
          }

          // Detect MIME type
          const mimeType = await detectMimeType(content, entry.entryName);

          // Check if allowed type
          if (this.options.allowedTypes && this.options.allowedTypes.length > 0) {
            if (!this.options.allowedTypes.includes(mimeType)) {
              logger.debug({ filename: entry.entryName, mimeType }, 'File type not allowed, skipping');
              result.metadata.skipped++;
              continue;
            }
          }

          // Calculate hash
          const hash = crypto.createHash('sha256').update(content).digest('hex');

          // Check if nested archive
          const isArchive = this.isArchiveFormat(mimeType, entry.entryName);

          if (isArchive && nestingLevel < (this.options.maxNestingLevel || 3)) {
            // Recursively extract nested archive
            logger.info({ filename: entry.entryName, nestingLevel: nestingLevel + 1 }, 'Extracting nested archive');
            const nestedResult = await this.extract(content, entry.entryName, nestingLevel + 1);

            // Add nested files
            result.files.push(...nestedResult.files);
            result.errors.push(...nestedResult.errors);
            result.metadata.archives++;
            result.metadata.totalSize += size;
          } else {
            // Add file to results
            const extractedFile: ExtractedFile = {
              filename: entry.entryName,
              originalPath: entry.entryName,
              content,
              mimeType,
              size,
              hash,
              extractedFrom: archiveName
            };

            result.files.push(extractedFile);
            result.metadata.totalFiles++;
            result.metadata.totalSize += size;

            // Track invoice files
            if (this.isInvoiceFile(mimeType, entry.entryName)) {
              result.metadata.invoices++;
            }

            logger.debug({
              filename: entry.entryName,
              size,
              mimeType,
              hash
            }, 'File extracted successfully');
          }

        } catch (error) {
          logger.error({ error, filename: entry.entryName }, 'Failed to extract entry');
          result.errors.push(`Failed to extract ${entry.entryName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

    } catch (error) {
      throw new Error(`ZIP extraction failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Detect archive format from buffer and filename
   */
  private detectArchiveFormat(buffer: Buffer, filename: string): ArchiveFormat | null {
    // Check magic bytes
    if (buffer.length < 4) {
      return null;
    }

    // ZIP: 50 4B 03 04 or 50 4B 05 06
    if ((buffer[0] === 0x50 && buffer[1] === 0x4B) &&
        (buffer[2] === 0x03 || buffer[2] === 0x05)) {
      return ArchiveFormat.ZIP;
    }

    // RAR: 52 61 72 21 1A 07
    if (buffer[0] === 0x52 && buffer[1] === 0x61 && buffer[2] === 0x72 && buffer[3] === 0x21) {
      return ArchiveFormat.RAR;
    }

    // 7-Zip: 37 7A BC AF 27 1C
    if (buffer[0] === 0x37 && buffer[1] === 0x7A && buffer[2] === 0xBC && buffer[3] === 0xAF) {
      return ArchiveFormat.SEVEN_ZIP;
    }

    // GZIP: 1F 8B
    if (buffer[0] === 0x1F && buffer[1] === 0x8B) {
      return ArchiveFormat.GZIP;
    }

    // Fallback to filename extension
    const ext = filename.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'zip':
        return ArchiveFormat.ZIP;
      case 'rar':
        return ArchiveFormat.RAR;
      case '7z':
        return ArchiveFormat.SEVEN_ZIP;
      case 'tar':
        return ArchiveFormat.TAR;
      case 'gz':
        return ArchiveFormat.GZIP;
      default:
        return null;
    }
  }

  /**
   * Check if file is an archive format
   */
  private isArchiveFormat(mimeType: string, filename: string): boolean {
    const archiveMimes = [
      'application/zip',
      'application/x-zip-compressed',
      'application/x-rar-compressed',
      'application/x-7z-compressed',
      'application/x-tar',
      'application/gzip'
    ];

    if (archiveMimes.includes(mimeType)) {
      return true;
    }

    const ext = filename.split('.').pop()?.toLowerCase();
    return ['zip', 'rar', '7z', 'tar', 'gz'].includes(ext || '');
  }

  /**
   * Check if file is an invoice
   */
  private isInvoiceFile(mimeType: string, filename: string): boolean {
    // Invoice files are typically PDF or XML
    const invoiceMimes = [
      'application/pdf',
      'application/xml',
      'text/xml'
    ];

    if (!invoiceMimes.includes(mimeType)) {
      return false;
    }

    // Check filename for invoice keywords
    const lowerFilename = filename.toLowerCase();
    const invoiceKeywords = ['invoice', 'račun', 'faktura', 'racun'];

    return invoiceKeywords.some(keyword => lowerFilename.includes(keyword));
  }
}
