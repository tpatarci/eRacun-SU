/**
 * PDF Extractor Module
 *
 * Extracts text content from PDF documents using pdf-parse library.
 * - Text extraction from native PDFs
 * - Scanned PDF detection (image-based PDFs)
 * - Metadata extraction (page count, title, author)
 * - Error handling for corrupt/encrypted PDFs
 */

import pdfParse from 'pdf-parse';
import {
  logger,
  pdfFileSizeBytes,
  pdfPageCount,
  pdfParsingDuration,
  pdfParsingErrorsTotal,
} from './observability';

/**
 * Extracted PDF content
 */
export interface ExtractedPDF {
  /** Extracted text content */
  text: string;
  /** Number of pages */
  pageCount: number;
  /** PDF metadata */
  metadata: {
    title?: string;
    author?: string;
    subject?: string;
    creator?: string;
    producer?: string;
    creationDate?: Date;
    modificationDate?: Date;
  };
  /** Whether PDF is scanned (image-based, requires OCR) */
  isScanned: boolean;
  /** Text extraction quality */
  quality: 'high' | 'medium' | 'low';
  /** File size in bytes */
  size: number;
}

/**
 * PDF extraction configuration
 */
export interface ExtractionConfig {
  /** Maximum file size (bytes) */
  maxFileSize: number;
  /** Maximum pages to process */
  maxPages: number;
  /** Minimum text length to consider PDF as native (not scanned) */
  minTextLength: number;
}

/**
 * Default extraction configuration
 */
const DEFAULT_CONFIG: ExtractionConfig = {
  maxFileSize: 10 * 1024 * 1024, // 10 MB
  maxPages: 100,
  minTextLength: 100, // Scanned PDFs have <100 chars after OCR failures
};

/**
 * PDF Extractor
 */
export class PDFExtractor {
  private config: ExtractionConfig;

  constructor(config: Partial<ExtractionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Extract content from PDF buffer
   *
   * @param buffer - PDF file buffer
   * @param filename - Original filename (for logging)
   * @returns Extracted PDF content
   * @throws Error if PDF is corrupt, encrypted, or too large
   */
  async extractPDF(buffer: Buffer, filename?: string): Promise<ExtractedPDF> {
    const endTimer = pdfParsingDuration.startTimer({ operation: 'extract' });

    try {
      logger.info({ filename, size: buffer.length }, 'Extracting PDF content');

      // Validate file size
      if (buffer.length > this.config.maxFileSize) {
        pdfParsingErrorsTotal.inc({ error_type: 'size_exceeded' });
        throw new Error(
          `PDF file size ${buffer.length} exceeds maximum ${this.config.maxFileSize}`
        );
      }

      if (buffer.length === 0) {
        pdfParsingErrorsTotal.inc({ error_type: 'empty_file' });
        throw new Error('PDF file is empty');
      }

      // Record file size metric
      pdfFileSizeBytes.observe(buffer.length);

      // Parse PDF
      const data = await pdfParse(buffer, {
        max: this.config.maxPages,
      });

      // Record page count metric
      pdfPageCount.observe(data.numpages);

      // Extract metadata
      const metadata = this.extractMetadata(data.info);

      // Detect if PDF is scanned
      const isScanned = this.detectScannedPDF(data.text, data.numpages);

      // Determine extraction quality
      const quality = this.assessQuality(data.text, data.numpages, isScanned);

      logger.info(
        {
          filename,
          pageCount: data.numpages,
          textLength: data.text.length,
          isScanned,
          quality,
        },
        'PDF extraction complete'
      );

      return {
        text: data.text,
        pageCount: data.numpages,
        metadata,
        isScanned,
        quality,
        size: buffer.length,
      };
    } catch (error) {
      logger.error({ error, filename }, 'PDF extraction failed');

      // Categorize error
      if (error instanceof Error) {
        if (error.message.includes('password')) {
          pdfParsingErrorsTotal.inc({ error_type: 'encrypted' });
          throw new Error('PDF is password-protected and cannot be parsed');
        } else if (error.message.includes('Invalid PDF')) {
          pdfParsingErrorsTotal.inc({ error_type: 'corrupt' });
          throw new Error('PDF file is corrupt or invalid');
        } else if (error.message.includes('size')) {
          // Already handled above
          throw error;
        }
      }

      pdfParsingErrorsTotal.inc({ error_type: 'unknown' });
      throw new Error(`PDF extraction failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      endTimer();
    }
  }

  /**
   * Extract PDF metadata
   */
  private extractMetadata(info: any): ExtractedPDF['metadata'] {
    return {
      title: info.Title || undefined,
      author: info.Author || undefined,
      subject: info.Subject || undefined,
      creator: info.Creator || undefined,
      producer: info.Producer || undefined,
      creationDate: info.CreationDate ? this.parsePDFDate(info.CreationDate) : undefined,
      modificationDate: info.ModDate ? this.parsePDFDate(info.ModDate) : undefined,
    };
  }

  /**
   * Parse PDF date string (format: D:YYYYMMDDHHmmSSOHH'mm')
   */
  private parsePDFDate(dateString: string): Date | undefined {
    try {
      // Remove D: prefix if present
      const cleaned = dateString.replace(/^D:/, '');

      // Extract date components
      const year = parseInt(cleaned.substring(0, 4), 10);
      const month = parseInt(cleaned.substring(4, 6), 10) - 1; // 0-indexed
      const day = parseInt(cleaned.substring(6, 8), 10);
      const hour = parseInt(cleaned.substring(8, 10), 10) || 0;
      const minute = parseInt(cleaned.substring(10, 12), 10) || 0;
      const second = parseInt(cleaned.substring(12, 14), 10) || 0;

      return new Date(year, month, day, hour, minute, second);
    } catch {
      return undefined;
    }
  }

  /**
   * Detect if PDF is scanned (image-based)
   *
   * Heuristic: If text length is very low relative to page count,
   * PDF is likely scanned and requires OCR
   */
  private detectScannedPDF(text: string, pageCount: number): boolean {
    const textLength = text.trim().length;
    const avgTextPerPage = textLength / pageCount;

    // If average text per page < minTextLength, consider it scanned
    if (avgTextPerPage < this.config.minTextLength) {
      logger.info(
        { textLength, pageCount, avgTextPerPage },
        'Detected scanned PDF (low text content)'
      );
      return true;
    }

    // Check for high ratio of whitespace/garbage characters
    const meaningfulChars = text.replace(/[\s\n\r\t]/g, '').length;
    const meaningfulRatio = meaningfulChars / textLength;

    if (meaningfulRatio < 0.3) {
      logger.info({ meaningfulRatio }, 'Detected scanned PDF (low meaningful text ratio)');
      return true;
    }

    return false;
  }

  /**
   * Assess extraction quality
   */
  private assessQuality(
    text: string,
    pageCount: number,
    isScanned: boolean
  ): 'high' | 'medium' | 'low' {
    if (isScanned) {
      return 'low'; // Scanned PDFs need OCR
    }

    const textLength = text.trim().length;
    const avgTextPerPage = textLength / pageCount;

    // High quality: >500 chars/page, good structure
    if (avgTextPerPage > 500 && text.includes('\n')) {
      return 'high';
    }

    // Medium quality: 200-500 chars/page
    if (avgTextPerPage > 200) {
      return 'medium';
    }

    // Low quality: <200 chars/page
    return 'low';
  }

  /**
   * Get extraction configuration
   */
  getConfig(): ExtractionConfig {
    return { ...this.config };
  }

  /**
   * Update extraction configuration
   */
  setConfig(config: Partial<ExtractionConfig>): void {
    this.config = { ...this.config, ...config };
    logger.info({ config: this.config }, 'Extraction configuration updated');
  }
}

/**
 * Create PDF extractor from environment variables
 */
export function createPDFExtractorFromEnv(): PDFExtractor {
  const config: Partial<ExtractionConfig> = {};

  if (process.env.PDF_MAX_FILE_SIZE) {
    config.maxFileSize = parseInt(process.env.PDF_MAX_FILE_SIZE, 10);
  }

  if (process.env.PDF_MAX_PAGES) {
    config.maxPages = parseInt(process.env.PDF_MAX_PAGES, 10);
  }

  if (process.env.PDF_MIN_TEXT_LENGTH) {
    config.minTextLength = parseInt(process.env.PDF_MIN_TEXT_LENGTH, 10);
  }

  logger.info({ config }, 'Creating PDF extractor');

  return new PDFExtractor(config);
}
