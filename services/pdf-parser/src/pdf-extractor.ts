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
 *
 * IMPROVEMENT-039: Add quality metrics for observability
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
  /** Scanned detection confidence (0-1, higher = more confident it's scanned) */
  scannedConfidence: number;
  /** Text extraction quality */
  quality: 'high' | 'medium' | 'low';
  /** Diagnostic metrics */
  metrics: {
    /** Total text length extracted */
    textLength: number;
    /** Average text per page */
    avgTextPerPage: number;
    /** Ratio of meaningful characters to whitespace */
    meaningfulCharRatio: number;
  };
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
  private readonly parsePdf: typeof pdfParse;
  // IMPROVEMENT-034: Pre-compiled regex for whitespace/garbage detection
  private readonly whitespaceRegex = /[\s\n\r\t]/g;

  constructor(config: Partial<ExtractionConfig> = {}, parseFn: typeof pdfParse = pdfParse) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.parsePdf = parseFn;
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
      const data = await this.parsePdf(buffer, {
        max: this.config.maxPages,
      });

      // Record page count metric
      pdfPageCount.observe(data.numpages);

      // Extract metadata
      const metadata = this.extractMetadata(data.info);

      // Detect if PDF is scanned with confidence score
      const { isScanned, confidence: scannedConfidence, metrics } = this.detectScannedPDFWithMetrics(data.text, data.numpages);

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
        scannedConfidence,
        quality,
        metrics,
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
   *
   * IMPROVEMENT-036: Handle more date formats and log failures instead of silent failures
   */
  private parsePDFDate(dateString: string): Date | undefined {
    if (!dateString || typeof dateString !== 'string') {
      return undefined;
    }

    try {
      // Remove D: prefix if present
      const cleaned = dateString.replace(/^D:/, '').trim();

      // Minimum length for YYYYMMDD
      if (cleaned.length < 8) {
        logger.warn({ dateString }, 'PDF date string too short');
        return undefined;
      }

      // Extract date components
      const year = parseInt(cleaned.substring(0, 4), 10);
      const month = parseInt(cleaned.substring(4, 6), 10) - 1; // 0-indexed
      const day = parseInt(cleaned.substring(6, 8), 10);
      const hour = cleaned.length >= 10 ? parseInt(cleaned.substring(8, 10), 10) : 0;
      const minute = cleaned.length >= 12 ? parseInt(cleaned.substring(10, 12), 10) : 0;
      const second = cleaned.length >= 14 ? parseInt(cleaned.substring(12, 14), 10) : 0;

      // Validate ranges
      if (year < 1900 || year > 2100) {
        logger.warn({ dateString, year }, 'Invalid PDF date year out of range');
        return undefined;
      }
      if (month < 0 || month > 11) {
        logger.warn({ dateString, month: month + 1 }, 'Invalid PDF date month');
        return undefined;
      }
      if (day < 1 || day > 31) {
        logger.warn({ dateString, day }, 'Invalid PDF date day');
        return undefined;
      }

      const parsedDate = new Date(year, month, day, hour, minute, second);

      // Verify the date was created successfully
      if (isNaN(parsedDate.getTime())) {
        logger.warn({ dateString }, 'PDF date parsing resulted in invalid date');
        return undefined;
      }

      return parsedDate;
    } catch (error) {
      logger.warn({ dateString, error: error instanceof Error ? error.message : 'Unknown error' }, 'Failed to parse PDF date');
      return undefined;
    }
  }

  /**
   * Detect if PDF is scanned (image-based) with confidence score
   *
   * IMPROVEMENT-033: Optimize string operations
   * IMPROVEMENT-034: Pre-compiled regex for whitespace detection
   * IMPROVEMENT-035: Return confidence score for heuristic-based detection
   *
   * Heuristic: If text length is very low relative to page count,
   * PDF is likely scanned and requires OCR
   *
   * @returns Object with isScanned boolean, confidence (0-1), and diagnostic metrics
   */
  private detectScannedPDFWithMetrics(
    text: string,
    pageCount: number
  ): {
    isScanned: boolean;
    confidence: number;
    metrics: {
      textLength: number;
      avgTextPerPage: number;
      meaningfulCharRatio: number;
    };
  } {
    // Trim text once to avoid multiple trim calls
    const trimmedText = text.trim();
    const textLength = trimmedText.length;
    const avgTextPerPage = textLength / pageCount;

    // Check for high ratio of whitespace/garbage characters
    // IMPROVEMENT-033 & IMPROVEMENT-034: Use pre-compiled regex and avoid intermediate string allocation
    const meaningfulChars = trimmedText.replace(this.whitespaceRegex, '').length;
    const meaningfulRatio = textLength > 0 ? meaningfulChars / textLength : 0;

    // Calculate confidence score based on multiple heuristics
    let confidence = 0;

    // Heuristic 1: Low text per page (high confidence it's scanned)
    if (avgTextPerPage < this.config.minTextLength) {
      confidence += 0.6;
      logger.info(
        { textLength, pageCount, avgTextPerPage },
        'Scanned PDF indicator: low text content'
      );
    }

    // Heuristic 2: High whitespace ratio (high confidence it's scanned)
    if (meaningfulRatio < 0.3) {
      confidence += 0.4;
      logger.info({ meaningfulRatio }, 'Scanned PDF indicator: low meaningful text ratio');
    }

    // Determine if PDF should be considered scanned (confidence threshold: >0.5)
    const isScanned = confidence > 0.5;

    // Log metrics for diagnosis
    if (isScanned) {
      logger.info(
        { confidence, avgTextPerPage, meaningfulRatio },
        'PDF classified as scanned (image-based)'
      );
    }

    return {
      isScanned,
      confidence: Math.min(confidence, 1.0), // Cap at 1.0
      metrics: {
        textLength,
        avgTextPerPage: Number(avgTextPerPage.toFixed(2)),
        meaningfulCharRatio: Number(meaningfulRatio.toFixed(3)),
      },
    };
  }

  /**
   * Detect if PDF is scanned (image-based) - Legacy method for backward compatibility
   */
  public detectScannedPDF(text: string, pageCount: number): boolean {
    const { isScanned } = this.detectScannedPDFWithMetrics(text, pageCount);
    return isScanned;
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
export function createPDFExtractorFromEnv(parseFn: typeof pdfParse = pdfParse): PDFExtractor {
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

  return new PDFExtractor(config, parseFn);
}
