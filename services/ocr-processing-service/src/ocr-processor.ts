/**
 * OCR Processor
 * Orchestrates OCR processing using the OCR engine
 */

import pino from 'pino';
import { MockOCREngine, Language } from '@eracun/team2-mocks';
import { ImagePreprocessor } from './image-preprocessor';
import { OCRRequest, OCRResponse, OCRProcessorOptions, TextBlock, Table } from './types';

const logger = pino({ name: 'ocr-processor' });

export class OCRProcessor {
  private readonly ocrEngine: MockOCREngine;
  private readonly preprocessor: ImagePreprocessor;
  private readonly options: OCRProcessorOptions;

  constructor(options: OCRProcessorOptions = {}) {
    this.options = {
      minConfidence: options.minConfidence || 0.7,
      enableTableExtraction: options.enableTableExtraction ?? true,
      enableLanguageDetection: options.enableLanguageDetection ?? true,
      preprocessImages: options.preprocessImages ?? true,
      maxImageSize: options.maxImageSize || 20 * 1024 * 1024
    };

    this.ocrEngine = new MockOCREngine();
    this.preprocessor = new ImagePreprocessor();
  }

  /**
   * Process OCR request
   */
  async processRequest(request: OCRRequest): Promise<OCRResponse> {
    const startTime = Date.now();
    const errors: string[] = [];

    logger.info(
      { fileId: request.fileId, filename: request.filename, mimeType: request.mimeType },
      'Processing OCR request'
    );

    try {
      // Decode base64 content
      const imageBuffer = Buffer.from(request.content, 'base64');

      // Validate image
      const validation = await this.preprocessor.validate(imageBuffer);
      if (!validation.valid) {
        return {
          fileId: request.fileId,
          success: false,
          processingTime: Date.now() - startTime,
          errors: validation.errors
        };
      }

      // Preprocess image if enabled
      let processedBuffer = imageBuffer;
      if (this.options.preprocessImages) {
        try {
          const preprocessed = await this.preprocessor.preprocess(imageBuffer);
          processedBuffer = preprocessed.buffer as any;
          logger.debug(
            { preprocessing: preprocessed.preprocessingApplied },
            'Image preprocessing complete'
          );
        } catch (error) {
          logger.warn({ error }, 'Image preprocessing failed, using original');
          errors.push(`Preprocessing warning: ${error}`);
        }
      }

      // Extract text using OCR engine
      const textResult = await this.ocrEngine.extractText(processedBuffer, {
        language: this.options.enableLanguageDetection ? undefined : Language.CROATIAN
      });

      // Check confidence threshold
      const minConf = this.options.minConfidence || 0.7;
      if (textResult.confidence < minConf) {
        errors.push(
          `OCR confidence ${textResult.confidence} below threshold ${minConf}`
        );
      }

      // Convert text blocks
      const blocks: TextBlock[] = textResult.blocks.map(block => ({
        text: block.text,
        confidence: block.confidence,
        boundingBox: block.boundingBox,
        type: this.determineBlockType(block.text)
      }));

      // Extract tables if enabled
      let tables: Table[] = [];
      if (this.options.enableTableExtraction) {
        try {
          const tableResults = await this.ocrEngine.extractTables(processedBuffer);
          tables = tableResults.map(table => ({
            rows: table.rows.map(row => ({
              cells: row.map(cellText => ({
                text: cellText,
                confidence: table.confidence // Use table-level confidence for cells
              }))
            })),
            confidence: table.confidence,
            boundingBox: table.boundingBox
          }));
        } catch (error) {
          logger.warn({ error }, 'Table extraction failed');
          errors.push(`Table extraction warning: ${error}`);
        }
      }

      const processingTime = Date.now() - startTime;

      logger.info(
        {
          fileId: request.fileId,
          confidence: textResult.confidence,
          textLength: textResult.text.length,
          blockCount: blocks.length,
          tableCount: tables.length,
          processingTime
        },
        'OCR processing complete'
      );

      return {
        fileId: request.fileId,
        success: true,
        extractedText: textResult.text,
        confidence: textResult.confidence,
        language: textResult.language,
        blocks,
        tables: tables.length > 0 ? tables : undefined,
        processingTime,
        errors
      };
    } catch (error) {
      logger.error({ error, fileId: request.fileId }, 'OCR processing failed');
      return {
        fileId: request.fileId,
        success: false,
        processingTime: Date.now() - startTime,
        errors: [`OCR processing failed: ${error}`]
      };
    }
  }

  /**
   * Batch process multiple requests
   */
  async processBatch(requests: OCRRequest[]): Promise<OCRResponse[]> {
    logger.info({ count: requests.length }, 'Processing OCR batch');

    const results = await Promise.all(
      requests.map(request => this.processRequest(request))
    );

    const successCount = results.filter(r => r.success).length;
    logger.info(
      { total: requests.length, successful: successCount, failed: requests.length - successCount },
      'Batch processing complete'
    );

    return results;
  }

  /**
   * Determine block type based on content
   */
  private determineBlockType(text: string): 'paragraph' | 'line' | 'word' {
    if (text.includes('\n') || text.length > 100) {
      return 'paragraph';
    }
    if (text.includes(' ') && text.length > 20) {
      return 'line';
    }
    return 'word';
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Test with minimal image
      const testBuffer = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
        'base64'
      );

      const result = await this.ocrEngine.extractText(testBuffer);
      return result.confidence > 0;
    } catch (error) {
      logger.error({ error }, 'Health check failed');
      return false;
    }
  }
}
