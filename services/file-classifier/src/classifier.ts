/**
 * Classifier Module
 *
 * Determines routing destination based on file type.
 * - Classification rules (PDF → pdf-parser, XML → xml-parser, etc.)
 * - Priority assignment
 * - Processor selection logic
 */

import { DetectedFile } from './file-detector';
import { logger, filesClassifiedTotal, filesRoutedTotal } from './observability';

/**
 * Classification result
 */
export interface ClassificationResult {
  /** Target processor service */
  processor: ProcessorType;
  /** Processing priority */
  priority: Priority;
  /** File type category */
  category: FileCategory;
  /** MIME type */
  mimeType: string;
  /** File extension */
  extension: string;
  /** File size */
  size: number;
  /** Classification confidence */
  confidence: 'high' | 'medium' | 'low';
}

/**
 * Processor types
 */
export type ProcessorType =
  | 'pdf-parser'
  | 'xml-parser'
  | 'ocr-processing-service'
  | 'manual-review-queue';

/**
 * Processing priority
 */
export type Priority = 'high' | 'medium' | 'low';

/**
 * File category
 */
export type FileCategory = 'pdf-document' | 'xml-document' | 'image' | 'unknown';

/**
 * Classification rules configuration
 */
export interface ClassificationRules {
  /** PDF-related MIME types */
  pdfTypes: string[];
  /** XML-related MIME types */
  xmlTypes: string[];
  /** Image MIME types */
  imageTypes: string[];
}

/**
 * Default classification rules
 */
const DEFAULT_RULES: ClassificationRules = {
  pdfTypes: ['application/pdf'],
  xmlTypes: ['application/xml', 'text/xml'],
  imageTypes: ['image/jpeg', 'image/jpg', 'image/png', 'image/tiff'],
};

/**
 * File Classifier
 */
export class Classifier {
  private rules: ClassificationRules;

  constructor(rules: ClassificationRules = DEFAULT_RULES) {
    this.rules = rules;
  }

  /**
   * Classify file and determine routing
   *
   * @param detectedFile - Detected file information
   * @returns Classification result
   */
  classify(detectedFile: DetectedFile): ClassificationResult {
    const { mimeType, extension, size, isSupported } = detectedFile;

    logger.debug({ mimeType, extension, size, isSupported }, 'Classifying file');

    // Classify based on MIME type
    let category: FileCategory;
    let processor: ProcessorType;
    let priority: Priority;
    let confidence: 'high' | 'medium' | 'low';

    if (this.rules.pdfTypes.includes(mimeType)) {
      // PDF documents
      category = 'pdf-document';
      processor = 'pdf-parser';
      priority = 'high';
      confidence = 'high';

      logger.info({ mimeType, processor }, 'PDF document classified');
    } else if (this.rules.xmlTypes.includes(mimeType)) {
      // XML documents (likely UBL invoices)
      category = 'xml-document';
      processor = 'xml-parser';
      priority = 'high';
      confidence = 'high';

      logger.info({ mimeType, processor }, 'XML document classified');
    } else if (this.rules.imageTypes.includes(mimeType)) {
      // Images (require OCR)
      category = 'image';
      processor = 'ocr-processing-service';
      priority = 'medium';
      confidence = 'high';

      logger.info({ mimeType, processor }, 'Image file classified (requires OCR)');
    } else {
      // Unknown or unsupported file type
      category = 'unknown';
      processor = 'manual-review-queue';
      priority = 'low';
      confidence = 'low';

      logger.warn({ mimeType, isSupported }, 'Unknown file type, routing to manual review');
    }

    // Record classification metrics
    filesClassifiedTotal.inc({
      file_type: category,
      status: 'success',
    });

    filesRoutedTotal.inc({
      processor,
      status: 'pending',
    });

    const result: ClassificationResult = {
      processor,
      priority,
      category,
      mimeType,
      extension,
      size,
      confidence,
    };

    logger.info(
      {
        processor: result.processor,
        priority: result.priority,
        category: result.category,
        confidence: result.confidence,
      },
      'File classification complete'
    );

    return result;
  }

  /**
   * Get classification rules
   */
  getRules(): ClassificationRules {
    return {
      pdfTypes: [...this.rules.pdfTypes],
      xmlTypes: [...this.rules.xmlTypes],
      imageTypes: [...this.rules.imageTypes],
    };
  }

  /**
   * Update classification rules
   */
  setRules(rules: Partial<ClassificationRules>): void {
    this.rules = {
      ...this.rules,
      ...rules,
    };
    logger.info({ rules: this.rules }, 'Classification rules updated');
  }
}

/**
 * Create classifier from environment variables
 */
export function createClassifierFromEnv(): Classifier {
  const pdfTypes = process.env.PDF_MIME_TYPES
    ? process.env.PDF_MIME_TYPES.split(',').map((type) => type.trim())
    : DEFAULT_RULES.pdfTypes;

  const xmlTypes = process.env.XML_MIME_TYPES
    ? process.env.XML_MIME_TYPES.split(',').map((type) => type.trim())
    : DEFAULT_RULES.xmlTypes;

  const imageTypes = process.env.IMAGE_MIME_TYPES
    ? process.env.IMAGE_MIME_TYPES.split(',').map((type) => type.trim())
    : DEFAULT_RULES.imageTypes;

  const rules: ClassificationRules = {
    pdfTypes,
    xmlTypes,
    imageTypes,
  };

  logger.info({ rules }, 'Creating classifier');

  return new Classifier(rules);
}
