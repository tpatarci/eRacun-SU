/**
 * Attachment Handler Service
 * Extract and process email/archive attachments
 */

export { AttachmentHandler } from './attachment-handler';
export { ArchiveExtractor } from './archive-extractor';
export { VirusScanner, createVirusScanner } from './virus-scanner';
export {
  detectMimeType,
  validateFileSignature,
  isInvoiceFormat,
  requiresOCR,
  getExtensionFromMime,
  validateFileSize
} from './file-detector';

export {
  AttachmentMetadata,
  ExtractedFile,
  ExtractionResult,
  VirusScanResult,
  ExtractionOptions,
  DEFAULT_EXTRACTION_OPTIONS,
  ArchiveFormat,
  ValidationResult,
  ValidationError,
  ValidationWarning
} from './types';
