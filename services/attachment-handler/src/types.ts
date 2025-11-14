/**
 * Types for Attachment Handler Service
 */

export interface AttachmentMetadata {
  filename: string;
  mimeType: string;
  size: number;
  hash: string;
  isArchive: boolean;
  isInvoice: boolean;
  virusScanResult?: VirusScanResult;
}

export interface ExtractedFile {
  filename: string;
  originalPath: string;
  content: Buffer;
  mimeType: string;
  size: number;
  hash: string;
  extractedFrom?: string;
}

export interface ExtractionResult {
  success: boolean;
  files: ExtractedFile[];
  errors: string[];
  metadata: {
    totalFiles: number;
    totalSize: number;
    archives: number;
    invoices: number;
    skipped: number;
  };
}

export interface VirusScanResult {
  clean: boolean;
  threats: string[];
  scanner: string;
  timestamp: Date;
}

export interface ExtractionOptions {
  maxFileSize?: number;
  maxTotalSize?: number;
  maxFiles?: number;
  maxNestingLevel?: number;
  allowedTypes?: string[];
  enableVirusScan?: boolean;
  password?: string;
}

export const DEFAULT_EXTRACTION_OPTIONS: ExtractionOptions = {
  maxFileSize: 10 * 1024 * 1024, // 10MB per file
  maxTotalSize: 50 * 1024 * 1024, // 50MB total
  maxFiles: 100,
  maxNestingLevel: 3,
  allowedTypes: [
    'application/pdf',
    'application/xml',
    'text/xml',
    'application/zip',
    'image/jpeg',
    'image/png',
    'image/tiff'
  ],
  enableVirusScan: true,
  password: undefined
};

export enum ArchiveFormat {
  ZIP = 'zip',
  RAR = 'rar',
  SEVEN_ZIP = '7z',
  TAR = 'tar',
  GZIP = 'gz'
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

export interface ValidationError {
  code: string;
  message: string;
  field?: string;
  fatal: boolean;
}

export interface ValidationWarning {
  code: string;
  message: string;
  field?: string;
}
