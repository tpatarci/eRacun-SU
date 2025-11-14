/**
 * Type Definitions for OCR Processing Service
 */

export interface OCRRequest {
  fileId: string;
  filename: string;
  content: string; // base64 encoded image
  mimeType: string;
  metadata: {
    sourceService: string;
    timestamp: string;
    originalFilename?: string;
  };
}

export interface OCRResponse {
  fileId: string;
  success: boolean;
  extractedText?: string;
  confidence?: number;
  language?: string;
  blocks?: TextBlock[];
  tables?: Table[];
  processingTime: number;
  errors: string[];
}

export interface TextBlock {
  text: string;
  confidence: number;
  boundingBox?: BoundingBox;
  type: 'paragraph' | 'line' | 'word';
}

export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface Table {
  rows: TableRow[];
  confidence: number;
  boundingBox?: BoundingBox;
}

export interface TableRow {
  cells: TableCell[];
}

export interface TableCell {
  text: string;
  confidence: number;
  rowSpan?: number;
  colSpan?: number;
}

export interface OCRProcessorOptions {
  minConfidence?: number;
  enableTableExtraction?: boolean;
  enableLanguageDetection?: boolean;
  preprocessImages?: boolean;
  maxImageSize?: number;
}

export interface ImagePreprocessingResult {
  buffer: Buffer;
  width: number;
  height: number;
  format: string;
  preprocessingApplied: string[];
}
