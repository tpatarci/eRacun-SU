/**
 * OCR Types for Mock OCR Engine
 * Provides realistic OCR output structures for testing
 */

export enum Language {
  CROATIAN = 'hr',
  ENGLISH = 'en',
  GERMAN = 'de',
  ITALIAN = 'it',
  SLOVENIAN = 'sl'
}

export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface TextBlock {
  text: string;
  boundingBox: BoundingBox;
  confidence: number;
  language?: Language;
}

export interface TableCell {
  text: string;
  row: number;
  column: number;
  confidence: number;
}

export interface TableResult {
  headers: string[];
  rows: string[][];
  confidence: number;
  boundingBox?: BoundingBox;
}

export interface TextResult {
  text: string;
  confidence: number;
  language: Language;
  blocks: TextBlock[];
  processingTime: number;
  metadata?: {
    pageCount: number;
    resolution: string;
    colorSpace: string;
  };
}

export interface OCROptions {
  language?: Language;
  deskew?: boolean;
  denoise?: boolean;
  detectTables?: boolean;
  detectBarcodes?: boolean;
}

export interface OCRScenario {
  name: string;
  text: string;
  confidence: number;
  language: Language;
  oibConfidence?: number;
  hasTable?: boolean;
  hasBarcode?: boolean;
}
