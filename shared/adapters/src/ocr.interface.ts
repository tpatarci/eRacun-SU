/**
 * OCR Service Adapter Interface
 * Abstracts text extraction and document parsing
 */

export interface IOCRService {
  /**
   * Extract raw text from PDF
   */
  extractText(pdf: Buffer): Promise<TextExtractionResult>;

  /**
   * Extract structured data from invoice PDF
   */
  extractStructuredData(pdf: Buffer): Promise<StructuredDataResult>;

  /**
   * Extract tables from PDF
   */
  extractTables(pdf: Buffer): Promise<TableExtractionResult>;

  /**
   * Health check
   */
  healthCheck(): Promise<boolean>;
}

export interface TextExtractionResult {
  success: boolean;
  text: string;
  confidence: number;             // 0-1 score
  language?: string;
  pageCount: number;
  processingTime: number;         // milliseconds
  error?: string;
}

export interface StructuredDataResult {
  success: boolean;
  data: {
    invoiceNumber?: string;
    issueDate?: string;
    dueDate?: string;
    supplierName?: string;
    supplierOIB?: string;
    buyerName?: string;
    buyerOIB?: string;
    totalAmount?: number;
    vatAmount?: number;
    currency?: string;
    lineItems?: OCRLineItem[];
  };
  confidence: number;
  error?: string;
}

export interface OCRLineItem {
  description: string;
  quantity?: number;
  unitPrice?: number;
  totalPrice?: number;
  confidence: number;
}

export interface TableExtractionResult {
  success: boolean;
  tables: Table[];
  error?: string;
}

export interface Table {
  headers: string[];
  rows: string[][];
  confidence: number;
}
