/**
 * Adapter Interfaces for Team 2 Services
 * Defines contracts for OCR, AI, and Email engines
 */

import {
  TextResult,
  TableResult,
  Language,
  OCROptions
} from '../types/ocr-types';

import {
  StructuredInvoice,
  AnomalyResult,
  SemanticValidation,
  RiskScore,
  Correction,
  ValidationError
} from '../types/ai-types';

import {
  EmailMessage,
  Attachment,
  FetchOptions
} from '../types/email-types';

/**
 * OCR Engine Interface
 * Abstracts OCR functionality for testing with mocks or production engines
 */
export interface IOCREngine {
  /**
   * Extract text from image buffer
   */
  extractText(image: Buffer, options?: OCROptions): Promise<TextResult>;

  /**
   * Extract tables from image buffer
   */
  extractTables(image: Buffer): Promise<TableResult[]>;

  /**
   * Detect language from image buffer
   */
  detectLanguage(image: Buffer): Promise<Language>;

  /**
   * Get overall confidence score
   */
  getConfidence(): Promise<number>;

  /**
   * Extract barcodes from image
   */
  extractBarcodes?(image: Buffer): Promise<string[]>;
}

/**
 * AI Validation Engine Interface
 * Abstracts AI validation functionality for testing with mocks or production models
 */
export interface IAIValidationEngine {
  /**
   * Detect anomalies in structured invoice data
   */
  detectAnomalies(invoice: StructuredInvoice): Promise<AnomalyResult[]>;

  /**
   * Validate semantic rules and business logic
   */
  validateSemantics(invoice: StructuredInvoice): Promise<SemanticValidation>;

  /**
   * Suggest corrections for validation errors
   */
  suggestCorrections(errors: ValidationError[]): Promise<Correction[]>;

  /**
   * Calculate risk score for invoice
   */
  calculateRiskScore(invoice: StructuredInvoice): Promise<RiskScore>;

  /**
   * Check for duplicate invoices
   */
  checkDuplicates?(invoice: StructuredInvoice): Promise<string[]>;

  /**
   * Validate KPD codes (Croatian classification)
   */
  validateKPDCodes?(invoice: StructuredInvoice): Promise<{
    valid: boolean;
    errors: ValidationError[];
  }>;
}

/**
 * Email Client Interface
 * Abstracts email functionality for testing with mocks or production IMAP
 */
export interface IEmailClient {
  /**
   * Connect to email server
   */
  connect(): Promise<void>;

  /**
   * Disconnect from email server
   */
  disconnect?(): Promise<void>;

  /**
   * Fetch unread messages
   */
  fetchUnread(options?: FetchOptions): Promise<EmailMessage[]>;

  /**
   * Fetch specific message by ID
   */
  fetchMessage(messageId: string): Promise<EmailMessage>;

  /**
   * Mark message as processed
   */
  markAsProcessed(messageId: string): Promise<void>;

  /**
   * Download attachment
   */
  downloadAttachment(messageId: string, attachmentId: string): Promise<Buffer>;

  /**
   * Search messages
   */
  search?(criteria: Record<string, any>): Promise<EmailMessage[]>;

  /**
   * Move message to folder
   */
  moveMessage?(messageId: string, folder: string): Promise<void>;
}
