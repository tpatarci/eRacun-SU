/**
 * Team 2 Mocks - Shared Testing Infrastructure
 * Provides mock implementations for OCR, AI, and Email services
 *
 * @packageDocumentation
 */

// Export adapters
export { IOCREngine, IAIValidationEngine, IEmailClient } from './adapters/interfaces';
export { MockOCREngine } from './adapters/mock-ocr-engine';
export { MockAIValidationEngine } from './adapters/mock-ai-validation-engine';
export { MockEmailClient } from './adapters/mock-email-client';

// Export types
export {
  Language,
  BoundingBox,
  TextBlock,
  TableCell,
  TableResult,
  TextResult,
  OCROptions,
  OCRScenario
} from './types/ocr-types';

export {
  StructuredInvoice,
  LineItem,
  AnomalyType,
  AnomalySeverity,
  AnomalyResult,
  SemanticError,
  SemanticWarning,
  SemanticValidation,
  RiskFactor,
  RiskCategory,
  RiskScore,
  Correction,
  ValidationError
} from './types/ai-types';

export {
  Attachment,
  EmailMessage,
  EmailClientConfig,
  FetchOptions
} from './types/email-types';

// Export generators
export {
  generateOIB,
  generateInvoiceNumber,
  generateLineItem,
  generateInvoice,
  generateValidUBL,
  InvoiceBuilder,
  CROATIAN_VAT_RATES
} from './generators/invoice-generator';
