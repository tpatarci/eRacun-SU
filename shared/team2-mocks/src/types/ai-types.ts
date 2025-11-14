/**
 * AI Validation Types for Mock AI Engine
 * Provides structures for anomaly detection, semantic validation, and risk scoring
 */

export interface StructuredInvoice {
  invoiceNumber: string;
  issueDate: string;
  supplierOIB: string;
  recipientOIB: string;
  totalAmount: number;
  vatAmount: number;
  netAmount: number;
  currency: string;
  lineItems: LineItem[];
  paymentTerms?: string;
  deliveryDate?: string;
}

export interface LineItem {
  description: string;
  quantity: number;
  price: number;
  vat: number;
  total: number;
  kpdCode?: string;
}

export enum AnomalyType {
  PRICE_ANOMALY = 'PRICE_ANOMALY',
  VAT_CALCULATION_ERROR = 'VAT_CALCULATION_ERROR',
  POTENTIAL_DUPLICATE = 'POTENTIAL_DUPLICATE',
  SUSPICIOUS_AMOUNT = 'SUSPICIOUS_AMOUNT',
  INVALID_DATE = 'INVALID_DATE',
  MISSING_REQUIRED_FIELD = 'MISSING_REQUIRED_FIELD',
  FORMAT_INCONSISTENCY = 'FORMAT_INCONSISTENCY'
}

export enum AnomalySeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface AnomalyResult {
  type: AnomalyType;
  severity: AnomalySeverity;
  field: string;
  expected?: any;
  actual?: any;
  confidence: number;
  explanation: string;
  similarInvoices?: string[];
}

export interface SemanticError {
  code: string;
  message: string;
  field: string;
  suggestion?: string;
}

export interface SemanticWarning {
  code: string;
  message: string;
  field: string;
  suggestion?: string;
}

export interface SemanticValidation {
  valid: boolean;
  errors: SemanticError[];
  warnings: SemanticWarning[];
  processingTime: number;
  modelVersion: string;
}

export interface RiskFactor {
  name: string;
  weight: number;
  score: number;
  explanation?: string;
}

export enum RiskCategory {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface RiskScore {
  score: number;
  category: RiskCategory;
  factors: RiskFactor[];
  threshold: number;
  requiresManualReview: boolean;
  explanation: string;
}

export interface Correction {
  field: string;
  currentValue: any;
  suggestedValue: any;
  confidence: number;
  rationale: string;
}

export interface ValidationError {
  code: string;
  message: string;
  field: string;
  value?: any;
}
