/**
 * AI Validation Service Adapter Interface
 * Abstracts anomaly detection and cross-validation
 */

import { UBLInvoice, LayerResult } from '@eracun/contracts';

export interface IAIValidationService {
  /**
   * Detect anomalies in invoice data
   */
  detectAnomalies(invoice: UBLInvoice): Promise<AnomalyDetectionResult>;

  /**
   * Cross-validate invoice fields for consistency
   */
  crossValidate(invoice: UBLInvoice): Promise<LayerResult>;

  /**
   * Suggest corrections for detected issues
   */
  suggestCorrections(invoice: UBLInvoice): Promise<CorrectionSuggestion[]>;

  /**
   * Health check
   */
  healthCheck(): Promise<boolean>;
}

export interface AnomalyDetectionResult {
  hasAnomalies: boolean;
  anomalies: Anomaly[];
  confidence: number;             // 0-1 score
  processingTime: number;         // milliseconds
}

export interface Anomaly {
  field: string;
  type: 'OUTLIER' | 'INCONSISTENCY' | 'PATTERN_VIOLATION';
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  expectedValue?: any;
  actualValue: any;
  confidence: number;
}

export interface CorrectionSuggestion {
  field: string;
  currentValue: any;
  suggestedValue: any;
  reason: string;
  confidence: number;
}
