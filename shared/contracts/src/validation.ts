/**
 * Validation Result Contracts
 * Used by validation-coordinator to aggregate results from 6 validation layers
 */

export interface ValidationResult {
  invoiceId: string;
  timestamp: string;                // ISO 8601

  // Overall result
  valid: boolean;
  confidence: number;              // 0-1 score

  // Layer results
  layers: {
    xsd: LayerResult;
    schematron: LayerResult;
    kpd: LayerResult;
    semantic: LayerResult;
    ai: LayerResult;
    consensus: LayerResult;
  };

  // Aggregated issues
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: Suggestion[];
}

export interface LayerResult {
  passed: boolean;
  executionTime: number;           // milliseconds
  details?: any;                   // Layer-specific data
}

export interface ValidationError {
  code: string;                    // e.g., 'INVALID_OIB'
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  field: string;                   // JSONPath to field
  message: string;
  suggestion?: string;
}

export interface ValidationWarning {
  code: string;
  field: string;
  message: string;
}

export interface Suggestion {
  field: string;
  message: string;
  suggestedValue?: string;
}
