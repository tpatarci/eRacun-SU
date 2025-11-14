/**
 * Error Aggregator
 * Aggregates errors, warnings, and suggestions from all validation layers
 */

import { injectable } from 'inversify';
import {
  LayerResult,
  ValidationError,
  ValidationWarning,
  Suggestion,
  ErrorCode,
} from '@eracun/contracts';

export interface AggregationResult {
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: Suggestion[];
}

@injectable()
export class ErrorAggregator {
  /**
   * Aggregate errors from all validation layers
   */
  aggregate(layers: {
    xsd: LayerResult;
    schematron: LayerResult;
    kpd: LayerResult;
    semantic: LayerResult;
    ai: LayerResult;
  }): AggregationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const suggestions: Suggestion[] = [];

    // Extract errors from each layer
    this.extractFromLayer(layers.xsd, 'XSD', errors, warnings);
    this.extractFromLayer(layers.schematron, 'Schematron', errors, warnings);
    this.extractFromLayer(layers.kpd, 'KPD', errors, warnings);
    this.extractFromLayer(layers.semantic, 'Semantic', errors, warnings);
    this.extractFromLayer(layers.ai, 'AI', errors, warnings);

    // Deduplicate errors and warnings
    const uniqueErrors = this.deduplicateErrors(errors);
    const uniqueWarnings = this.deduplicateWarnings(warnings);

    // Sort by severity
    uniqueErrors.sort((a, b) => this.compareSeverity(a.severity, b.severity));

    return {
      errors: uniqueErrors,
      warnings: uniqueWarnings,
      suggestions,
    };
  }

  /**
   * Extract errors and warnings from a layer result
   */
  private extractFromLayer(
    layer: LayerResult,
    layerName: string,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    if (!layer.passed && layer.details) {
      // Check if details contains errors array
      if (Array.isArray(layer.details.errors)) {
        for (const error of layer.details.errors) {
          errors.push({
            code: error.code || ErrorCode.SCHEMA_VALIDATION_FAILED,
            severity: error.severity || 'HIGH',
            field: error.field || 'unknown',
            message: `[${layerName}] ${error.message}`,
            suggestion: error.suggestion,
          });
        }
      } else if (layer.details.error) {
        // Single error message
        errors.push({
          code: ErrorCode.SCHEMA_VALIDATION_FAILED,
          severity: 'HIGH',
          field: 'unknown',
          message: `[${layerName}] ${layer.details.error}`,
        });
      }
    }
  }

  /**
   * Deduplicate errors by code and field
   */
  private deduplicateErrors(errors: ValidationError[]): ValidationError[] {
    const seen = new Set<string>();
    const unique: ValidationError[] = [];

    for (const error of errors) {
      const key = `${error.code}-${error.field}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(error);
      }
    }

    return unique;
  }

  /**
   * Deduplicate warnings by code and field
   */
  private deduplicateWarnings(warnings: ValidationWarning[]): ValidationWarning[] {
    const seen = new Set<string>();
    const unique: ValidationWarning[] = [];

    for (const warning of warnings) {
      const key = `${warning.code}-${warning.field}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(warning);
      }
    }

    return unique;
  }

  /**
   * Compare severity for sorting (CRITICAL > HIGH > MEDIUM)
   */
  private compareSeverity(
    a: 'CRITICAL' | 'HIGH' | 'MEDIUM',
    b: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  ): number {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
    return order[a] - order[b];
  }
}
