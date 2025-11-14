/**
 * Mock AI Validation Engine
 * Simulates AI-powered validation for testing without ML infrastructure
 */

import { IAIValidationEngine } from './interfaces';
import {
  StructuredInvoice,
  AnomalyResult,
  AnomalyType,
  AnomalySeverity,
  SemanticValidation,
  SemanticError,
  SemanticWarning,
  RiskScore,
  RiskFactor,
  RiskCategory,
  Correction,
  ValidationError
} from '../types/ai-types';

export class MockAIValidationEngine implements IAIValidationEngine {
  private readonly modelVersion = '2.1.0-mock';

  /**
   * Detect anomalies in structured invoice data
   */
  async detectAnomalies(invoice: StructuredInvoice): Promise<AnomalyResult[]> {
    const anomalies: AnomalyResult[] = [];

    // Simulate AI processing delay
    await this.simulateAIProcessing();

    // Price anomaly detection (10% chance)
    if (this.isPriceAnomaly(invoice)) {
      anomalies.push({
        type: AnomalyType.PRICE_ANOMALY,
        severity: AnomalySeverity.HIGH,
        field: 'totalAmount',
        expected: this.calculateExpectedPrice(invoice),
        actual: invoice.totalAmount,
        confidence: 0.87,
        explanation: 'Total amount significantly deviates from historical patterns for this supplier'
      });
    }

    // VAT calculation error (5% chance)
    if (this.isVATAnomaly(invoice)) {
      const expectedVAT = this.calculateVAT(invoice);
      anomalies.push({
        type: AnomalyType.VAT_CALCULATION_ERROR,
        severity: AnomalySeverity.CRITICAL,
        field: 'vatAmount',
        expected: expectedVAT,
        actual: invoice.vatAmount,
        confidence: 0.95,
        explanation: `VAT calculation error: expected ${expectedVAT.toFixed(2)}, got ${invoice.vatAmount.toFixed(2)}`
      });
    }

    // Duplicate invoice detection (3% chance)
    if (this.isDuplicateInvoice(invoice)) {
      anomalies.push({
        type: AnomalyType.POTENTIAL_DUPLICATE,
        severity: AnomalySeverity.MEDIUM,
        field: 'invoiceNumber',
        similarInvoices: this.findSimilarInvoices(invoice),
        confidence: 0.78,
        explanation: 'Similar invoice detected in recent history (same supplier, similar amount, close date)'
      });
    }

    // Suspicious amount (2% chance)
    if (this.isSuspiciousAmount(invoice)) {
      anomalies.push({
        type: AnomalyType.SUSPICIOUS_AMOUNT,
        severity: AnomalySeverity.HIGH,
        field: 'totalAmount',
        actual: invoice.totalAmount,
        confidence: 0.82,
        explanation: 'Amount is suspiciously round or matches common fraud patterns'
      });
    }

    return anomalies;
  }

  /**
   * Validate semantic rules and business logic
   */
  async validateSemantics(invoice: StructuredInvoice): Promise<SemanticValidation> {
    const errors: SemanticError[] = [];
    const warnings: SemanticWarning[] = [];

    await this.simulateAIProcessing();

    // Business relationship validation
    if (!this.isValidBusinessRelationship(invoice)) {
      errors.push({
        code: 'INVALID_BUSINESS_RELATIONSHIP',
        message: 'Supplier-buyer relationship not recognized in business registry',
        field: 'parties',
        suggestion: 'Verify both OIB numbers are registered and have valid business relationship'
      });
    }

    // Delivery date validation
    if (!this.isReasonableDeliveryDate(invoice)) {
      warnings.push({
        code: 'SUSPICIOUS_DELIVERY_DATE',
        message: 'Delivery date is unusual (too far in future or past)',
        field: 'deliveryDate',
        suggestion: 'Verify delivery date is correct'
      });
    }

    // Line item validation
    const lineItemErrors = this.validateLineItems(invoice);
    errors.push(...lineItemErrors);

    // KPD classification validation
    const kpdValidation = await this.validateKPDCodes(invoice);
    if (!kpdValidation.valid) {
      errors.push(...kpdValidation.errors.map(e => ({
        code: e.code,
        message: e.message,
        field: e.field,
        suggestion: 'Use valid KLASUS 2025 classification codes'
      })));
    }

    // Amount consistency check
    if (!this.isAmountConsistent(invoice)) {
      errors.push({
        code: 'AMOUNT_INCONSISTENCY',
        message: 'Total amount does not match sum of line items',
        field: 'totalAmount',
        suggestion: 'Recalculate totals from line items'
      });
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      processingTime: Date.now(),
      modelVersion: this.modelVersion
    };
  }

  /**
   * Suggest corrections for validation errors
   */
  async suggestCorrections(errors: ValidationError[]): Promise<Correction[]> {
    await this.simulateAIProcessing();

    const corrections: Correction[] = [];

    for (const error of errors) {
      if (error.code === 'VAT_CALCULATION_ERROR') {
        corrections.push({
          field: 'vatAmount',
          currentValue: error.value,
          suggestedValue: this.suggestVATCorrection(error),
          confidence: 0.92,
          rationale: 'Recalculated VAT based on line items and applicable rates'
        });
      }

      if (error.code === 'INVALID_OIB') {
        corrections.push({
          field: error.field,
          currentValue: error.value,
          suggestedValue: this.suggestOIBCorrection(error.value),
          confidence: 0.65,
          rationale: 'OIB check digit correction based on ISO 7064 algorithm'
        });
      }
    }

    return corrections;
  }

  /**
   * Calculate risk score for invoice
   */
  async calculateRiskScore(invoice: StructuredInvoice): Promise<RiskScore> {
    await this.simulateAIProcessing();

    const factors: RiskFactor[] = [
      {
        name: 'supplier_history',
        weight: 0.3,
        score: this.evaluateSupplierHistory(invoice) * 0.3,
        explanation: 'Supplier has good payment history and reputation'
      },
      {
        name: 'amount_variance',
        weight: 0.25,
        score: this.calculateAmountVariance(invoice) * 0.25,
        explanation: 'Amount is within expected range for this supplier'
      },
      {
        name: 'payment_terms',
        weight: 0.2,
        score: this.evaluatePaymentTerms(invoice) * 0.2,
        explanation: 'Payment terms are standard and acceptable'
      },
      {
        name: 'document_quality',
        weight: 0.15,
        score: Math.random() * 0.15,
        explanation: 'Document quality and completeness assessment'
      },
      {
        name: 'compliance_check',
        weight: 0.1,
        score: Math.random() * 0.1,
        explanation: 'Compliance with Croatian e-invoice regulations'
      }
    ];

    const totalScore = factors.reduce((sum, f) => sum + f.score, 0);
    const category = this.categorizeRisk(totalScore);

    return {
      score: totalScore,
      category,
      factors,
      threshold: 0.7,
      requiresManualReview: totalScore > 0.7,
      explanation: this.generateRiskExplanation(factors, totalScore)
    };
  }

  /**
   * Check for duplicate invoices
   */
  async checkDuplicates(invoice: StructuredInvoice): Promise<string[]> {
    await this.simulateAIProcessing();

    if (this.isDuplicateInvoice(invoice)) {
      return this.findSimilarInvoices(invoice);
    }

    return [];
  }

  /**
   * Validate KPD codes (Croatian classification)
   */
  async validateKPDCodes(invoice: StructuredInvoice): Promise<{
    valid: boolean;
    errors: ValidationError[];
  }> {
    const errors: ValidationError[] = [];

    // Validate each line item has KPD code
    for (const [index, item] of invoice.lineItems.entries()) {
      if (!item.kpdCode) {
        errors.push({
          code: 'MISSING_KPD_CODE',
          message: 'KPD classification code is required for all line items',
          field: `lineItems[${index}].kpdCode`,
          value: undefined
        });
      } else if (!this.isValidKPDFormat(item.kpdCode)) {
        errors.push({
          code: 'INVALID_KPD_FORMAT',
          message: 'KPD code must be 6 digits (KLASUS 2025 format)',
          field: `lineItems[${index}].kpdCode`,
          value: item.kpdCode
        });
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  // Private helper methods

  private simulateAIProcessing(): Promise<void> {
    // Realistic AI processing delay (200-1000ms)
    return new Promise(resolve =>
      setTimeout(resolve, 200 + Math.random() * 800)
    );
  }

  private isPriceAnomaly(invoice: StructuredInvoice): boolean {
    // 10% chance of price anomaly in mock
    return Math.random() < 0.1;
  }

  private isVATAnomaly(invoice: StructuredInvoice): boolean {
    // Check if VAT calculation is actually wrong
    const expectedVAT = this.calculateVAT(invoice);
    const difference = Math.abs(expectedVAT - invoice.vatAmount);

    // 5% chance OR actual calculation error
    return Math.random() < 0.05 || difference > 0.01;
  }

  private isDuplicateInvoice(invoice: StructuredInvoice): boolean {
    // 3% chance of duplicate detection in mock
    return Math.random() < 0.03;
  }

  private isSuspiciousAmount(invoice: StructuredInvoice): boolean {
    // Round numbers are sometimes suspicious (e.g., exactly 10000.00)
    const isRound = invoice.totalAmount % 1000 === 0 && invoice.totalAmount >= 10000;
    return isRound && Math.random() < 0.02;
  }

  private calculateExpectedPrice(invoice: StructuredInvoice): number {
    // Simulate expected price based on line items with 10% variance
    const calculated = invoice.lineItems.reduce((sum, item) =>
      sum + (item.quantity * item.price * (1 + item.vat)), 0
    );
    return calculated * (0.9 + Math.random() * 0.2);
  }

  private calculateVAT(invoice: StructuredInvoice): number {
    return invoice.lineItems.reduce((sum, item) =>
      sum + (item.quantity * item.price * item.vat), 0
    );
  }

  private findSimilarInvoices(invoice: StructuredInvoice): string[] {
    // Generate fake similar invoice numbers
    return [
      `${invoice.invoiceNumber}-DUP`,
      `${new Date().getFullYear()}-${Math.floor(Math.random() * 1000).toString().padStart(4, '0')}`
    ];
  }

  private isValidBusinessRelationship(invoice: StructuredInvoice): boolean {
    // 95% pass rate - most relationships are valid
    return Math.random() < 0.95;
  }

  private isReasonableDeliveryDate(invoice: StructuredInvoice): boolean {
    if (!invoice.deliveryDate) return true;

    const deliveryDate = new Date(invoice.deliveryDate);
    const issueDate = new Date(invoice.issueDate);
    const daysDifference = (deliveryDate.getTime() - issueDate.getTime()) / (1000 * 60 * 60 * 24);

    // Reasonable if between -30 and +90 days from issue date
    return daysDifference >= -30 && daysDifference <= 90;
  }

  private validateLineItems(invoice: StructuredInvoice): SemanticError[] {
    const errors: SemanticError[] = [];

    if (invoice.lineItems.length === 0) {
      errors.push({
        code: 'NO_LINE_ITEMS',
        message: 'Invoice must have at least one line item',
        field: 'lineItems'
      });
    }

    return errors;
  }

  private isAmountConsistent(invoice: StructuredInvoice): boolean {
    const calculatedTotal = invoice.lineItems.reduce((sum, item) =>
      sum + item.total, 0
    );

    // Allow 0.01 difference for rounding
    return Math.abs(calculatedTotal - invoice.totalAmount) < 0.01;
  }

  private isValidKPDFormat(code: string): boolean {
    // KLASUS 2025: 6-digit code
    return /^\d{6}$/.test(code);
  }

  private suggestVATCorrection(error: ValidationError): number {
    // Simulate VAT correction
    return parseFloat((Math.random() * 1000).toFixed(2));
  }

  private suggestOIBCorrection(currentOIB: string): string {
    // Return a plausible OIB by fixing check digit
    return currentOIB.substring(0, 10) + Math.floor(Math.random() * 10);
  }

  private evaluateSupplierHistory(invoice: StructuredInvoice): number {
    // Random score weighted towards good suppliers (lower risk)
    return Math.random() * 0.5; // 0-0.5 range (low risk)
  }

  private calculateAmountVariance(invoice: StructuredInvoice): number {
    // Most invoices are within normal range
    return Math.random() * 0.3; // 0-0.3 range (low variance)
  }

  private evaluatePaymentTerms(invoice: StructuredInvoice): number {
    if (!invoice.paymentTerms) return 0.1;

    const standardTerms = ['Net 30', 'Net 15', 'Net 45', '2/10 Net 30'];
    const isStandard = standardTerms.includes(invoice.paymentTerms);

    return isStandard ? 0.05 : 0.15;
  }

  private categorizeRisk(score: number): RiskCategory {
    if (score < 0.3) return RiskCategory.LOW;
    if (score < 0.5) return RiskCategory.MEDIUM;
    if (score < 0.7) return RiskCategory.HIGH;
    return RiskCategory.CRITICAL;
  }

  private generateRiskExplanation(factors: RiskFactor[], totalScore: number): string {
    const category = this.categorizeRisk(totalScore);
    const topFactors = factors
      .sort((a, b) => b.score - a.score)
      .slice(0, 2)
      .map(f => f.name)
      .join(' and ');

    return `Risk score ${totalScore.toFixed(2)} (${category}). Primary concerns: ${topFactors}.`;
  }
}
