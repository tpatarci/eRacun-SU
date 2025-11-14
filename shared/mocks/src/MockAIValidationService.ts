/**
 * Mock AI Validation Service
 * Simulates anomaly detection and cross-validation
 */

import { injectable } from 'inversify';
import {
  IAIValidationService,
  AnomalyDetectionResult,
  Anomaly,
  CorrectionSuggestion
} from '@eracun/adapters';
import { UBLInvoice, LayerResult } from '@eracun/contracts';

@injectable()
export class MockAIValidationService implements IAIValidationService {
  async detectAnomalies(invoice: UBLInvoice): Promise<AnomalyDetectionResult> {
    await this.simulateNetworkDelay(300, 800);

    // 10% chance of detecting anomalies
    const hasAnomalies = Math.random() < 0.1;

    if (hasAnomalies) {
      const anomaly: Anomaly = {
        field: 'amounts.net',
        type: 'OUTLIER',
        severity: 'MEDIUM',
        description: 'Net amount significantly higher than typical for this supplier',
        expectedValue: 1000,
        actualValue: invoice.amounts.net,
        confidence: 0.75
      };

      return {
        hasAnomalies: true,
        anomalies: [anomaly],
        confidence: 0.75,
        processingTime: Math.random() * 600 + 300
      };
    }

    return {
      hasAnomalies: false,
      anomalies: [],
      confidence: 0.95,
      processingTime: Math.random() * 500 + 300
    };
  }

  async crossValidate(invoice: UBLInvoice): Promise<LayerResult> {
    await this.simulateNetworkDelay(200, 600);

    // 97% validation pass rate
    const passed = Math.random() > 0.03;

    return {
      passed,
      executionTime: Math.random() * 500 + 200,
      details: passed
        ? {
            checks: ['VAT calculation', 'Line item totals', 'OIB format'],
            allPassed: true
          }
        : {
            checks: ['VAT calculation', 'Line item totals', 'OIB format'],
            allPassed: false,
            failedChecks: ['VAT calculation'],
            errors: [
              {
                check: 'VAT calculation',
                message: 'Calculated VAT does not match declared VAT'
              }
            ]
          }
    };
  }

  async suggestCorrections(invoice: UBLInvoice): Promise<CorrectionSuggestion[]> {
    await this.simulateNetworkDelay(200, 500);

    // 20% chance of having suggestions
    if (Math.random() < 0.2) {
      return [
        {
          field: 'lineItems[0].kpdCode',
          currentValue: '000000',
          suggestedValue: '123456',
          reason: 'Most commonly used KPD code for this type of service',
          confidence: 0.82
        }
      ];
    }

    return [];
  }

  async healthCheck(): Promise<boolean> {
    await this.simulateNetworkDelay(50, 150);
    // 96% uptime
    return Math.random() > 0.04;
  }

  private async simulateNetworkDelay(min: number = 100, max: number = 500): Promise<void> {
    const delay = Math.random() * (max - min) + min;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}
