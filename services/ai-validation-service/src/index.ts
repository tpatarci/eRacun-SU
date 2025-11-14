/**
 * AI Validation Service
 */
import { MockAIValidationEngine, StructuredInvoice, AnomalyResult } from '@eracun/team2-mocks';
import pino from 'pino';

const logger = pino({ name: 'ai-validation-service' });

export class AIValidationService {
  private engine: MockAIValidationEngine;

  constructor() {
    this.engine = new MockAIValidationEngine();
  }

  async validateInvoice(invoice: StructuredInvoice): Promise<{
    valid: boolean;
    anomalies: AnomalyResult[];
    riskScore: number;
  }> {
    const anomalies = await this.engine.detectAnomalies(invoice);
    const semanticValidation = await this.engine.validateSemantics(invoice);
    const riskScore = await this.engine.calculateRiskScore(invoice);

    const valid = anomalies.length === 0 && semanticValidation.valid;

    logger.info({ invoiceId: invoice.invoiceNumber, valid, riskScore: riskScore.score }, 'Validation complete');

    return {
      valid,
      anomalies,
      riskScore: riskScore.score
    };
  }
}

export { StructuredInvoice, AnomalyResult };
