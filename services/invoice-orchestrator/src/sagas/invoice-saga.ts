/**
 * Invoice Processing Saga
 * Coordinates the complete invoice processing workflow
 */

import { injectable, inject } from 'inversify';
import { interpret, InterpreterFrom } from 'xstate';
import { invoiceWorkflowMachine, InvoiceWorkflowContext } from '../state-machine/invoice-workflow';
import { TYPES } from '@eracun/di-container';
import { IValidationService, IFINAService } from '@eracun/adapters';
import { UBLInvoice, ValidationResult } from '@eracun/contracts';
import pino from 'pino';

const logger = pino({ name: 'invoice-saga' });

@injectable()
export class InvoiceSaga {
  private interpreter: InterpreterFrom<typeof invoiceWorkflowMachine> | null = null;

  constructor(
    @inject(TYPES.ValidationService) private validationService: IValidationService,
    @inject(TYPES.FINAService) private finaService: IFINAService
  ) {}

  /**
   * Start invoice processing saga
   */
  async startSaga(invoice: UBLInvoice): Promise<void> {
    logger.info({ invoiceId: invoice.id }, 'Starting invoice processing saga');

    // Create and start state machine interpreter
    this.interpreter = interpret(invoiceWorkflowMachine);

    // Subscribe to state transitions
    this.interpreter.onTransition((state) => {
      logger.debug({
        invoiceId: invoice.id,
        state: state.value,
        context: state.context,
      }, 'State transition');
    });

    // Handle state-specific logic
    this.interpreter.onTransition(async (state) => {
      const context = state.context as InvoiceWorkflowContext;

      if (state.matches('validating')) {
        await this.handleValidation(context);
      } else if (state.matches('transforming')) {
        await this.handleTransformation(context);
      } else if (state.matches('submitting')) {
        await this.handleSubmission(context);
      } else if (state.matches('compensating')) {
        await this.handleCompensation(context);
      }
    });

    // Start the interpreter
    this.interpreter.start();

    // Send START_PROCESSING event
    this.interpreter.send({
      type: 'START_PROCESSING',
      invoice,
    });
  }

  /**
   * Handle validation step
   */
  private async handleValidation(context: InvoiceWorkflowContext): Promise<void> {
    try {
      logger.info({ invoiceId: context.invoiceId }, 'Running validation');

      // TODO: Generate XML from invoice object
      const xml = this.generateMockXML(context.invoice);

      // Run validation
      const result: ValidationResult = await this.validationService.validateFull(xml);

      if (result.valid) {
        this.interpreter?.send({
          type: 'VALIDATION_SUCCESS',
          result,
        });
      } else {
        throw new Error(`Validation failed: ${JSON.stringify(result.errors)}`);
      }
    } catch (error) {
      logger.error({ error, invoiceId: context.invoiceId }, 'Validation failed');
      this.interpreter?.send({
        type: 'VALIDATION_FAILURE',
        error: error as Error,
      });
    }
  }

  /**
   * Handle transformation step
   */
  private async handleTransformation(context: InvoiceWorkflowContext): Promise<void> {
    try {
      logger.info({ invoiceId: context.invoiceId }, 'Running transformation');

      // TODO: Transform to UBL 2.1 XML
      const xml = this.generateMockXML(context.invoice);

      this.interpreter?.send({
        type: 'TRANSFORMATION_SUCCESS',
        xml,
      });
    } catch (error) {
      logger.error({ error, invoiceId: context.invoiceId }, 'Transformation failed');
      this.interpreter?.send({
        type: 'TRANSFORMATION_FAILURE',
        error: error as Error,
      });
    }
  }

  /**
   * Handle FINA submission step
   */
  private async handleSubmission(context: InvoiceWorkflowContext): Promise<void> {
    try {
      logger.info({ invoiceId: context.invoiceId }, 'Submitting to FINA');

      // Submit to FINA
      const response = await this.finaService.submitInvoice({
        invoice: context.invoice,
        signature: '', // TODO: Sign document
        zki: '', // TODO: Calculate ZKI
        certificateId: 'mock-cert-id',
      });

      if (response.success && response.jir) {
        this.interpreter?.send({
          type: 'SUBMISSION_SUCCESS',
          jir: response.jir,
        });
      } else {
        throw new Error(`FINA submission failed: ${response.error?.message}`);
      }
    } catch (error) {
      logger.error({ error, invoiceId: context.invoiceId }, 'FINA submission failed');
      this.interpreter?.send({
        type: 'SUBMISSION_FAILURE',
        error: error as Error,
      });
    }
  }

  /**
   * Handle compensation (rollback) logic
   */
  private async handleCompensation(context: InvoiceWorkflowContext): Promise<void> {
    logger.info({ invoiceId: context.invoiceId }, 'Running compensation logic');

    try {
      // Compensation steps (in reverse order):
      // 1. Cancel FINA submission (if submitted)
      if (context.finaJIR) {
        logger.info({ invoiceId: context.invoiceId, jir: context.finaJIR }, 'Canceling FINA submission');
        // TODO: Implement FINA cancellation
      }

      // 2. Rollback database changes
      logger.info({ invoiceId: context.invoiceId }, 'Rolling back database changes');
      // TODO: Implement database rollback

      // 3. Publish failure event
      logger.info({ invoiceId: context.invoiceId }, 'Publishing failure event');
      // TODO: Publish InvoiceProcessingFailedEvent

      logger.info({ invoiceId: context.invoiceId }, 'Compensation completed');
    } catch (error) {
      logger.error({ error, invoiceId: context.invoiceId }, 'Compensation failed');
      throw error;
    }
  }

  /**
   * Get current saga state
   */
  getState(): string {
    return this.interpreter?.getSnapshot().value as string || 'unknown';
  }

  /**
   * Get saga context
   */
  getContext(): InvoiceWorkflowContext | null {
    return this.interpreter?.getSnapshot().context as InvoiceWorkflowContext || null;
  }

  /**
   * Stop saga
   */
  stop(): void {
    this.interpreter?.stop();
  }

  /**
   * Generate mock XML (temporary)
   */
  private generateMockXML(invoice: UBLInvoice): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">
  <cbc:ID>${invoice.invoiceNumber}</cbc:ID>
  <cbc:IssueDate>${invoice.issueDate}</cbc:IssueDate>
</Invoice>`;
  }
}
