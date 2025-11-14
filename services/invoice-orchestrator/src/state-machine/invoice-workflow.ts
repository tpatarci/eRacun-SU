/**
 * Invoice Processing Workflow State Machine
 * Implements saga pattern with XState
 */

import { createMachine, assign } from 'xstate';
import { UBLInvoice, ValidationResult } from '@eracun/contracts';

// State machine context
export interface InvoiceWorkflowContext {
  invoiceId: string;
  invoice: UBLInvoice;
  validationResult?: ValidationResult;
  transformedXML?: string;
  finaJIR?: string;
  error?: Error;
  retryCount: number;
  startedAt: string;
  completedAt?: string;
}

// State machine events
export type InvoiceWorkflowEvent =
  | { type: 'START_PROCESSING'; invoice: UBLInvoice }
  | { type: 'VALIDATION_SUCCESS'; result: ValidationResult }
  | { type: 'VALIDATION_FAILURE'; error: Error }
  | { type: 'TRANSFORMATION_SUCCESS'; xml: string }
  | { type: 'TRANSFORMATION_FAILURE'; error: Error }
  | { type: 'SUBMISSION_SUCCESS'; jir: string }
  | { type: 'SUBMISSION_FAILURE'; error: Error }
  | { type: 'RETRY' }
  | { type: 'COMPENSATE' };

/**
 * Invoice processing workflow state machine
 * States: IDLE → VALIDATING → TRANSFORMING → SUBMITTING → COMPLETED
 * Handles failures with compensation logic
 */
export const invoiceWorkflowMachine = createMachine(
  {
    id: 'invoiceWorkflow',
    initial: 'idle',
    context: {
      invoiceId: '',
      invoice: {} as UBLInvoice,
      retryCount: 0,
      startedAt: new Date().toISOString(),
    } as InvoiceWorkflowContext,
    states: {
      idle: {
        on: {
          START_PROCESSING: {
            target: 'validating',
            actions: 'assignInvoice',
          },
        },
      },
      validating: {
        entry: 'logValidationStart',
        on: {
          VALIDATION_SUCCESS: {
            target: 'transforming',
            actions: 'assignValidationResult',
          },
          VALIDATION_FAILURE: [
            {
              target: 'retrying',
              cond: 'canRetry',
              actions: 'incrementRetryCount',
            },
            {
              target: 'compensating',
              actions: 'assignError',
            },
          ],
        },
      },
      transforming: {
        entry: 'logTransformationStart',
        on: {
          TRANSFORMATION_SUCCESS: {
            target: 'submitting',
            actions: 'assignTransformedXML',
          },
          TRANSFORMATION_FAILURE: [
            {
              target: 'retrying',
              cond: 'canRetry',
              actions: 'incrementRetryCount',
            },
            {
              target: 'compensating',
              actions: 'assignError',
            },
          ],
        },
      },
      submitting: {
        entry: 'logSubmissionStart',
        on: {
          SUBMISSION_SUCCESS: {
            target: 'completed',
            actions: 'assignFINAJIR',
          },
          SUBMISSION_FAILURE: [
            {
              target: 'retrying',
              cond: 'canRetry',
              actions: 'incrementRetryCount',
            },
            {
              target: 'compensating',
              actions: 'assignError',
            },
          ],
        },
      },
      retrying: {
        entry: 'logRetry',
        after: {
          RETRY_DELAY: 'validating',
        },
      },
      compensating: {
        entry: 'logCompensation',
        invoke: {
          src: 'compensate',
          onDone: 'failed',
          onError: 'failed',
        },
      },
      completed: {
        type: 'final',
        entry: 'logCompletion',
      },
      failed: {
        type: 'final',
        entry: 'logFailure',
      },
    },
  },
  {
    actions: {
      assignInvoice: assign({
        invoice: (context, event: any) => event.invoice,
        invoiceId: (context, event: any) => event.invoice.id,
        startedAt: () => new Date().toISOString(),
      }),
      assignValidationResult: assign({
        validationResult: (context, event: any) => event.result,
      }),
      assignTransformedXML: assign({
        transformedXML: (context, event: any) => event.xml,
      }),
      assignFINAJIR: assign({
        finaJIR: (context, event: any) => event.jir,
        completedAt: () => new Date().toISOString(),
      }),
      assignError: assign({
        error: (context, event: any) => event.error,
      }),
      incrementRetryCount: assign({
        retryCount: (context) => context.retryCount + 1,
      }),
      logValidationStart: (context) => {
        console.log(`[${context.invoiceId}] Starting validation`);
      },
      logTransformationStart: (context) => {
        console.log(`[${context.invoiceId}] Starting transformation`);
      },
      logSubmissionStart: (context) => {
        console.log(`[${context.invoiceId}] Starting FINA submission`);
      },
      logRetry: (context) => {
        console.log(`[${context.invoiceId}] Retry attempt ${context.retryCount}`);
      },
      logCompensation: (context) => {
        console.log(`[${context.invoiceId}] Starting compensation`);
      },
      logCompletion: (context) => {
        console.log(`[${context.invoiceId}] Processing completed successfully`);
      },
      logFailure: (context) => {
        console.error(`[${context.invoiceId}] Processing failed:`, context.error);
      },
    },
    guards: {
      canRetry: (context) => context.retryCount < 3,
    },
    delays: {
      RETRY_DELAY: (context) => {
        // Exponential backoff: 2^retryCount * 1000ms + jitter
        const baseDelay = Math.pow(2, context.retryCount) * 1000;
        const jitter = Math.random() * 1000;
        return baseDelay + jitter;
      },
    },
  }
);
