import { Queue } from 'bullmq';
import { logger } from '../shared/logger.js';
import {
  createInvoiceQueue,
  createInvoiceWorker,
  type InvoiceJobData,
  type JobStatusUpdate,
  JobType,
} from './queue.js';
import { updateInvoiceStatus } from '../archive/invoice-repository.js';

/**
 * Invoice submission service
 * Manages the queue and worker for async FINA submission
 */
export class InvoiceSubmissionService {
  private queue: Queue<InvoiceJobData> | null = null;
  private worker: ReturnType<typeof createInvoiceWorker> | null = null;
  private initialized = false;

  /**
   * Initialize the submission service
   */
  initialize(redisUrl: string): void {
    if (this.initialized) {
      throw new Error('InvoiceSubmissionService already initialized');
    }

    this.queue = createInvoiceQueue(redisUrl);
    this.worker = createInvoiceWorker(redisUrl, this.handleJobComplete.bind(this));
    this.initialized = true;

    logger.info('InvoiceSubmissionService initialized');
  }

  /**
   * Submit an invoice for processing
   */
  async submitInvoice(data: InvoiceJobData): Promise<string> {
    if (!this.queue) {
      throw new Error('InvoiceSubmissionService not initialized');
    }

    const job = await this.queue.add(JobType.SUBMIT_TO_FINA, data);

    logger.info({
      invoiceId: data.invoiceId,
      jobId: job.id,
    }, 'Invoice submitted to queue');

    return job.id!;
  }

  /**
   * Handle job completion - update invoice status in database
   */
  private async handleJobComplete(update: JobStatusUpdate): Promise<void> {
    try {
      await updateInvoiceStatus(
        update.invoiceId,
        update.status,
        update.jir
      );

      logger.info({
        invoiceId: update.invoiceId,
        status: update.status,
        jir: update.jir,
      }, 'Invoice status updated in database');
    } catch (error) {
      logger.error({
        invoiceId: update.invoiceId,
        error: error instanceof Error ? error.message : String(error),
      }, 'Failed to update invoice status');
    }
  }

  /**
   * Get job count by state
   */
  async getJobCounts(): Promise<{
    active: number;
    waiting: number;
    completed: number;
    failed: number;
  }> {
    if (!this.queue) {
      throw new Error('InvoiceSubmissionService not initialized');
    }

    const [active, waiting, completed, failed] = await Promise.all([
      this.queue.getActiveCount(),
      this.queue.getWaitingCount(),
      this.queue.getCompletedCount(),
      this.queue.getFailedCount(),
    ]);

    return { active, waiting, completed, failed };
  }

  /**
   * Shutdown the service
   */
  async shutdown(): Promise<void> {
    if (this.worker) {
      await this.worker.close();
      this.worker = null;
    }

    if (this.queue) {
      await this.queue.close();
      this.queue = null;
    }

    this.initialized = false;
    logger.info('InvoiceSubmissionService shut down');
  }
}

// Singleton instance
let serviceInstance: InvoiceSubmissionService | null = null;

/**
 * Get the invoice submission service instance
 */
export function getInvoiceSubmissionService(): InvoiceSubmissionService {
  if (!serviceInstance) {
    serviceInstance = new InvoiceSubmissionService();
  }
  return serviceInstance;
}

/**
 * Initialize the invoice submission service
 */
export function initializeInvoiceSubmission(redisUrl: string): void {
  const service = getInvoiceSubmissionService();
  service.initialize(redisUrl);
}

/**
 * Submit an invoice for async processing
 */
export async function submitInvoiceForProcessing(data: InvoiceJobData): Promise<string> {
  const service = getInvoiceSubmissionService();
  return service.submitInvoice(data);
}

/**
 * Reset the singleton instance (for testing only)
 */
export function resetInvoiceSubmissionService(): void {
  serviceInstance = null;
}
