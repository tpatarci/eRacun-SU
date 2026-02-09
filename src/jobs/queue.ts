import { Queue, Worker, Job } from 'bullmq';
import { logger } from '../shared/logger.js';
import { fiscalizeInvoice } from '../fina/fina-client.js';
import type { Invoice } from '../archive/types.js';

/**
 * Invoice job data
 */
export interface InvoiceJobData {
  invoiceId: string;
  oib: string;
  invoiceNumber: string;
  originalXml: string;
  signedXml: string;
}

/**
 * Job types
 */
export enum JobType {
  SUBMIT_TO_FINA = 'submit-to-fina',
}

/**
 * Job status update
 */
export interface JobStatusUpdate {
  invoiceId: string;
  status: string;
  jir?: string;
  error?: string;
}

/**
 * Create invoice submission queue
 */
export function createInvoiceQueue(redisUrl: string): Queue<InvoiceJobData> {
  return new Queue(JobType.SUBMIT_TO_FINA, {
    connection: {
      host: redisUrl.split('://')[1]?.split(':')[0] || 'localhost',
      port: parseInt(redisUrl.split(':')[2] || '6379', 10),
    },
    defaultJobOptions: {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000,
      },
      removeOnComplete: {
        count: 1000,
        age: 7 * 24 * 3600, // 7 days
      },
      removeOnFail: {
        count: 5000,
        age: 30 * 24 * 3600, // 30 days
      },
    },
  });
}

/**
 * Job processor for FINA submission
 */
export async function processFinaSubmission(
  job: Job<InvoiceJobData>
): Promise<JobStatusUpdate> {
  const { invoiceId, oib, invoiceNumber, signedXml } = job.data;

  logger.info({
    invoiceId,
    jobId: job.id,
  }, 'Processing FINA submission job');

  try {
    const result = await fiscalizeInvoice({
      oib,
      invoiceNumber,
      dateTime: new Date().toISOString(),
      businessPremises: 'PP1', // TODO: get from invoice data
      cashRegister: '1', // TODO: get from invoice data
      totalAmount: '0', // TODO: get from invoice data
      signedXml,
    });

    logger.info({
      invoiceId,
      jir: result.jir,
    }, 'FINA submission successful');

    return {
      invoiceId,
      status: 'submitted',
      jir: result.jir,
    };
  } catch (error) {
    logger.error({
      invoiceId,
      error: error instanceof Error ? error.message : String(error),
    }, 'FINA submission failed');

    return {
      invoiceId,
      status: 'failed',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Create invoice submission worker
 */
export function createInvoiceWorker(
  redisUrl: string,
  onComplete?: (update: JobStatusUpdate) => Promise<void>
): Worker<InvoiceJobData, JobStatusUpdate> {
  const connection = {
    host: redisUrl.split('://')[1]?.split(':')[0] || 'localhost',
    port: parseInt(redisUrl.split(':')[2] || '6379', 10),
  };

  const worker = new Worker<InvoiceJobData, JobStatusUpdate>(
    JobType.SUBMIT_TO_FINA,
    async (job) => {
      const result = await processFinaSubmission(job);

      // Call completion callback if provided
      if (onComplete) {
        await onComplete(result);
      }

      return result;
    },
    {
      connection,
      concurrency: 5, // Process up to 5 jobs concurrently
    }
  );

  worker.on('completed', (job, result) => {
    logger.info({
      jobId: job.id,
      invoiceId: result.invoiceId,
      status: result.status,
    }, 'Job completed');
  });

  worker.on('failed', (job, error) => {
    logger.error({
      jobId: job?.id,
      error: error instanceof Error ? error.message : String(error),
    }, 'Job failed');
  });

  return worker;
}
