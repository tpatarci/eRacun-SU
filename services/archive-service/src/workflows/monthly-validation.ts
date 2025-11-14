/**
 * Monthly Signature Validation Workflow
 *
 * Scheduled task that re-validates all archived invoice signatures monthly.
 * Required by Croatian fiscalization law for 11-year retention period.
 *
 * Execution: 1st of every month at 02:00 UTC (systemd timer)
 * Duration: ~1-4 hours for 100,000 invoices (estimated)
 *
 * See: CLAUDE.md §5.4, ADR-004
 */

import { createLogger } from '../utils/logger';
import { ArchiveService } from '../services/archive-service';
import { createWORMStorage } from '../storage/interfaces';
import { InvoiceRepository, MockInvoiceRepository } from '../repositories/invoice-repository';

const logger = createLogger('monthly-validation');

export interface ValidationWorkflowConfig {
  /** Batch size for parallel validation (default: 100) */
  batchSize?: number;

  /** Delay between batches in ms (default: 1000) */
  batchDelayMs?: number;

  /** Maximum concurrent validations (default: 10) */
  maxConcurrency?: number;

  /** Storage type (mock or s3) */
  storageType?: 'mock' | 's3';

  /** Database connection string */
  databaseUrl?: string;

  /** Digital signature service URL */
  signatureServiceUrl?: string;
}

export interface ValidationReport {
  startTime: Date;
  endTime: Date;
  totalInvoices: number;
  validCount: number;
  invalidCount: number;
  errorCount: number;
  duration: number; // milliseconds
  errors: Array<{ invoiceId: string; error: string }>;
}

export class MonthlyValidationWorkflow {
  private archiveService: ArchiveService;
  private readonly config: Required<ValidationWorkflowConfig>;

  constructor(config: ValidationWorkflowConfig = {}) {
    this.config = {
      batchSize: config.batchSize ?? 100,
      batchDelayMs: config.batchDelayMs ?? 1000,
      maxConcurrency: config.maxConcurrency ?? 10,
      storageType: config.storageType ?? 'mock',
      databaseUrl: config.databaseUrl ?? process.env.ARCHIVE_DATABASE_URL ?? '',
      signatureServiceUrl: config.signatureServiceUrl ?? process.env.SIGNATURE_SERVICE_URL,
    };

    // Initialize storage and repository
    const storage = createWORMStorage(this.config.storageType);
    const repository = this.config.databaseUrl
      ? new InvoiceRepository(this.config.databaseUrl)
      : new MockInvoiceRepository();

    this.archiveService = new ArchiveService(
      storage,
      repository,
      this.config.signatureServiceUrl
    );
  }

  /**
   * Execute monthly validation workflow
   *
   * @returns Validation report
   */
  async execute(): Promise<ValidationReport> {
    const startTime = new Date();
    logger.info('Starting monthly signature validation workflow', {
      timestamp: startTime.toISOString(),
      batchSize: this.config.batchSize,
      maxConcurrency: this.config.maxConcurrency,
    });

    try {
      // 1. Get all invoices for monthly validation
      const invoiceIds = await this.archiveService.getInvoicesForMonthlyValidation();
      logger.info('Retrieved invoices for validation', { count: invoiceIds.length });

      if (invoiceIds.length === 0) {
        logger.info('No invoices found for monthly validation');
        return this.createEmptyReport(startTime);
      }

      // 2. Split into batches
      const batches = this.splitIntoBatches(invoiceIds, this.config.batchSize);
      logger.info('Split invoices into batches', {
        totalInvoices: invoiceIds.length,
        batches: batches.length,
        batchSize: this.config.batchSize,
      });

      // 3. Process batches sequentially with delay
      let validCount = 0;
      let invalidCount = 0;
      let errorCount = 0;
      const errors: Array<{ invoiceId: string; error: string }> = [];

      for (let i = 0; i < batches.length; i++) {
        const batch = batches[i];
        logger.info(`Processing batch ${i + 1}/${batches.length}`, { size: batch.length });

        try {
          // Process batch with concurrency limit
          const results = await this.processBatchWithConcurrency(batch);

          // Aggregate results
          for (const result of results) {
            if (result.status === 'VALID') {
              validCount++;
            } else if (result.status === 'INVALID' || result.status === 'EXPIRED') {
              invalidCount++;
            }

            // Check for errors in details
            if (result.details.error) {
              errorCount++;
              errors.push({
                invoiceId: result.invoiceId,
                error: String(result.details.error),
              });
            }
          }

          logger.info(`Batch ${i + 1} complete`, {
            valid: results.filter((r) => r.status === 'VALID').length,
            invalid: results.filter((r) => r.status !== 'VALID').length,
          });
        } catch (error) {
          logger.error(`Batch ${i + 1} failed`, { error });
          errorCount += batch.length;
          errors.push({
            invoiceId: `batch-${i + 1}`,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        }

        // Delay between batches (except last batch)
        if (i < batches.length - 1) {
          await this.delay(this.config.batchDelayMs);
        }
      }

      const endTime = new Date();
      const duration = endTime.getTime() - startTime.getTime();

      const report: ValidationReport = {
        startTime,
        endTime,
        totalInvoices: invoiceIds.length,
        validCount,
        invalidCount,
        errorCount,
        duration,
        errors: errors.slice(0, 100), // Limit errors to first 100
      };

      logger.info('Monthly validation workflow complete', {
        duration: `${(duration / 1000).toFixed(2)}s`,
        totalInvoices: report.totalInvoices,
        valid: report.validCount,
        invalid: report.invalidCount,
        errors: report.errorCount,
      });

      return report;
    } catch (error) {
      logger.error('Monthly validation workflow failed', { error });
      throw error;
    } finally {
      await this.archiveService.close();
    }
  }

  /**
   * Get validation status (for monitoring)
   *
   * @returns Current validation progress
   */
  async getStatus(): Promise<{
    running: boolean;
    startTime?: Date;
    processedCount?: number;
    totalCount?: number;
  }> {
    // TODO: Implement status tracking (requires state storage)
    return {
      running: false,
    };
  }

  /**
   * Cancel running validation (graceful shutdown)
   */
  async cancel(): Promise<void> {
    logger.info('Cancelling monthly validation workflow');
    // TODO: Implement cancellation flag
    await this.archiveService.close();
  }

  // --- Private Methods ---

  private splitIntoBatches(items: string[], batchSize: number): string[][] {
    const batches: string[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  private async processBatchWithConcurrency(
    invoiceIds: string[]
  ): Promise<Array<{ invoiceId: string; status: string; details: Record<string, unknown> }>> {
    const results: Array<{
      invoiceId: string;
      status: string;
      details: Record<string, unknown>;
    }> = [];

    // Process in chunks of maxConcurrency
    for (let i = 0; i < invoiceIds.length; i += this.config.maxConcurrency) {
      const chunk = invoiceIds.slice(i, i + this.config.maxConcurrency);

      const chunkResults = await Promise.allSettled(
        chunk.map((id) => this.archiveService.validateSignature(id))
      );

      for (let j = 0; j < chunkResults.length; j++) {
        const result = chunkResults[j];
        if (result.status === 'fulfilled') {
          results.push({
            invoiceId: result.value.invoiceId,
            status: result.value.status,
            details: result.value.details,
          });
        } else {
          results.push({
            invoiceId: chunk[j],
            status: 'INVALID',
            details: {
              error: result.reason instanceof Error ? result.reason.message : 'Unknown error',
            },
          });
        }
      }
    }

    return results;
  }

  private async delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private createEmptyReport(startTime: Date): ValidationReport {
    return {
      startTime,
      endTime: new Date(),
      totalInvoices: 0,
      validCount: 0,
      invalidCount: 0,
      errorCount: 0,
      duration: 0,
      errors: [],
    };
  }
}

/**
 * CLI entry point for systemd service
 */
export async function main(): Promise<void> {
  logger.info('Monthly validation workflow starting...');

  const workflow = new MonthlyValidationWorkflow({
    batchSize: parseInt(process.env.BATCH_SIZE ?? '100'),
    batchDelayMs: parseInt(process.env.BATCH_DELAY_MS ?? '1000'),
    maxConcurrency: parseInt(process.env.MAX_CONCURRENCY ?? '10'),
    storageType: (process.env.STORAGE_TYPE as 'mock' | 's3') ?? 'mock',
    databaseUrl: process.env.ARCHIVE_DATABASE_URL,
    signatureServiceUrl: process.env.SIGNATURE_SERVICE_URL,
  });

  try {
    const report = await workflow.execute();

    // Log final report
    logger.info('Validation report', {
      totalInvoices: report.totalInvoices,
      valid: report.validCount,
      invalid: report.invalidCount,
      errors: report.errorCount,
      duration: `${(report.duration / 1000).toFixed(2)}s`,
    });

    // Exit with error code if too many failures
    const failureRate = (report.invalidCount + report.errorCount) / report.totalInvoices;
    if (failureRate > 0.05) {
      // More than 5% failures
      logger.error('High failure rate detected', { failureRate });
      process.exit(1);
    }

    process.exit(0);
  } catch (error) {
    logger.error('Workflow failed', { error });
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch((error) => {
    logger.error('Fatal error', { error });
    process.exit(1);
  });
}
