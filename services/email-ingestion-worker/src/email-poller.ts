/**
 * Email Poller Module
 *
 * Scheduled email inbox monitoring using cron.
 * - Periodic inbox checking
 * - Unread email detection
 * - Message processing coordination
 * - Error handling and retry logic
 */

import cron from 'node-cron';
import { ImapClient } from './imap-client';
import {
  logger,
  inboxUnreadCount,
  emailProcessingDuration,
  withSpan,
  emailPollingErrors,
  emailPollingTimeouts,
} from './observability';

/**
 * Email poller configuration
 */
export interface EmailPollerConfig {
  /** Cron expression for polling schedule (default: every 5 minutes) */
  schedule: string;
  /** Mailbox to monitor (default: INBOX) */
  mailbox: string;
  /** Maximum number of emails to process per poll */
  batchSize: number;
  /** Enable/disable polling */
  enabled: boolean;
  /** Poll timeout in milliseconds (default: 30000) */
  pollTimeoutMs: number;
}

/**
 * Email processing callback
 */
export type EmailProcessor = (uid: number) => Promise<void>;

/**
 * Email Poller - Scheduled inbox monitoring
 */
export class EmailPoller {
  private config: EmailPollerConfig;
  private imapClient: ImapClient;
  private cronJob: cron.ScheduledTask | null = null;
  private processor: EmailProcessor;
  private isPolling = false;
  private lastProcessedUid = 0;

  constructor(
    config: EmailPollerConfig,
    imapClient: ImapClient,
    processor: EmailProcessor
  ) {
    this.config = config;
    this.imapClient = imapClient;
    this.processor = processor;
  }

  /**
   * Start polling
   */
  start(): void {
    if (!this.config.enabled) {
      logger.info('Email polling is disabled');
      return;
    }

    if (this.cronJob) {
      logger.warn('Email poller already started');
      return;
    }

    logger.info(
      { schedule: this.config.schedule, mailbox: this.config.mailbox },
      'Starting email poller'
    );

    // Validate cron expression
    if (!cron.validate(this.config.schedule)) {
      throw new Error(`Invalid cron expression: ${this.config.schedule}`);
    }

    // Schedule polling job
    this.cronJob = cron.schedule(this.config.schedule, async () => {
      await this.poll();
    });

    // Run initial poll immediately
    setImmediate(() => {
      this.poll().catch((err) => {
        logger.error({ err }, 'Initial poll failed');
      });
    });

    logger.info('Email poller started successfully');
  }

  /**
   * Stop polling
   */
  stop(): void {
    if (!this.cronJob) {
      logger.warn('Email poller not started');
      return;
    }

    logger.info('Stopping email poller');
    this.cronJob.stop();
    this.cronJob = null;
    logger.info('Email poller stopped');
  }

  /**
   * Perform a single poll of the inbox
   *
   * IMPROVEMENT-002: Added timeout protection and error metrics
   */
  async poll(): Promise<void> {
    if (this.isPolling) {
      logger.debug('Poll already in progress, skipping');
      return;
    }

    this.isPolling = true;
    const endTimer = emailProcessingDuration.startTimer({ operation: 'poll' });

    try {
      // Execute poll with timeout protection
      await Promise.race([
        this.executePoll(),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error('Email poll timeout')),
            this.config.pollTimeoutMs
          )
        ),
      ]);
    } catch (err) {
      // Classify error for monitoring
      if ((err as Error).message.includes('timeout')) {
        emailPollingTimeouts.inc();
        logger.warn(
          { timeoutMs: this.config.pollTimeoutMs },
          'Email poll timed out'
        );
      } else {
        emailPollingErrors.inc({
          error_type: (err as any).code || 'unknown',
        });
        logger.error(
          { error: err, code: (err as any).code },
          'Email polling failed'
        );
      }
      // Continue - next scheduled poll will retry
    } finally {
      this.isPolling = false; // GUARANTEE: Always reset flag
      endTimer();
    }
  }

  /**
   * Extract polling logic for timeout protection
   *
   * IMPROVEMENT-002: Separated from poll() to enable Promise.race timeout
   */
  private async executePoll(): Promise<void> {
    await withSpan(
      'email.poll',
      {
        mailbox: this.config.mailbox,
        batchSize: this.config.batchSize,
      },
      async (span) => {
        logger.info({ mailbox: this.config.mailbox }, 'Starting email poll');

        // Ensure IMAP connection is established
        if (!this.imapClient.getConnectionStatus()) {
          logger.info('IMAP client not connected, attempting to connect');
          await this.imapClient.connect();
        }

        // Open mailbox
        const box = await this.imapClient.openMailbox(this.config.mailbox, false);

        // Update unread count metric
        const unreadCount = box.messages.unseen || 0;
        inboxUnreadCount.set({ mailbox: this.config.mailbox }, unreadCount);
        span.setAttribute('unread_count', unreadCount);

        logger.info(
          {
            total: box.messages.total,
            unseen: unreadCount,
            new: box.messages.new,
          },
          'Mailbox status'
        );

        if (unreadCount === 0) {
          logger.debug('No unread emails to process');
          return;
        }

        // Search for unread messages
        const uids = await this.imapClient.searchMessages(['UNSEEN']);

        if (uids.length === 0) {
          logger.debug('No unseen messages found');
          return;
        }

        // Limit batch size
        const batchUids = uids.slice(0, this.config.batchSize);
        span.setAttribute('batch_size', batchUids.length);

        logger.info(
          { total: uids.length, batch: batchUids.length },
          'Processing email batch'
        );

        // IMPROVEMENT-002: Process in controlled parallel batches (max 3 concurrent)
        const concurrencyLimit = 3;
        for (let i = 0; i < batchUids.length; i += concurrencyLimit) {
          const batch = batchUids.slice(i, i + concurrencyLimit);

          // Use Promise.allSettled to handle individual email failures
          await Promise.allSettled(
            batch.map(uid => this.processEmail(uid))
          );

          this.lastProcessedUid = Math.max(...batch);
        }

        logger.info(
          { processed: batchUids.length },
          'Email batch processing complete'
        );
      }
    );
  }

  /**
   * Process a single email by UID
   */
  private async processEmail(uid: number): Promise<void> {
    const endTimer = emailProcessingDuration.startTimer({ operation: 'process_email' });

    try {
      await withSpan(
        'email.process',
        { uid },
        async (span) => {
          logger.info({ uid }, 'Processing email');

          try {
            // Call the email processor callback
            await this.processor(uid);

            // Mark as seen after successful processing
            await this.imapClient.markAsSeen(uid);

            logger.info({ uid }, 'Email processed successfully');
            span.setAttribute('status', 'success');
          } catch (err) {
            logger.error({ err, uid }, 'Failed to process email');
            span.setAttribute('status', 'error');
            span.recordException(err as Error);
            // Don't mark as seen - will be retried on next poll
            throw err;
          }
        }
      );
    } catch (err) {
      // Error already logged in withSpan
      // Continue processing other emails
    } finally {
      endTimer();
    }
  }

  /**
   * Get polling status
   */
  isRunning(): boolean {
    return this.cronJob !== null;
  }

  /**
   * Get current configuration
   */
  getConfig(): EmailPollerConfig {
    return { ...this.config };
  }
}

/**
 * Create email poller from environment variables
 *
 * IMPROVEMENT-002: Added pollTimeoutMs configuration
 */
export function createEmailPollerFromEnv(
  imapClient: ImapClient,
  processor: EmailProcessor
): EmailPoller {
  const config: EmailPollerConfig = {
    schedule: process.env.EMAIL_POLL_SCHEDULE || '*/5 * * * *', // Every 5 minutes
    mailbox: process.env.EMAIL_MAILBOX || 'INBOX',
    batchSize: parseInt(process.env.EMAIL_BATCH_SIZE || '10', 10),
    enabled: process.env.EMAIL_POLLING_ENABLED !== 'false',
    pollTimeoutMs: parseInt(process.env.EMAIL_POLL_TIMEOUT_MS || '30000', 10), // 30 seconds
  };

  logger.info({ config }, 'Creating email poller');

  return new EmailPoller(config, imapClient, processor);
}
