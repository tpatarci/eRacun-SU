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
   */
  async poll(): Promise<void> {
    if (this.isPolling) {
      logger.debug('Poll already in progress, skipping');
      return;
    }

    this.isPolling = true;
    const endTimer = emailProcessingDuration.startTimer({ operation: 'poll' });

    try {
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

          // Process emails sequentially (avoid overwhelming downstream services)
          for (const uid of batchUids) {
            await this.processEmail(uid);
          }

          logger.info({ processed: batchUids.length }, 'Email batch processing complete');
        }
      );
    } catch (err) {
      logger.error({ err }, 'Email poll failed');
      throw err;
    } finally {
      this.isPolling = false;
      endTimer();
    }
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
  };

  logger.info({ config }, 'Creating email poller');

  return new EmailPoller(config, imapClient, processor);
}
