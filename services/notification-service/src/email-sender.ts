/**
 * Email Sender
 *
 * Handles email sending via SMTP with nodemailer.
 * Features:
 * - SMTP integration (nodemailer)
 * - Retry logic (3 attempts with exponential backoff)
 * - Rate limiting (100 emails/minute)
 * - Template support (HTML emails)
 * - Audit trail (PostgreSQL logging)
 * - Distributed tracing
 */

import nodemailer, { Transporter } from 'nodemailer';
import {
  logger,
  notificationsSentTotal,
  notificationSendDuration,
  notificationRetryAttemptsTotal,
  notificationFailuresTotal,
  withSpan,
} from './observability';
import {
  NotificationType,
  NotificationPriority,
  NotificationStatus,
  saveNotification,
  updateNotificationStatus,
} from './repository';
import { emailRateLimiter } from './rate-limiter';
import { renderEmailTemplate, TemplateVariables } from './template-engine';

// =============================================================================
// TYPES
// =============================================================================

export interface SendEmailParams {
  notification_id: string;
  recipients: string[];       // Email addresses
  subject: string;
  body: string;               // HTML content
  priority: NotificationPriority;
  template_name?: string;     // If using template
  template_vars?: TemplateVariables;
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASSWORD = process.env.SMTP_PASSWORD || '';
const SMTP_FROM = process.env.SMTP_FROM || 'noreply@eracun.hr';
const SMTP_FROM_NAME = process.env.SMTP_FROM_NAME || 'eRacun Platform';

const MAX_RETRY_ATTEMPTS = parseInt(process.env.MAX_RETRY_ATTEMPTS || '3', 10);
const RETRY_BACKOFF_BASE_MS = parseInt(process.env.RETRY_BACKOFF_BASE_MS || '1000', 10);

// =============================================================================
// SMTP TRANSPORTER
// =============================================================================

let transporter: Transporter | null = null;

/**
 * Initialize SMTP transporter
 */
export function initTransporter(): Transporter {
  if (transporter) {
    logger.warn('SMTP transporter already initialized');
    return transporter;
  }

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASSWORD,
    },
    // Connection pool
    pool: true,
    maxConnections: 10,
    maxMessages: 100,
  });

  logger.info(
    {
      smtp_host: SMTP_HOST,
      smtp_port: SMTP_PORT,
      smtp_secure: SMTP_SECURE,
      smtp_from: SMTP_FROM,
    },
    'SMTP transporter initialized'
  );

  return transporter;
}

/**
 * Get SMTP transporter (initialize if not exists)
 */
export function getTransporter(): Transporter {
  if (!transporter) {
    return initTransporter();
  }
  return transporter;
}

/**
 * Close SMTP transporter (for graceful shutdown)
 */
export async function closeTransporter(): Promise<void> {
  if (transporter) {
    transporter.close();
    transporter = null;
    logger.info('SMTP transporter closed');
  }
}

/**
 * Verify SMTP connection
 */
export async function verifyConnection(): Promise<boolean> {
  try {
    const transporter = getTransporter();
    await transporter.verify();
    logger.info('SMTP connection verified');
    return true;
  } catch (error) {
    logger.error({ error }, 'SMTP connection verification failed');
    return false;
  }
}

// =============================================================================
// EMAIL SENDING
// =============================================================================

/**
 * Send email with retry logic
 *
 * @param params - Email parameters
 * @returns true if sent successfully
 */
export async function sendEmail(params: SendEmailParams): Promise<boolean> {
  return withSpan(
    'send_email',
    {
      notification_id: params.notification_id,
      recipients_count: params.recipients.length,
      priority: params.priority,
      has_template: params.template_name ? 'true' : 'false',
    },
    async (_span) => {
      const startTime = Date.now();

      try {
        // Save notification to database (audit trail)
        await saveNotification({
          notification_id: params.notification_id,
          type: NotificationType.EMAIL,
          priority: params.priority,
          recipients: params.recipients,
          subject: params.subject,
          body: params.body,
        });

        // Render template if provided
        let htmlBody = params.body;
        if (params.template_name && params.template_vars) {
          htmlBody = renderEmailTemplate(params.template_name, params.template_vars);
        }

        // Apply rate limiting (unless CRITICAL priority)
        if (params.priority !== NotificationPriority.CRITICAL) {
          const tokenAcquired = await emailRateLimiter.waitForToken(params.priority, 60000);
          if (!tokenAcquired) {
            throw new Error('Rate limit timeout - email queue backlog');
          }
        }

        // Retry logic: 3 attempts with exponential backoff
        let lastError: Error | null = null;
        for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
          try {
            // Send email via SMTP
            const transporter = getTransporter();
            const info = await transporter.sendMail({
              from: `"${SMTP_FROM_NAME}" <${SMTP_FROM}>`,
              to: params.recipients.join(', '),
              subject: params.subject,
              html: htmlBody,
            });

            // Success!
            const duration = (Date.now() - startTime) / 1000;
            notificationSendDuration.observe({ type: 'email' }, duration);
            notificationsSentTotal.inc({
              type: 'email',
              priority: params.priority,
              status: 'success',
            });

            await updateNotificationStatus({
              notification_id: params.notification_id,
              status: NotificationStatus.SENT,
              sent_at: new Date(),
            });

            logger.info(
              {
                notification_id: params.notification_id,
                recipients_count: params.recipients.length,
                message_id: info.messageId,
                attempt,
                duration_seconds: duration,
              },
              'Email sent successfully'
            );

            return true;
          } catch (error) {
            lastError = error as Error;

            // Track retry attempt
            notificationRetryAttemptsTotal.inc({
              type: 'email',
              attempt: attempt.toString(),
            });

            logger.warn(
              {
                notification_id: params.notification_id,
                error: lastError,
                attempt,
                max_attempts: MAX_RETRY_ATTEMPTS,
              },
              'Email send failed, retrying...'
            );

            // Exponential backoff (unless last attempt)
            if (attempt < MAX_RETRY_ATTEMPTS) {
              const backoffMs = RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt - 1);
              await new Promise((resolve) => setTimeout(resolve, backoffMs));
            }
          }
        }

        // All retries exhausted - permanent failure
        throw lastError || new Error('Email send failed after all retries');
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Track failure
        notificationFailuresTotal.inc({
          type: 'email',
          reason: errorMessage.includes('Rate limit') ? 'rate_limit' : 'smtp_error',
        });

        notificationsSentTotal.inc({
          type: 'email',
          priority: params.priority,
          status: 'failed',
        });

        await updateNotificationStatus({
          notification_id: params.notification_id,
          status: NotificationStatus.FAILED,
          error_message: errorMessage,
        });

        logger.error(
          {
            notification_id: params.notification_id,
            error: errorMessage,
          },
          'Email send permanently failed'
        );

        throw error;
      }
    }
  );
}

/**
 * Send email with template
 *
 * @param params - Email parameters with template
 * @returns true if sent successfully
 */
export async function sendEmailWithTemplate(
  notification_id: string,
  recipients: string[],
  subject: string,
  template_name: string,
  template_vars: TemplateVariables,
  priority: NotificationPriority
): Promise<boolean> {
  return sendEmail({
    notification_id,
    recipients,
    subject,
    body: '', // Will be rendered from template
    priority,
    template_name,
    template_vars,
  });
}

// =============================================================================
// BATCH SENDING (for low-priority emails)
// =============================================================================

/**
 * Send batch of emails (used for daily digests)
 *
 * @param emails - Array of email parameters
 * @returns Number of successfully sent emails
 */
export async function sendBatch(emails: SendEmailParams[]): Promise<number> {
  let successCount = 0;

  logger.info({ batch_size: emails.length }, 'Starting batch email send');

  for (const email of emails) {
    try {
      const success = await sendEmail(email);
      if (success) {
        successCount++;
      }
    } catch (error) {
      // Continue with next email even if one fails
      logger.error(
        { notification_id: email.notification_id, error },
        'Email in batch failed'
      );
    }
  }

  logger.info(
    {
      batch_size: emails.length,
      success_count: successCount,
      failure_count: emails.length - successCount,
    },
    'Batch email send complete'
  );

  return successCount;
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  initTransporter,
  getTransporter,
  closeTransporter,
  verifyConnection,
  sendEmail,
  sendEmailWithTemplate,
  sendBatch,
};
