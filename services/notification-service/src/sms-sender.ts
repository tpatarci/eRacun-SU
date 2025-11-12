/**
 * SMS Sender
 *
 * Handles SMS sending via Twilio API.
 * Features:
 * - Twilio integration
 * - Rate limiting (10 SMS/minute to prevent carrier throttling)
 * - Priority bypass (CRITICAL messages skip rate limit)
 * - Retry logic (3 attempts with exponential backoff)
 * - Template support (plain text SMS)
 * - Audit trail (PostgreSQL logging)
 * - Distributed tracing
 */

import Twilio from 'twilio';
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
import { smsRateLimiter } from './rate-limiter';
import { renderSMSTemplate, TemplateVariables } from './template-engine';

// =============================================================================
// TYPES
// =============================================================================

export interface SendSMSParams {
  notification_id: string;
  recipients: string[];       // Phone numbers in E.164 format (+385...)
  message: string;            // Plain text message (max 160 chars)
  priority: NotificationPriority;
  template_name?: string;     // If using template
  template_vars?: TemplateVariables;
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const TWILIO_FROM_NUMBER = process.env.TWILIO_FROM_NUMBER || '';

const MAX_RETRY_ATTEMPTS = parseInt(process.env.MAX_RETRY_ATTEMPTS || '3', 10);
const RETRY_BACKOFF_BASE_MS = parseInt(process.env.RETRY_BACKOFF_BASE_MS || '1000', 10);

const SMS_MAX_LENGTH = 160; // Standard SMS length

// =============================================================================
// TWILIO CLIENT
// =============================================================================

let twilioClient: Twilio.Twilio | null = null;

/**
 * Initialize Twilio client
 */
export function initTwilioClient(): Twilio.Twilio {
  if (twilioClient) {
    logger.warn('Twilio client already initialized');
    return twilioClient;
  }

  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN) {
    logger.error('Twilio credentials not configured');
    throw new Error('Twilio credentials not configured (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)');
  }

  twilioClient = Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

  logger.info(
    {
      account_sid: TWILIO_ACCOUNT_SID.substring(0, 10) + '...',
      from_number: TWILIO_FROM_NUMBER,
    },
    'Twilio client initialized'
  );

  return twilioClient;
}

/**
 * Get Twilio client (initialize if not exists)
 */
export function getTwilioClient(): Twilio.Twilio {
  if (!twilioClient) {
    return initTwilioClient();
  }
  return twilioClient;
}

// =============================================================================
// SMS VALIDATION
// =============================================================================

/**
 * Validate phone number format (E.164)
 *
 * @param phoneNumber - Phone number to validate
 * @returns true if valid
 */
function validatePhoneNumber(phoneNumber: string): boolean {
  // E.164 format: +[country code][number] (max 15 digits)
  const e164Regex = /^\+[1-9]\d{1,14}$/;
  return e164Regex.test(phoneNumber);
}

/**
 * Truncate message to SMS length limit
 *
 * @param message - Message to truncate
 * @returns Truncated message
 */
function truncateMessage(message: string): string {
  if (message.length <= SMS_MAX_LENGTH) {
    return message;
  }

  logger.warn(
    {
      original_length: message.length,
      truncated_length: SMS_MAX_LENGTH,
    },
    'SMS message truncated to fit length limit'
  );

  return message.substring(0, SMS_MAX_LENGTH - 3) + '...';
}

// =============================================================================
// SMS SENDING
// =============================================================================

/**
 * Send SMS to single recipient
 *
 * @param recipient - Phone number in E.164 format
 * @param message - Message text
 * @param notificationId - Notification UUID
 * @returns Twilio message SID
 */
async function sendSingleSMS(
  recipient: string,
  message: string,
  notificationId: string
): Promise<string> {
  // Validate phone number
  if (!validatePhoneNumber(recipient)) {
    throw new Error(`Invalid phone number format: ${recipient} (must be E.164 format)`);
  }

  // Truncate message if too long
  const truncatedMessage = truncateMessage(message);

  // Send via Twilio
  const client = getTwilioClient();
  const twilioMessage = await client.messages.create({
    body: truncatedMessage,
    from: TWILIO_FROM_NUMBER,
    to: recipient,
  });

  logger.debug(
    {
      notification_id: notificationId,
      recipient,
      message_sid: twilioMessage.sid,
      status: twilioMessage.status,
    },
    'SMS sent via Twilio'
  );

  return twilioMessage.sid;
}

/**
 * Send SMS with retry logic
 *
 * @param params - SMS parameters
 * @returns true if sent successfully
 */
export async function sendSMS(params: SendSMSParams): Promise<boolean> {
  return withSpan(
    'send_sms',
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
          type: NotificationType.SMS,
          priority: params.priority,
          recipients: params.recipients,
          subject: undefined, // SMS doesn't have subject
          body: params.message,
        });

        // Render template if provided
        let messageText = params.message;
        if (params.template_name && params.template_vars) {
          messageText = renderSMSTemplate(params.template_name, params.template_vars);
        }

        // Apply rate limiting (unless CRITICAL priority)
        if (params.priority !== NotificationPriority.CRITICAL) {
          const tokenAcquired = await smsRateLimiter.waitForToken(params.priority, 60000);
          if (!tokenAcquired) {
            throw new Error('Rate limit timeout - SMS queue backlog');
          }
        }

        // Send to all recipients (one by one due to Twilio API)
        const messageSids: string[] = [];
        let lastError: Error | null = null;

        for (const recipient of params.recipients) {
          // Retry logic: 3 attempts with exponential backoff
          for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
            try {
              const messageSid = await sendSingleSMS(recipient, messageText, params.notification_id);
              messageSids.push(messageSid);
              break; // Success - move to next recipient
            } catch (error) {
              lastError = error as Error;

              // Track retry attempt
              notificationRetryAttemptsTotal.inc({
                type: 'sms',
                attempt: attempt.toString(),
              });

              logger.warn(
                {
                  notification_id: params.notification_id,
                  recipient,
                  error: lastError,
                  attempt,
                  max_attempts: MAX_RETRY_ATTEMPTS,
                },
                'SMS send failed, retrying...'
              );

              // Exponential backoff (unless last attempt)
              if (attempt < MAX_RETRY_ATTEMPTS) {
                const backoffMs = RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt - 1);
                await new Promise((resolve) => setTimeout(resolve, backoffMs));
              }
            }
          }

          // If all retries failed for this recipient, throw error
          if (messageSids.length !== params.recipients.indexOf(recipient) + 1) {
            throw lastError || new Error(`SMS send failed for recipient: ${recipient}`);
          }
        }

        // Success!
        const duration = (Date.now() - startTime) / 1000;
        notificationSendDuration.observe({ type: 'sms' }, duration);
        notificationsSentTotal.inc({
          type: 'sms',
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
            message_sids: messageSids,
            duration_seconds: duration,
          },
          'SMS sent successfully to all recipients'
        );

        return true;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Track failure
        notificationFailuresTotal.inc({
          type: 'sms',
          reason: errorMessage.includes('Rate limit') ? 'rate_limit' : 'twilio_error',
        });

        notificationsSentTotal.inc({
          type: 'sms',
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
          'SMS send permanently failed'
        );

        throw error;
      }
    }
  );
}

/**
 * Send SMS with template
 *
 * @param params - SMS parameters with template
 * @returns true if sent successfully
 */
export async function sendSMSWithTemplate(
  notification_id: string,
  recipients: string[],
  template_name: string,
  template_vars: TemplateVariables,
  priority: NotificationPriority
): Promise<boolean> {
  return sendSMS({
    notification_id,
    recipients,
    message: '', // Will be rendered from template
    priority,
    template_name,
    template_vars,
  });
}

/**
 * Verify Twilio configuration
 *
 * @returns true if configured correctly
 */
export async function verifyTwilioConfig(): Promise<boolean> {
  try {
    const client = getTwilioClient();
    const account = await client.api.accounts(TWILIO_ACCOUNT_SID).fetch();

    logger.info(
      {
        account_sid: account.sid,
        account_status: account.status,
        friendly_name: account.friendlyName,
      },
      'Twilio configuration verified'
    );

    return account.status === 'active';
  } catch (error) {
    logger.error({ error }, 'Twilio configuration verification failed');
    return false;
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  initTwilioClient,
  getTwilioClient,
  sendSMS,
  sendSMSWithTemplate,
  verifyTwilioConfig,
};
