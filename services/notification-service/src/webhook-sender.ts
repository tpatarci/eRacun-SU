/**
 * Webhook Sender
 *
 * Handles webhook notifications via HTTP POST.
 * Features:
 * - HTTP POST client (axios)
 * - Retry logic (3 attempts with exponential backoff)
 * - Timeout handling (10 seconds)
 * - Audit trail (PostgreSQL logging)
 * - Distributed tracing
 */

import axios, { AxiosError } from 'axios';
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

// =============================================================================
// TYPES
// =============================================================================

export interface SendWebhookParams {
  notification_id: string;
  webhook_url: string;        // Target URL
  payload: Record<string, any>; // JSON payload
  priority: NotificationPriority;
  headers?: Record<string, string>; // Custom HTTP headers
}

export interface WebhookResponse {
  status_code: number;
  response_body?: any;
  duration_ms: number;
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const MAX_RETRY_ATTEMPTS = parseInt(process.env.MAX_RETRY_ATTEMPTS || '3', 10);
const RETRY_BACKOFF_BASE_MS = parseInt(process.env.RETRY_BACKOFF_BASE_MS || '1000', 10);
const WEBHOOK_TIMEOUT_MS = 10000; // 10 seconds

// =============================================================================
// WEBHOOK VALIDATION
// =============================================================================

/**
 * Validate webhook URL
 *
 * @param url - URL to validate
 * @returns true if valid
 */
function validateWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);

    // Only allow HTTP/HTTPS
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return false;
    }

    // Reject localhost/internal IPs in production
    if (process.env.NODE_ENV === 'production') {
      const hostname = parsed.hostname.toLowerCase();
      if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '0.0.0.0' ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('10.') ||
        hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
      ) {
        logger.warn({ url }, 'Webhook URL rejected - internal/localhost not allowed in production');
        return false;
      }
    }

    return true;
  } catch (error) {
    return false;
  }
}

// =============================================================================
// WEBHOOK SENDING
// =============================================================================

/**
 * Send webhook with retry logic
 *
 * @param params - Webhook parameters
 * @returns WebhookResponse
 */
export async function sendWebhook(params: SendWebhookParams): Promise<WebhookResponse> {
  return withSpan(
    'send_webhook',
    {
      notification_id: params.notification_id,
      webhook_url: params.webhook_url,
      priority: params.priority,
    },
    async (_span) => {
      const startTime = Date.now();

      try {
        // Validate webhook URL
        if (!validateWebhookUrl(params.webhook_url)) {
          throw new Error(`Invalid webhook URL: ${params.webhook_url}`);
        }

        // Save notification to database (audit trail)
        await saveNotification({
          notification_id: params.notification_id,
          type: NotificationType.WEBHOOK,
          priority: params.priority,
          recipients: [params.webhook_url], // Use URL as recipient
          subject: undefined, // Webhooks don't have subject
          body: JSON.stringify(params.payload),
          webhook_url: params.webhook_url,
        });

        // Retry logic: 3 attempts with exponential backoff
        let lastError: Error | null = null;
        let response: WebhookResponse | null = null;

        for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
          try {
            // Send HTTP POST request
            const axiosResponse = await axios.post(
              params.webhook_url,
              params.payload,
              {
                headers: {
                  'Content-Type': 'application/json',
                  'User-Agent': 'eRacun-NotificationService/1.0',
                  'X-Notification-ID': params.notification_id,
                  'X-Notification-Priority': params.priority,
                  ...params.headers,
                },
                timeout: WEBHOOK_TIMEOUT_MS,
                validateStatus: (status) => status >= 200 && status < 300, // Only 2xx is success
              }
            );

            // Success!
            const duration = (Date.now() - startTime) / 1000;
            response = {
              status_code: axiosResponse.status,
              response_body: axiosResponse.data,
              duration_ms: Date.now() - startTime,
            };

            notificationSendDuration.observe({ type: 'webhook' }, duration);
            notificationsSentTotal.inc({
              type: 'webhook',
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
                webhook_url: params.webhook_url,
                status_code: response.status_code,
                attempt,
                duration_seconds: duration,
              },
              'Webhook sent successfully'
            );

            return response;
          } catch (error) {
            lastError = error as Error;

            // Determine if error is retryable
            const isRetryable = isRetryableError(error as AxiosError);

            // Track retry attempt
            notificationRetryAttemptsTotal.inc({
              type: 'webhook',
              attempt: attempt.toString(),
            });

            logger.warn(
              {
                notification_id: params.notification_id,
                webhook_url: params.webhook_url,
                error: lastError.message,
                attempt,
                max_attempts: MAX_RETRY_ATTEMPTS,
                retryable: isRetryable,
              },
              'Webhook send failed, retrying...'
            );

            // Don't retry non-retryable errors (4xx client errors)
            if (!isRetryable) {
              logger.error(
                {
                  notification_id: params.notification_id,
                  webhook_url: params.webhook_url,
                  error: lastError.message,
                },
                'Webhook error is non-retryable (client error 4xx)'
              );
              break;
            }

            // Exponential backoff (unless last attempt)
            if (attempt < MAX_RETRY_ATTEMPTS) {
              const backoffMs = RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt - 1);
              await new Promise((resolve) => setTimeout(resolve, backoffMs));
            }
          }
        }

        // All retries exhausted or non-retryable error
        throw lastError || new Error('Webhook send failed after all retries');
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Determine failure reason
        let failureReason = 'unknown_error';
        if (error instanceof AxiosError) {
          if (error.code === 'ECONNABORTED') {
            failureReason = 'timeout';
          } else if (error.response?.status) {
            failureReason = `http_${error.response.status}`;
          } else {
            failureReason = 'network_error';
          }
        }

        // Track failure
        notificationFailuresTotal.inc({
          type: 'webhook',
          reason: failureReason,
        });

        notificationsSentTotal.inc({
          type: 'webhook',
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
            webhook_url: params.webhook_url,
            error: errorMessage,
            failure_reason: failureReason,
          },
          'Webhook send permanently failed'
        );

        throw error;
      }
    }
  );
}

/**
 * Determine if HTTP error is retryable
 *
 * @param error - Axios error
 * @returns true if retryable
 */
function isRetryableError(error: AxiosError): boolean {
  if (!error.response) {
    // Network errors (no response received) are retryable
    return true;
  }

  const status = error.response.status;

  // Retry on server errors (5xx) and specific client errors
  if (status >= 500) return true; // Server errors
  if (status === 408) return true; // Request Timeout
  if (status === 429) return true; // Too Many Requests (rate limit)

  // Don't retry on client errors (4xx)
  return false;
}

/**
 * Send batch of webhooks
 *
 * @param webhooks - Array of webhook parameters
 * @returns Number of successfully sent webhooks
 */
export async function sendBatch(webhooks: SendWebhookParams[]): Promise<number> {
  let successCount = 0;

  logger.info({ batch_size: webhooks.length }, 'Starting batch webhook send');

  for (const webhook of webhooks) {
    try {
      await sendWebhook(webhook);
      successCount++;
    } catch (error) {
      // Continue with next webhook even if one fails
      logger.error(
        { notification_id: webhook.notification_id, error },
        'Webhook in batch failed'
      );
    }
  }

  logger.info(
    {
      batch_size: webhooks.length,
      success_count: successCount,
      failure_count: webhooks.length - successCount,
    },
    'Batch webhook send complete'
  );

  return successCount;
}

/**
 * Test webhook URL (send test ping)
 *
 * @param url - Webhook URL to test
 * @returns true if webhook is reachable
 */
export async function testWebhookUrl(url: string): Promise<boolean> {
  try {
    await axios.post(
      url,
      {
        test: true,
        message: 'eRacun webhook connectivity test',
        timestamp: new Date().toISOString(),
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'eRacun-NotificationService/1.0',
        },
        timeout: 5000,
      }
    );

    logger.info({ webhook_url: url }, 'Webhook URL test successful');
    return true;
  } catch (error) {
    logger.error({ webhook_url: url, error }, 'Webhook URL test failed');
    return false;
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  sendWebhook,
  sendBatch,
  testWebhookUrl,
};
