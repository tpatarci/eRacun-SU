/**
 * Error Router
 *
 * Routes classified errors to appropriate destinations:
 * - TRANSIENT → retry-scheduler queue
 * - BUSINESS/TECHNICAL/UNKNOWN → manual review queue + notification
 *
 * See: README.md §3.2 for routing logic
 */

import { Channel } from 'amqplib';
import { v4 as uuidv4 } from 'uuid';
import { DLQMessage, ErrorClassification, RetryMessage, ErrorEvent } from './types';
import { createLogger } from './utils/logger';
import { extractServiceName, extractInvoiceId } from './classifier';
import { ManualReviewRepository } from './repository';
import {
  dlqRetriesScheduled,
  dlqManualReviewRouted,
  dlqNotificationsSent,
  dlqErrorEventsPublished,
} from './observability';

const logger = createLogger('router');

export interface RouterDependencies {
  retryChannel: Channel;
  retryQueue: string;
  manualReviewQueue: string;
  repository: ManualReviewRepository;
  maxRetries: number;
  transientRetryDelayMs: number;
  notificationServiceUrl?: string;
}

/**
 * Route DLQ message based on error classification
 *
 * @param dlqMessage - DLQ message to route
 * @param classification - Error classification
 * @param deps - Router dependencies (channels, queues, etc.)
 */
export async function routeError(
  dlqMessage: DLQMessage,
  classification: ErrorClassification,
  deps: RouterDependencies
): Promise<void> {
  const serviceName = extractServiceName(dlqMessage);
  const invoiceId = extractInvoiceId(dlqMessage);

  logger.info('Routing error', {
    classification,
    serviceName,
    invoiceId,
    originalQueue: dlqMessage.original_queue,
  });

  try {
    switch (classification) {
      case ErrorClassification.TRANSIENT:
        await routeToRetryScheduler(dlqMessage, deps);
        dlqRetriesScheduled.inc({ service: serviceName });
        break;

      case ErrorClassification.BUSINESS:
      case ErrorClassification.TECHNICAL:
      case ErrorClassification.UNKNOWN:
        await routeToManualReview(dlqMessage, classification, deps);
        dlqManualReviewRouted.inc({ classification, service: serviceName });

        // Notify for critical errors (TECHNICAL and UNKNOWN)
        if (classification === ErrorClassification.TECHNICAL || classification === ErrorClassification.UNKNOWN) {
          await sendCriticalErrorNotification(dlqMessage, classification, deps);
        }
        break;
    }

    // Publish error event (optional - if Kafka is configured)
    await publishErrorEvent(dlqMessage, classification, serviceName, invoiceId);

    logger.info('Error routed successfully', { classification, serviceName });
  } catch (error) {
    logger.error('Failed to route error', { error, classification, serviceName });
    throw error;
  }
}

/**
 * Route transient error to retry scheduler
 *
 * @param dlqMessage - DLQ message
 * @param deps - Router dependencies
 */
async function routeToRetryScheduler(
  dlqMessage: DLQMessage,
  deps: RouterDependencies
): Promise<void> {
  const retryCount = getRetryCount(dlqMessage);

  if (retryCount >= deps.maxRetries) {
    logger.warn('Max retries exceeded, routing to manual review', {
      retryCount,
      maxRetries: deps.maxRetries,
    });
    await routeToManualReview(dlqMessage, ErrorClassification.TRANSIENT, deps);
    return;
  }

  const nextRetryAt = Date.now() + deps.transientRetryDelayMs;

  const retryMessage: RetryMessage = {
    message_id: uuidv4(),
    original_payload: dlqMessage.original_message,
    original_queue: dlqMessage.original_queue,
    error_reason: dlqMessage.error.reason,
    retry_count: retryCount + 1,
    max_retries: deps.maxRetries,
    next_retry_at_ms: nextRetryAt,
    classification: ErrorClassification.TRANSIENT,
  };

  await deps.retryChannel.sendToQueue(
    deps.retryQueue,
    Buffer.from(JSON.stringify(retryMessage)),
    {
      persistent: true,
      headers: {
        'x-retry-count': retryCount + 1,
        'x-original-queue': dlqMessage.original_queue,
      },
    }
  );

  logger.info('Routed to retry scheduler', {
    retryCount: retryCount + 1,
    nextRetryAt: new Date(nextRetryAt).toISOString(),
  });
}

/**
 * Route error to manual review queue
 *
 * @param dlqMessage - DLQ message
 * @param classification - Error classification
 * @param deps - Router dependencies
 */
async function routeToManualReview(
  dlqMessage: DLQMessage,
  classification: ErrorClassification,
  deps: RouterDependencies
): Promise<void> {
  const errorId = uuidv4();
  const serviceName = extractServiceName(dlqMessage);
  const invoiceId = extractInvoiceId(dlqMessage);

  // Save to PostgreSQL for admin portal
  await deps.repository.createManualReviewError({
    error_id: errorId,
    invoice_id: invoiceId,
    service_name: serviceName,
    error_classification: classification,
    original_message: dlqMessage.original_message,
    original_queue: dlqMessage.original_queue,
    error_reason: dlqMessage.error.reason,
    error_stack: dlqMessage.error.exception,
    retry_count: getRetryCount(dlqMessage),
    status: 'pending',
  });

  // Also send to RabbitMQ manual review queue (for real-time processing)
  await deps.retryChannel.sendToQueue(
    deps.manualReviewQueue,
    Buffer.from(
      JSON.stringify({
        error_id: errorId,
        classification,
        service_name: serviceName,
        invoice_id: invoiceId,
        error_reason: dlqMessage.error.reason,
        timestamp: Date.now(),
      })
    ),
    {
      persistent: true,
      headers: {
        'x-error-classification': classification,
        'x-service-name': serviceName,
      },
    }
  );

  logger.info('Routed to manual review', {
    errorId,
    classification,
    serviceName,
    invoiceId,
  });
}

/**
 * Send critical error notification
 *
 * @param dlqMessage - DLQ message
 * @param classification - Error classification
 * @param deps - Router dependencies
 */
async function sendCriticalErrorNotification(
  dlqMessage: DLQMessage,
  classification: ErrorClassification,
  deps: RouterDependencies
): Promise<void> {
  if (!deps.notificationServiceUrl) {
    logger.warn('Notification service URL not configured, skipping notification');
    return;
  }

  const serviceName = extractServiceName(dlqMessage);
  const invoiceId = extractInvoiceId(dlqMessage);

  try {
    // Mock HTTP call (actual implementation would use axios)
    logger.warn('Critical error detected - notification would be sent', {
      classification,
      serviceName,
      invoiceId,
      errorReason: dlqMessage.error.reason.substring(0, 100),
    });

    // TODO: Implement actual HTTP call to notification service
    // await axios.post(`${deps.notificationServiceUrl}/notifications`, {
    //   type: 'CRITICAL_ERROR',
    //   severity: classification === ErrorClassification.TECHNICAL ? 'URGENT' : 'HIGH',
    //   service: serviceName,
    //   message: `Critical error in ${serviceName}: ${dlqMessage.error.reason}`,
    //   invoice_id: invoiceId,
    //   classification,
    // });

    dlqNotificationsSent.inc({ severity: classification });
  } catch (error) {
    logger.error('Failed to send notification', { error });
    // Don't throw - notification failure shouldn't block error handling
  }
}

/**
 * Publish error event to Kafka (optional)
 *
 * @param dlqMessage - DLQ message
 * @param classification - Error classification
 * @param serviceName - Service name
 * @param invoiceId - Invoice ID (if available)
 */
async function publishErrorEvent(
  dlqMessage: DLQMessage,
  classification: ErrorClassification,
  serviceName: string,
  invoiceId?: string
): Promise<void> {
  try {
    const event: ErrorEvent = {
      error_id: uuidv4(),
      invoice_id: invoiceId,
      service_name: serviceName,
      classification,
      error_message: dlqMessage.error.reason,
      timestamp_ms: Date.now(),
      retry_scheduled: classification === ErrorClassification.TRANSIENT,
      manual_review_required:
        classification === ErrorClassification.BUSINESS ||
        classification === ErrorClassification.TECHNICAL ||
        classification === ErrorClassification.UNKNOWN,
    };

    // TODO: Implement Kafka producer
    // await kafkaProducer.send({
    //   topic: 'error-events',
    //   messages: [
    //     {
    //       key: invoiceId || serviceName,
    //       value: JSON.stringify(event),
    //     },
    //   ],
    // });

    logger.debug('Error event published', { errorId: event.error_id });
    dlqErrorEventsPublished.inc({ classification, service: serviceName });
  } catch (error) {
    logger.error('Failed to publish error event', { error });
    // Don't throw - Kafka failure shouldn't block error handling
  }
}

/**
 * Extract retry count from DLQ message headers
 *
 * @param dlqMessage - DLQ message
 * @returns Retry count (0 if not found)
 */
function getRetryCount(dlqMessage: DLQMessage): number {
  if (dlqMessage.headers['x-death'] && dlqMessage.headers['x-death'].length > 0) {
    return dlqMessage.headers['x-death'][0].count || 0;
  }
  return 0;
}
