/**
 * Notification Service - Main Entry Point
 *
 * Features:
 * - RabbitMQ consumer (notifications.send queue)
 * - HTTP REST API (POST /notifications)
 * - Priority-based notification routing
 * - Health check endpoints
 * - Prometheus metrics endpoint
 * - Graceful shutdown
 */

import express, { Request, Response } from 'express';
import amqp, { Channel, Connection, ConsumeMessage } from 'amqplib';
import { v4 as uuidv4 } from 'uuid';
import {
  logger,
  initTracing,
  shutdownTracing,
  getMetrics,
  serviceUp,
  notificationQueueDepth,
} from './observability';
import {
  initPool,
  closePool,
  createSchema,
  healthCheck as dbHealthCheck,
  NotificationType,
  NotificationPriority,
} from './repository';
import { startRateLimiters, stopRateLimiters } from './rate-limiter';
import { sendEmail, initTransporter, closeTransporter, verifyConnection as verifySmtp } from './email-sender';
import { sendSMS, initTwilioClient, verifyTwilioConfig } from './sms-sender';
import { sendWebhook } from './webhook-sender';

// =============================================================================
// CONFIGURATION
// =============================================================================

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8085', 10);
const PROMETHEUS_PORT = parseInt(process.env.PROMETHEUS_PORT || '9093', 10);
const RABBITMQ_URL = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
const NOTIFICATION_QUEUE = process.env.NOTIFICATION_QUEUE || 'notifications.send';
const RABBITMQ_PREFETCH = parseInt(process.env.RABBITMQ_PREFETCH || '10', 10);

// =============================================================================
// TYPES
// =============================================================================

interface NotificationRequest {
  notification_id?: string;
  type: 'email' | 'sms' | 'webhook';
  priority: 'low' | 'normal' | 'high' | 'critical';
  recipients: string[];
  subject?: string;
  body: string;
  template_name?: string;
  template_vars?: Record<string, any>;
  webhook_url?: string;
}

// =============================================================================
// STATE
// =============================================================================

let rabbitmqConnection: Connection | null = null;
let rabbitmqChannel: Channel | null = null;
let httpServer: any = null;
let isShuttingDown = false;

// =============================================================================
// NOTIFICATION PROCESSING
// =============================================================================

/**
 * Process notification request and route to appropriate sender
 *
 * @param notification - Notification request
 */
async function processNotification(notification: NotificationRequest): Promise<void> {
  // Generate notification ID if not provided
  const notificationId = notification.notification_id || uuidv4();

  logger.info(
    {
      notification_id: notificationId,
      type: notification.type,
      priority: notification.priority,
      recipients_count: notification.recipients.length,
    },
    'Processing notification'
  );

  try {
    // Route to appropriate sender based on type
    switch (notification.type) {
      case 'email':
        await sendEmail({
          notification_id: notificationId,
          recipients: notification.recipients,
          subject: notification.subject || 'eRacun Notification',
          body: notification.body,
          priority: notification.priority as NotificationPriority,
          template_name: notification.template_name,
          template_vars: notification.template_vars,
        });
        break;

      case 'sms':
        await sendSMS({
          notification_id: notificationId,
          recipients: notification.recipients,
          message: notification.body,
          priority: notification.priority as NotificationPriority,
          template_name: notification.template_name,
          template_vars: notification.template_vars,
        });
        break;

      case 'webhook':
        if (!notification.webhook_url) {
          throw new Error('webhook_url is required for webhook notifications');
        }
        await sendWebhook({
          notification_id: notificationId,
          webhook_url: notification.webhook_url,
          payload: {
            notification_id: notificationId,
            body: notification.body,
            priority: notification.priority,
            ...notification.template_vars,
          },
          priority: notification.priority as NotificationPriority,
        });
        break;

      default:
        throw new Error(`Unknown notification type: ${notification.type}`);
    }

    logger.info(
      { notification_id: notificationId, type: notification.type },
      'Notification processed successfully'
    );
  } catch (error) {
    logger.error(
      { notification_id: notificationId, error },
      'Failed to process notification'
    );
    throw error;
  }
}

// =============================================================================
// RABBITMQ CONSUMER
// =============================================================================

/**
 * Connect to RabbitMQ and start consuming messages
 */
async function startRabbitMQConsumer(): Promise<void> {
  try {
    logger.info({ rabbitmq_url: RABBITMQ_URL, queue: NOTIFICATION_QUEUE }, 'Connecting to RabbitMQ');

    // Connect to RabbitMQ
    rabbitmqConnection = await amqp.connect(RABBITMQ_URL);
    rabbitmqChannel = await rabbitmqConnection.createChannel();

    // Assert queue exists
    await rabbitmqChannel.assertQueue(NOTIFICATION_QUEUE, {
      durable: true, // Queue survives broker restart
    });

    // Set prefetch (max messages to process concurrently)
    await rabbitmqChannel.prefetch(RABBITMQ_PREFETCH);

    // Start consuming messages
    await rabbitmqChannel.consume(
      NOTIFICATION_QUEUE,
      async (msg: ConsumeMessage | null) => {
        if (!msg) return;

        try {
          // Parse message
          const notification: NotificationRequest = JSON.parse(msg.content.toString());

          // Update queue depth metric
          notificationQueueDepth.dec();

          // Process notification
          await processNotification(notification);

          // Acknowledge message
          rabbitmqChannel!.ack(msg);
        } catch (error) {
          logger.error({ error, message: msg.content.toString() }, 'Failed to process RabbitMQ message');

          // Reject message and requeue (will be retried)
          rabbitmqChannel!.nack(msg, false, true);
        }
      },
      {
        noAck: false, // Manual acknowledgment
      }
    );

    logger.info('RabbitMQ consumer started');
  } catch (error) {
    logger.error({ error }, 'Failed to start RabbitMQ consumer');
    throw error;
  }
}

/**
 * Close RabbitMQ connection
 */
async function closeRabbitMQ(): Promise<void> {
  if (rabbitmqChannel) {
    await rabbitmqChannel.close();
    rabbitmqChannel = null;
  }

  if (rabbitmqConnection) {
    await rabbitmqConnection.close();
    rabbitmqConnection = null;
  }

  logger.info('RabbitMQ connection closed');
}

// =============================================================================
// HTTP REST API
// =============================================================================

/**
 * Start HTTP API server
 */
function startHttpApi(): void {
  const app = express();

  // JSON body parser
  app.use(express.json({ limit: '1mb' }));

  // Request logging middleware
  app.use((req, res, next) => {
    logger.debug({ method: req.method, path: req.path }, 'HTTP request received');
    next();
  });

  /**
   * POST /notifications - Send notification (synchronous)
   */
  app.post('/notifications', async (req: Request, res: Response) => {
    try {
      const notification: NotificationRequest = req.body;

      // Validate required fields
      if (!notification.type || !notification.priority || !notification.recipients || !notification.body) {
        return res.status(400).json({
          error: 'Missing required fields: type, priority, recipients, body',
        });
      }

      // Process notification
      await processNotification(notification);

      res.status(200).json({
        success: true,
        notification_id: notification.notification_id || uuidv4(),
      });
    } catch (error) {
      logger.error({ error }, 'HTTP notification request failed');
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  /**
   * GET /health - Health check
   */
  app.get('/health', async (req: Request, res: Response) => {
    const dbHealthy = await dbHealthCheck();
    const smtpHealthy = await verifySmtp();

    const healthy = dbHealthy && smtpHealthy;

    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'healthy' : 'unhealthy',
      uptime_seconds: process.uptime(),
      checks: {
        database: dbHealthy ? 'ok' : 'failed',
        smtp: smtpHealthy ? 'ok' : 'failed',
      },
    });
  });

  /**
   * GET /ready - Readiness check
   */
  app.get('/ready', async (req: Request, res: Response) => {
    const dbHealthy = await dbHealthCheck();
    const ready = dbHealthy && rabbitmqChannel !== null;

    res.status(ready ? 200 : 503).json({
      status: ready ? 'ready' : 'not_ready',
      dependencies: {
        database: dbHealthy ? 'connected' : 'disconnected',
        rabbitmq: rabbitmqChannel ? 'connected' : 'disconnected',
      },
    });
  });

  /**
   * GET /metrics - Prometheus metrics
   */
  app.get('/metrics', async (req: Request, res: Response) => {
    try {
      const metrics = await getMetrics();
      res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.send(metrics);
    } catch (error) {
      logger.error({ error }, 'Failed to generate metrics');
      res.status(500).send('Failed to generate metrics');
    }
  });

  // Start HTTP server
  httpServer = app.listen(HTTP_PORT, () => {
    logger.info({ port: HTTP_PORT }, 'HTTP API server started');
  });
}

/**
 * Close HTTP API server
 */
async function closeHttpApi(): Promise<void> {
  return new Promise((resolve) => {
    if (httpServer) {
      httpServer.close(() => {
        logger.info('HTTP API server closed');
        resolve();
      });
    } else {
      resolve();
    }
  });
}

// =============================================================================
// INITIALIZATION & SHUTDOWN
// =============================================================================

/**
 * Initialize all services
 */
async function initialize(): Promise<void> {
  logger.info('Initializing notification service...');

  try {
    // Initialize tracing
    initTracing();

    // Initialize database
    initPool();
    await createSchema();

    // Initialize SMTP transporter
    initTransporter();

    // Initialize Twilio client (if configured)
    try {
      initTwilioClient();
    } catch (error) {
      logger.warn('Twilio not configured - SMS notifications will not be available');
    }

    // Start rate limiters
    startRateLimiters();

    // Start RabbitMQ consumer
    await startRabbitMQConsumer();

    // Start HTTP API
    startHttpApi();

    // Mark service as up
    serviceUp.set(1);

    logger.info('Notification service initialized successfully');
  } catch (error) {
    logger.error({ error }, 'Failed to initialize notification service');
    throw error;
  }
}

/**
 * Graceful shutdown
 */
async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress');
    return;
  }

  isShuttingDown = true;
  logger.info({ signal }, 'Shutting down notification service...');

  try {
    // Mark service as down
    serviceUp.set(0);

    // Stop accepting new HTTP requests
    await closeHttpApi();

    // Stop consuming RabbitMQ messages
    await closeRabbitMQ();

    // Stop rate limiters
    stopRateLimiters();

    // Close SMTP transporter
    await closeTransporter();

    // Close database pool
    await closePool();

    // Shutdown tracing
    await shutdownTracing();

    logger.info('Notification service shutdown complete');
    process.exit(0);
  } catch (error) {
    logger.error({ error }, 'Error during shutdown');
    process.exit(1);
  }
}

// =============================================================================
// SIGNAL HANDLERS
// =============================================================================

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception');
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  logger.fatal({ reason }, 'Unhandled promise rejection');
  shutdown('unhandledRejection');
});

// =============================================================================
// START SERVICE
// =============================================================================

initialize().catch((error) => {
  logger.fatal({ error }, 'Failed to start notification service');
  process.exit(1);
});
