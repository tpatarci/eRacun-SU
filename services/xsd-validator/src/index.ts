import 'dotenv/config';
import http from 'http';
import amqp, { Channel, Connection, ConsumeMessage } from 'amqplib';
import { XSDValidator, SchemaType } from './validator.js';
import {
  logger,
  initObservability,
  validationTotal,
  validationDuration,
  validationErrors,
  queueDepth,
  serviceUp,
  schemasLoaded,
  getMetrics,
  createSpan,
  setSpanError,
  getSamplingRate,
} from './observability.js';
import { context, trace } from '@opentelemetry/api';

/**
 * Configuration (from environment variables or defaults)
 */
const CONFIG = {
  rabbitmqUrl: process.env.RABBITMQ_URL || 'amqp://localhost:5672',
  queueName: process.env.RABBITMQ_QUEUE || 'eracun.xsd-validator.xml',
  schemaPath: process.env.SCHEMA_PATH,
  prometheusPort: parseInt(process.env.PROMETHEUS_PORT || '9100', 10),
  healthPort: parseInt(process.env.HEALTH_PORT || '8080', 10),
  maxConcurrent: parseInt(process.env.MAX_CONCURRENT || '100', 10),
};

/**
 * Service state
 */
let validator: XSDValidator;
let rabbitmqConnection: Connection | null = null;
let rabbitmqChannel: Channel | null = null;
let isShuttingDown = false;

/**
 * Process validation message from RabbitMQ
 */
async function processValidationMessage(msg: ConsumeMessage): Promise<void> {

  // Extract message content
  const messageContent = msg.content.toString();
  let requestData: any;

  try {
    requestData = JSON.parse(messageContent);
  } catch (error) {
    logger.error({ error }, 'Failed to parse message JSON');
    validationErrors.inc({ error_type: 'parse' });

    // Reject message (don't requeue - malformed JSON won't fix itself)
    rabbitmqChannel?.nack(msg, false, false);
    return;
  }

  const { context: reqContext, invoice_id, xml_content, schema_type } = requestData;
  const requestId = reqContext?.request_id || 'unknown';

  // Create OpenTelemetry span (100% sampling)
  const span = createSpan('xsd_validation', {
    'invoice.id': invoice_id || 'unknown',
    'validation.schema_type': schema_type || 'unknown',
    'request.id': requestId,
  });

  // Add span to context
  await context.with(trace.setSpan(context.active(), span), async () => {
    try {
      logger.info(
        {
          request_id: requestId,
          invoice_id,
          schema_type,
          xml_size: xml_content?.length || 0,
        },
        'Processing XSD validation request'
      );

      // Validate input
      if (!xml_content) {
        throw new Error('Missing xml_content in message');
      }

      if (!schema_type) {
        throw new Error('Missing schema_type in message');
      }

      // Map string schema type to enum
      const schemaTypeEnum = schema_type as SchemaType;

      // Start validation span
      const validateSpan = createSpan('validate_against_schema', {
        'schema.type': schemaTypeEnum,
      });

      // Perform XSD validation
      const result = await validator.validate(
        Buffer.from(xml_content, 'base64'),
        schemaTypeEnum
      );

      validateSpan.end();

      // Record metrics
      validationTotal.inc({ status: result.status.toLowerCase() });
      validationDuration.observe(
        { schema_type: schemaTypeEnum },
        result.validationTimeMs / 1000
      );

      if (result.errors.length > 0) {
        result.errors.forEach((error) => {
          validationErrors.inc({ error_type: error.code });
        });
      }

      // Log result
      logger.info(
        {
          request_id: requestId,
          invoice_id,
          duration_ms: result.validationTimeMs,
          result: result.status,
          error_count: result.errors.length,
        },
        'XSD validation completed'
      );

      // Add span attributes
      span.setAttributes({
        'validation.result': result.status,
        'validation.error_count': result.errors.length,
        'validation.duration_ms': result.validationTimeMs,
      });

      // Acknowledge message
      rabbitmqChannel?.ack(msg);

      // TODO: Publish result to downstream service (schematron-validator or invoice-state-manager)
      // For now, just log the result
      logger.debug({ invoice_id, result }, 'Would publish result to downstream');

      span.end();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      logger.error(
        {
          request_id: requestId,
          invoice_id,
          error: errorMessage,
        },
        'Validation failed with error'
      );

      validationTotal.inc({ status: 'error' });
      validationErrors.inc({ error_type: 'internal' });
      setSpanError(span, error instanceof Error ? error : new Error(errorMessage));

      // Reject message and requeue (transient errors may be retried)
      rabbitmqChannel?.nack(msg, false, true);

      span.end();
    }
  });
}

/**
 * Connect to RabbitMQ and start consuming messages
 */
async function connectRabbitMQ(): Promise<void> {
  try {
    logger.info({ url: CONFIG.rabbitmqUrl }, 'Connecting to RabbitMQ');

    rabbitmqConnection = await amqp.connect(CONFIG.rabbitmqUrl);
    rabbitmqChannel = await rabbitmqConnection.createChannel();

    // Assert queue exists
    await rabbitmqChannel.assertQueue(CONFIG.queueName, {
      durable: true,
      arguments: {
        'x-dead-letter-exchange': '',
        'x-dead-letter-routing-key': `${CONFIG.queueName}.dlq`,
        'x-message-ttl': 300000, // 5 minutes
      },
    });

    // Assert DLQ exists
    await rabbitmqChannel.assertQueue(`${CONFIG.queueName}.dlq`, {
      durable: true,
    });

    // Set prefetch (max concurrent messages)
    await rabbitmqChannel.prefetch(CONFIG.maxConcurrent);

    // Start consuming
    await rabbitmqChannel.consume(CONFIG.queueName, async (msg) => {
      if (!msg) return;

      queueDepth.inc();
      await processValidationMessage(msg);
      queueDepth.dec();
    });

    logger.info({ queue: CONFIG.queueName }, 'RabbitMQ consumer started');
  } catch (error) {
    logger.error({ error }, 'Failed to connect to RabbitMQ');
    throw error;
  }
}

/**
 * Health check endpoint
 */
function createHealthServer(): http.Server {
  const server = http.createServer(async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');

    if (req.url === '/health') {
      // Liveness probe - always returns 200 if process is running
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', service: 'xsd-validator' }));
    } else if (req.url === '/ready') {
      // Readiness probe - returns 200 if service is ready to accept traffic
      const isReady =
        validator &&
        validator.isReady() &&
        rabbitmqConnection !== null &&
        !isShuttingDown;

      if (isReady) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'ready',
            schemas_loaded: validator.getLoadedSchemas().length,
            rabbitmq_connected: rabbitmqConnection !== null,
            // IMPROVEMENT-015: Include sampling rate in ready endpoint
            observability: {
              tracing_sampling_rate: getSamplingRate(),
              tracing_sampling_percentage: Math.round(getSamplingRate() * 100),
            },
          })
        );
      } else {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            status: 'not_ready',
            schemas_loaded: validator?.getLoadedSchemas().length || 0,
            rabbitmq_connected: rabbitmqConnection !== null,
            // IMPROVEMENT-015: Include sampling rate in not-ready endpoint
            observability: {
              tracing_sampling_rate: getSamplingRate(),
              tracing_sampling_percentage: Math.round(getSamplingRate() * 100),
            },
          })
        );
      }
    } else if (req.url === '/metrics') {
      // Prometheus metrics endpoint
      try {
        const metrics = await getMetrics();
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(metrics);
      } catch (error) {
        logger.error({ error }, 'Failed to generate metrics');
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to generate metrics' }));
      }
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    }
  });

  return server;
}

/**
 * Graceful shutdown
 */
async function shutdown(signal: string): Promise<void> {
  logger.info({ signal }, 'Received shutdown signal');
  isShuttingDown = true;
  serviceUp.set(0);

  // Stop accepting new messages
  if (rabbitmqChannel) {
    try {
      await rabbitmqChannel.close();
      logger.info('RabbitMQ channel closed');
    } catch (error) {
      logger.error({ error }, 'Error closing RabbitMQ channel');
    }
  }

  if (rabbitmqConnection) {
    try {
      await rabbitmqConnection.close();
      logger.info('RabbitMQ connection closed');
    } catch (error) {
      logger.error({ error }, 'Error closing RabbitMQ connection');
    }
  }

  // Give in-flight requests time to complete
  await new Promise((resolve) => setTimeout(resolve, 5000));

  logger.info('Shutdown complete');
  process.exit(0);
}

/**
 * Main service startup
 */
async function main(): Promise<void> {
  try {
    logger.info('Starting XSD Validator Service');

    // Initialize observability
    initObservability();

    // Load XSD schemas
    logger.info({ schema_path: CONFIG.schemaPath || 'default' }, 'Loading XSD schemas');
    validator = new XSDValidator(CONFIG.schemaPath);
    await validator.loadSchemas();

    const loadedSchemas = validator.getLoadedSchemas();
    schemasLoaded.set(loadedSchemas.length);
    logger.info({ schemas: loadedSchemas }, 'XSD schemas loaded');

    // Connect to RabbitMQ
    await connectRabbitMQ();

    // Start health check server
    const healthServer = createHealthServer();
    healthServer.listen(CONFIG.healthPort, () => {
      logger.info({ port: CONFIG.healthPort }, 'Health check server listening');
    });

    logger.info('XSD Validator Service started successfully');

    // Register shutdown handlers
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    logger.fatal({ error }, 'Failed to start service');
    serviceUp.set(0);
    process.exit(1);
  }
}

// Start the service
main().catch((error) => {
  logger.fatal({ error }, 'Unhandled error in main');
  process.exit(1);
});
