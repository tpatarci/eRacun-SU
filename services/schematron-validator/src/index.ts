/**
 * Schematron Validator Service - Main Entry Point
 *
 * Bounded Context: Validation Layer
 * Responsibility: Validate UBL 2.1 invoices against Schematron business rules (Croatian CIUS)
 *
 * This service:
 * - Consumes validation commands from RabbitMQ (validation.schematron.validate)
 * - Validates XML against Schematron rules using Saxon-JS
 * - Publishes validation results to RabbitMQ (validation.schematron.completed)
 * - Exposes health endpoints (/health, /ready, /metrics)
 * - Implements TODO-008 observability requirements
 */

import http from 'http';
import amqp from 'amqplib';
import { SchematronValidator, SchematronRuleSet, ValidationStatus } from './validator.js';
import {
  initializeObservability,
  getMetricsRegistry,
  createSpan,
  logInfo,
  logError,
  logWarn,
  validationTotal,
  validationDuration
} from './observability.js';

// ============================================================================
// Configuration
// ============================================================================

const CONFIG = {
  rabbitmq: {
    url: process.env.RABBITMQ_URL || 'amqp://localhost:5672',
    queue: 'validation.schematron.validate',
    exchange: 'validation',
    routingKey: 'validation.schematron.validate',
    resultRoutingKey: 'validation.schematron.completed',
    dlq: 'validation.schematron.validate.dlq',
    prefetch: 10 // Process up to 10 messages concurrently
  },
  http: {
    port: parseInt(process.env.HTTP_PORT || '8081', 10)
  },
  prometheus: {
    port: parseInt(process.env.PROMETHEUS_PORT || '9101', 10)
  },
  rules: {
    path: process.env.SCHEMATRON_RULES_PATH || './rules'
  },
  validation: {
    timeout: parseInt(process.env.VALIDATION_TIMEOUT_MS || '10000', 10) // 10s max
  }
};

// ============================================================================
// Service State
// ============================================================================

let rabbitmqConnection: amqp.Connection | null = null;
let rabbitmqChannel: amqp.Channel | null = null;
let httpServer: http.Server | null = null;
let metricsServer: http.Server | null = null;
let validator: SchematronValidator;
let isReady = false;
let isShuttingDown = false;

// ============================================================================
// RabbitMQ Message Handling
// ============================================================================

interface ValidationMessage {
  request_id: string;
  invoice_id: string;
  xml_content: string; // base64-encoded
  rule_set: string;    // SchematronRuleSet enum value
}

/**
 * Process validation message from RabbitMQ
 */
async function processValidationMessage(msg: amqp.Message): Promise<void> {
  const startTime = Date.now();
  let requestId = 'unknown';
  let invoiceId = 'unknown';

  try {
    // Parse message
    const message: ValidationMessage = JSON.parse(msg.content.toString('utf-8'));
    requestId = message.request_id;
    invoiceId = message.invoice_id;

    logInfo({
      request_id: requestId,
      invoice_id: invoiceId,
      rule_set: message.rule_set
    }, 'Schematron validation started');

    // Create tracing span
    const span = createSpan('schematron_validation', {
      'request.id': requestId,
      'invoice.id': invoiceId,
      'rule.set': message.rule_set
    });

    try {
      // Decode XML content
      const xmlContent = Buffer.from(message.xml_content, 'base64');

      // Map rule set string to enum
      const ruleSet = message.rule_set as SchematronRuleSet;
      if (!Object.values(SchematronRuleSet).includes(ruleSet)) {
        throw new Error(`Invalid rule set: ${message.rule_set}`);
      }

      // Validate with timeout
      const result = await Promise.race([
        validator.validate(xmlContent, ruleSet),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Validation timeout')), CONFIG.validation.timeout)
        )
      ]) as Awaited<ReturnType<typeof validator.validate>>;

      // Publish result
      await publishResult(requestId, invoiceId, result);

      // Log completion
      logInfo({
        request_id: requestId,
        invoice_id: invoiceId,
        rule_set: ruleSet,
        status: result.status,
        rules_checked: result.rules_checked,
        rules_failed: result.rules_failed,
        errors_count: result.errors.length,
        warnings_count: result.warnings.length,
        duration_ms: result.validation_time_ms
      }, 'Schematron validation completed');

      // ACK message
      rabbitmqChannel?.ack(msg);

      span.setAttribute('status', result.status);
      span.setAttribute('rules_checked', result.rules_checked);
      span.setAttribute('errors_count', result.errors.length);
      span.end();

    } catch (error) {
      span.recordException(error as Error);
      span.end();
      throw error;
    }

  } catch (error) {
    const duration = Date.now() - startTime;

    logError({
      request_id: requestId,
      invoice_id: invoiceId,
      error: (error as Error).message,
      duration_ms: duration
    }, 'Schematron validation failed');

    // Record error metrics
    validationTotal.inc({ status: 'error', rule_set: 'unknown' });
    validationDuration.observe({ rule_set: 'unknown' }, duration / 1000);

    // Publish error result
    await publishErrorResult(requestId, invoiceId, error as Error);

    // NACK message and send to DLQ
    rabbitmqChannel?.nack(msg, false, false);
  }
}

/**
 * Publish validation result to RabbitMQ
 */
async function publishResult(
  requestId: string,
  invoiceId: string,
  result: Awaited<ReturnType<typeof validator.validate>>
): Promise<void> {
  if (!rabbitmqChannel) {
    throw new Error('RabbitMQ channel not initialized');
  }

  const resultMessage = {
    request_id: requestId,
    invoice_id: invoiceId,
    status: result.status,
    rules_checked: result.rules_checked,
    rules_failed: result.rules_failed,
    validation_time_ms: result.validation_time_ms,
    rule_set: result.rule_set,
    errors: result.errors,
    warnings: result.warnings,
    timestamp: new Date().toISOString()
  };

  rabbitmqChannel.publish(
    CONFIG.rabbitmq.exchange,
    CONFIG.rabbitmq.resultRoutingKey,
    Buffer.from(JSON.stringify(resultMessage)),
    {
      contentType: 'application/json',
      persistent: true,
      messageId: requestId
    }
  );

  logInfo({
    request_id: requestId,
    invoice_id: invoiceId,
    routing_key: CONFIG.rabbitmq.resultRoutingKey
  }, 'Validation result published');
}

/**
 * Publish error result to RabbitMQ
 */
async function publishErrorResult(
  requestId: string,
  invoiceId: string,
  error: Error
): Promise<void> {
  if (!rabbitmqChannel) return;

  const errorMessage = {
    request_id: requestId,
    invoice_id: invoiceId,
    status: ValidationStatus.ERROR,
    rules_checked: 0,
    rules_failed: 0,
    validation_time_ms: 0,
    errors: [{
      rule_id: 'SYSTEM_ERROR',
      severity: 'fatal',
      message: error.message,
      location: '/'
    }],
    warnings: [],
    timestamp: new Date().toISOString()
  };

  rabbitmqChannel.publish(
    CONFIG.rabbitmq.exchange,
    CONFIG.rabbitmq.resultRoutingKey,
    Buffer.from(JSON.stringify(errorMessage)),
    {
      contentType: 'application/json',
      persistent: true,
      messageId: requestId
    }
  );
}

// ============================================================================
// RabbitMQ Connection
// ============================================================================

/**
 * Connect to RabbitMQ and start consuming messages
 */
async function connectRabbitMQ(): Promise<void> {
  try {
    logInfo({ url: CONFIG.rabbitmq.url }, 'Connecting to RabbitMQ');

    // Connect
    rabbitmqConnection = await amqp.connect(CONFIG.rabbitmq.url);

    rabbitmqConnection.on('error', (error) => {
      logError({ error: error.message }, 'RabbitMQ connection error');
    });

    rabbitmqConnection.on('close', () => {
      if (!isShuttingDown) {
        logWarn({}, 'RabbitMQ connection closed, reconnecting in 5s');
        setTimeout(connectRabbitMQ, 5000);
      }
    });

    // Create channel
    rabbitmqChannel = await rabbitmqConnection.createChannel();
    rabbitmqChannel.prefetch(CONFIG.rabbitmq.prefetch);

    // Assert exchange
    await rabbitmqChannel.assertExchange(CONFIG.rabbitmq.exchange, 'topic', { durable: true });

    // Assert queue
    await rabbitmqChannel.assertQueue(CONFIG.rabbitmq.queue, {
      durable: true,
      deadLetterExchange: CONFIG.rabbitmq.exchange,
      deadLetterRoutingKey: CONFIG.rabbitmq.dlq
    });

    // Assert DLQ
    await rabbitmqChannel.assertQueue(CONFIG.rabbitmq.dlq, { durable: true });

    // Bind queue
    await rabbitmqChannel.bindQueue(
      CONFIG.rabbitmq.queue,
      CONFIG.rabbitmq.exchange,
      CONFIG.rabbitmq.routingKey
    );

    // Start consuming
    await rabbitmqChannel.consume(CONFIG.rabbitmq.queue, (msg) => {
      if (msg) {
        processValidationMessage(msg).catch((error) => {
          logError({ error: error.message }, 'Error processing message');
        });
      }
    });

    logInfo({ queue: CONFIG.rabbitmq.queue }, 'RabbitMQ consumer started');

  } catch (error) {
    logError({ error: (error as Error).message }, 'Failed to connect to RabbitMQ, retrying in 5s');
    setTimeout(connectRabbitMQ, 5000);
  }
}

// ============================================================================
// HTTP Health Endpoints
// ============================================================================

/**
 * HTTP request handler for health endpoints
 */
function handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Liveness probe: service is running
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'healthy', service: 'schematron-validator' }));
    return;
  }

  // Readiness probe: service is ready to accept traffic
  if (req.url === '/ready') {
    if (isReady) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ready',
        rabbitmq: rabbitmqChannel !== null,
        rules_loaded: validator ? Array.from(validator.getCacheStats().keys()).length > 0 : false
      }));
    } else {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'not ready',
        rabbitmq: rabbitmqChannel !== null,
        rules_loaded: false
      }));
    }
    return;
  }

  // 404 for unknown endpoints
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

/**
 * Start HTTP health server
 */
function startHttpServer(): void {
  httpServer = http.createServer(handleHttpRequest);

  httpServer.listen(CONFIG.http.port, () => {
    logInfo({ port: CONFIG.http.port }, 'HTTP health server started');
  });
}

// ============================================================================
// Prometheus Metrics Server
// ============================================================================

/**
 * HTTP request handler for Prometheus metrics
 */
async function handleMetricsRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  if (req.url === '/metrics' && req.method === 'GET') {
    res.setHeader('Content-Type', getMetricsRegistry().contentType);
    res.end(await getMetricsRegistry().metrics());
  } else {
    res.writeHead(404);
    res.end();
  }
}

/**
 * Start Prometheus metrics server
 */
function startMetricsServer(): void {
  metricsServer = http.createServer(handleMetricsRequest);

  metricsServer.listen(CONFIG.prometheus.port, () => {
    logInfo({ port: CONFIG.prometheus.port }, 'Prometheus metrics server started');
  });
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

/**
 * Graceful shutdown handler
 */
async function shutdown(signal: string): Promise<void> {
  logInfo({ signal }, 'Shutdown signal received');
  isShuttingDown = true;
  isReady = false;

  // Stop accepting new messages
  if (rabbitmqChannel) {
    await rabbitmqChannel.close();
  }

  if (rabbitmqConnection) {
    await rabbitmqConnection.close();
  }

  // Close HTTP servers
  if (httpServer) {
    httpServer.close();
  }

  if (metricsServer) {
    metricsServer.close();
  }

  logInfo({}, 'Shutdown complete');
  process.exit(0);
}

// Register shutdown handlers
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// ============================================================================
// Service Initialization
// ============================================================================

/**
 * Initialize and start service
 */
async function main(): Promise<void> {
  try {
    logInfo({}, 'Starting schematron-validator service');

    // Initialize observability
    initializeObservability();

    // Initialize validator
    validator = new SchematronValidator(CONFIG.rules.path);

    // Pre-load Croatian CIUS rules (most common rule set)
    try {
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);
      logInfo({ rule_set: SchematronRuleSet.CIUS_HR_CORE }, 'Pre-loaded Schematron rules');
      isReady = true;
    } catch (error) {
      logWarn({
        error: (error as Error).message
      }, 'Failed to pre-load rules, will load on-demand');
      // Service can still start, rules will load on first validation
      isReady = true;
    }

    // Start HTTP health server
    startHttpServer();

    // Start Prometheus metrics server
    startMetricsServer();

    // Connect to RabbitMQ
    await connectRabbitMQ();

    logInfo({
      http_port: CONFIG.http.port,
      prometheus_port: CONFIG.prometheus.port,
      rabbitmq_queue: CONFIG.rabbitmq.queue
    }, 'schematron-validator service started successfully');

  } catch (error) {
    logError({ error: (error as Error).message }, 'Failed to start service');
    process.exit(1);
  }
}

// Start service
main().catch((error) => {
  logError({ error: error.message }, 'Unhandled error during startup');
  process.exit(1);
});
