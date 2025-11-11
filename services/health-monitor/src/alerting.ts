/**
 * Alerting Module
 *
 * Sends notifications for critical health changes:
 * - P0: Critical service unhealthy, circuit breaker open >5min
 * - P1: Critical service degraded, circuit breaker just opened
 * - Publishes health events to Kafka
 * - POSTs to notification-service
 */

import axios from 'axios';
import { Kafka, Producer } from 'kafkajs';
import { logger, createSpan, setSpanError } from './observability';
import { HealthStatus, HealthCheckResult } from './health-checker';
import { CircuitBreakerInfo } from './circuit-breaker';
import { Service } from './service-registry';

// =============================================
// Configuration
// =============================================

const NOTIFICATION_SERVICE_URL =
  process.env.NOTIFICATION_SERVICE_URL || 'http://notification-service:8080';

const KAFKA_BROKERS = (process.env.KAFKA_BROKERS || 'localhost:9092').split(',');
const KAFKA_TOPIC = process.env.KAFKA_HEALTH_TOPIC || 'system-health';

// =============================================
// Types
// =============================================

export enum AlertSeverity {
  P0 = 'P0', // Critical - page immediately
  P1 = 'P1', // High - page in 15min
  P2 = 'P2', // Medium - ticket next day
}

export interface Alert {
  severity: AlertSeverity;
  service: string;
  message: string;
  timestamp_ms: number;
  metadata?: Record<string, any>;
}

// =============================================
// Kafka Producer
// =============================================

let kafkaProducer: Producer | null = null;

async function getKafkaProducer(): Promise<Producer> {
  if (!kafkaProducer) {
    const kafka = new Kafka({
      clientId: 'health-monitor-alerting',
      brokers: KAFKA_BROKERS,
    });

    kafkaProducer = kafka.producer();
    await kafkaProducer.connect();

    logger.info('Kafka producer connected for alerting');
  }

  return kafkaProducer;
}

/**
 * Publish health status event to Kafka
 * @param healthResult - Health check result
 */
export async function publishHealthEvent(healthResult: HealthCheckResult): Promise<void> {
  const span = createSpan('publish_health_event', {
    'service.name': healthResult.service_name,
    'health.status': healthResult.status,
  });

  try {
    const producer = await getKafkaProducer();

    const event = {
      service_name: healthResult.service_name,
      status: healthResult.status,
      timestamp_ms: healthResult.timestamp_ms,
      reason: healthResult.error || 'Health check completed',
      metadata: {
        latency_ms: healthResult.latency_ms,
        checks: healthResult.checks,
      },
    };

    await producer.send({
      topic: KAFKA_TOPIC,
      messages: [
        {
          key: healthResult.service_name,
          value: JSON.stringify(event),
        },
      ],
    });

    logger.debug(
      {
        service: healthResult.service_name,
        status: healthResult.status,
        topic: KAFKA_TOPIC,
      },
      'Health event published to Kafka'
    );

    span.end();
  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error(
      {
        err: error,
        service: healthResult.service_name,
      },
      'Failed to publish health event to Kafka'
    );
  }
}

/**
 * Send critical alert to notification service
 * @param alert - Alert to send
 */
export async function sendAlert(alert: Alert): Promise<void> {
  const span = createSpan('send_alert', {
    'alert.severity': alert.severity,
    'alert.service': alert.service,
  });

  try {
    await axios.post(
      `${NOTIFICATION_SERVICE_URL}/notifications`,
      {
        severity: alert.severity,
        service: alert.service,
        message: alert.message,
        timestamp: new Date(alert.timestamp_ms).toISOString(),
        metadata: alert.metadata,
      },
      {
        timeout: 5000,
      }
    );

    logger.info(
      {
        severity: alert.severity,
        service: alert.service,
        message: alert.message,
      },
      'Alert sent to notification service'
    );

    span.end();
  } catch (error) {
    setSpanError(span, error as Error);
    span.end();

    logger.error(
      {
        err: error,
        alert,
      },
      'Failed to send alert to notification service'
    );
  }
}

/**
 * Check if service health change requires alert
 * @param service - Service configuration
 * @param healthResult - Current health check result
 * @param previousStatus - Previous health status
 * @returns Alert or null
 */
export function checkHealthAlert(
  service: Service,
  healthResult: HealthCheckResult,
  previousStatus: HealthStatus | undefined
): Alert | null {
  // No alert if status unchanged
  if (previousStatus === healthResult.status) {
    return null;
  }

  // Critical service became unhealthy → P0
  if (service.critical && healthResult.status === HealthStatus.UNHEALTHY) {
    return {
      severity: AlertSeverity.P0,
      service: service.name,
      message: `CRITICAL: ${service.name} is UNHEALTHY. Immediate action required.`,
      timestamp_ms: healthResult.timestamp_ms,
      metadata: {
        previous_status: previousStatus,
        current_status: healthResult.status,
        error: healthResult.error,
        checks: healthResult.checks,
      },
    };
  }

  // Critical service became degraded → P1
  if (service.critical && healthResult.status === HealthStatus.DEGRADED) {
    return {
      severity: AlertSeverity.P1,
      service: service.name,
      message: `WARNING: ${service.name} is DEGRADED. Service functionality impaired.`,
      timestamp_ms: healthResult.timestamp_ms,
      metadata: {
        previous_status: previousStatus,
        current_status: healthResult.status,
        checks: healthResult.checks,
      },
    };
  }

  // Non-critical service alerts (P2)
  if (!service.critical && healthResult.status === HealthStatus.UNHEALTHY) {
    return {
      severity: AlertSeverity.P2,
      service: service.name,
      message: `${service.name} is UNHEALTHY. Non-critical service affected.`,
      timestamp_ms: healthResult.timestamp_ms,
      metadata: {
        previous_status: previousStatus,
        current_status: healthResult.status,
        error: healthResult.error,
      },
    };
  }

  return null;
}

/**
 * Check if circuit breaker requires alert
 * @param breaker - Circuit breaker info
 * @returns Alert or null
 */
export function checkCircuitBreakerAlert(breaker: CircuitBreakerInfo): Alert | null {
  const openDurationMs = Date.now() - breaker.last_state_change_ms;
  const FIVE_MINUTES_MS = 5 * 60 * 1000;

  // Circuit breaker open >5 minutes → P0
  if (breaker.state === 'open' && openDurationMs > FIVE_MINUTES_MS) {
    return {
      severity: AlertSeverity.P0,
      service: breaker.service,
      message: `CRITICAL: Circuit breaker '${breaker.breaker_name}' has been OPEN for ${Math.floor(openDurationMs / 60000)} minutes. Extended outage detected.`,
      timestamp_ms: Date.now(),
      metadata: {
        breaker_name: breaker.breaker_name,
        state: breaker.state,
        failure_rate: breaker.failure_rate,
        open_duration_ms: openDurationMs,
      },
    };
  }

  // Circuit breaker just opened → P1
  const ONE_MINUTE_MS = 60 * 1000;
  if (breaker.state === 'open' && openDurationMs < ONE_MINUTE_MS) {
    return {
      severity: AlertSeverity.P1,
      service: breaker.service,
      message: `WARNING: Circuit breaker '${breaker.breaker_name}' is now OPEN. Service degraded.`,
      timestamp_ms: Date.now(),
      metadata: {
        breaker_name: breaker.breaker_name,
        state: breaker.state,
        failure_rate: breaker.failure_rate,
      },
    };
  }

  return null;
}

/**
 * Disconnect Kafka producer (for graceful shutdown)
 */
export async function disconnectKafka(): Promise<void> {
  if (kafkaProducer) {
    await kafkaProducer.disconnect();
    kafkaProducer = null;
    logger.info('Kafka producer disconnected');
  }
}
