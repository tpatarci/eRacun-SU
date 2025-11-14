/**
 * Type definitions for Dead Letter Handler Service
 *
 * See: README.md for complete specification
 */

export enum ErrorClassification {
  TRANSIENT = 'TRANSIENT',       // Network, timeout, resource exhaustion
  BUSINESS = 'BUSINESS',          // Validation failure, business rule violation
  TECHNICAL = 'TECHNICAL',        // Programming error, null pointer, type mismatch
  UNKNOWN = 'UNKNOWN',            // Cannot classify
}

export interface DLQMessage {
  original_message: Buffer;       // Original message payload
  original_routing_key: string;   // Where it was going
  original_queue: string;         // Queue it failed from
  error: {
    reason: string;               // Error message
    exception: string;            // Stack trace
    timestamp: number;            // When it failed
  };
  headers: {
    'x-death': Array<{            // RabbitMQ death header
      count: number;              // Retry attempts
      reason: string;             // rejection/expired/maxlen
      queue: string;
      time: Date;
    }>;
    'x-first-death-reason': string;
    'x-first-death-queue': string;
    'x-first-death-exchange': string;
  };
}

export interface RetryMessage {
  message_id: string;             // UUID
  original_payload: Buffer;       // Original message
  original_queue: string;         // Destination queue
  error_reason: string;           // Why it failed
  retry_count: number;            // Current attempt
  max_retries: number;            // Max allowed (default 3)
  next_retry_at_ms: number;       // Scheduled retry time
  classification: ErrorClassification;
}

export interface ErrorEvent {
  error_id: string;
  invoice_id?: string;
  service_name: string;
  classification: ErrorClassification;
  error_message: string;
  timestamp_ms: number;
  retry_scheduled: boolean;
  manual_review_required: boolean;
}

export interface ManualReviewError {
  id?: number;
  error_id: string;
  invoice_id?: string;
  service_name: string;
  error_classification: ErrorClassification;
  original_message: Buffer;
  original_queue: string;
  error_reason: string;
  error_stack?: string;
  retry_count: number;
  status: 'pending' | 'in_review' | 'resolved';
  created_at?: Date;
  resolved_at?: Date;
  resolved_by?: string;
}

export interface ErrorStats {
  total_errors: number;
  by_classification: Record<ErrorClassification, number>;
  by_service: Record<string, number>;
  by_status: Record<string, number>;
  pending_count: number;
  resolved_count: number;
}

export interface DLQConfig {
  rabbitmqUrl: string;
  dlqExchange: string;
  dlqQueue: string;
  retryQueue: string;
  manualReviewQueue: string;
  maxRetries: number;
  transientRetryDelayMs: number;
}

export interface ServiceConfig {
  serviceName: string;
  nodeEnv: string;
  httpPort: number;
  prometheusPort: number;
  databaseUrl: string;
  notificationServiceUrl?: string;
  kafkaBrokers?: string;
  errorEventsTopic?: string;
  logLevel: string;
  dlq: DLQConfig;
}
