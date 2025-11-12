/**
 * Configuration Management
 *
 * Loads configuration from /etc/eracun/services/archive-service.conf
 * with environment variable overrides.
 *
 * See: CLAUDE.md §6.1 (Deployment & Orchestration)
 */

import { z } from 'zod';

const configSchema = z.object({
  version: z.string().default('1.0.0'),
  environment: z.enum(['development', 'staging', 'production']).default('development'),

  api: z.object({
    port: z.number().default(9310),
    cors: z.object({
      enabled: z.boolean().default(true),
      origins: z.array(z.string()).default(['*']),
    }),
  }),

  postgres: z.object({
    url: z.string(),
    poolMax: z.number().default(30),
    schema: z.string().default('archive_metadata'),
  }),

  rabbitmq: z.object({
    url: z.string(),
    queue: z.string().default('archive-service.ingest'),
    exchange: z.string().default('archive.commands'),
    dlqExchange: z.string().default('archive.commands.dlq'),
    prefetch: z.number().default(10),
  }),

  storage: z.object({
    hotBucket: z.string().default('eracun-archive-hot-eu'),
    warmBucket: z.string().default('eracun-archive-warm-eu'),
    coldBucket: z.string().default('eracun-archive-cold-eu'),
    endpoint: z.string().optional(), // DigitalOcean Spaces endpoint
    region: z.string().default('eu-west-1'),
    clientSideEncryptionKey: z.string(), // Age encryption key
  }),

  validation: z.object({
    monthlyWindowDays: z.number().default(30),
    chunkSize: z.number().default(10000),
    digitalSignatureServiceUrl: z.string().default('http://localhost:9301'),
  }),

  observability: z.object({
    metricsPort: z.number().default(9310),
    logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    tracingEndpoint: z.string().optional(),
  }),
});

export type Config = z.infer<typeof configSchema>;

function loadConfig(): Config {
  // TODO: Implement configuration file loading from /etc/eracun/services/archive-service.conf
  // For now, use environment variables
  const rawConfig = {
    version: process.env.SERVICE_VERSION || '1.0.0',
    environment: process.env.NODE_ENV || 'development',

    api: {
      port: parseInt(process.env.API_PORT || '9310', 10),
      cors: {
        enabled: process.env.CORS_ENABLED !== 'false',
        origins: process.env.CORS_ORIGINS?.split(',') || ['*'],
      },
    },

    postgres: {
      url: process.env.ARCHIVE_DATABASE_URL || '',
      poolMax: parseInt(process.env.PG_POOL_MAX || '30', 10),
      schema: process.env.PG_SCHEMA || 'archive_metadata',
    },

    rabbitmq: {
      url: process.env.RABBITMQ_URL || '',
      queue: process.env.RABBITMQ_QUEUE || 'archive-service.ingest',
      exchange: process.env.RABBITMQ_EXCHANGE || 'archive.commands',
      dlqExchange: process.env.RABBITMQ_DLQ_EXCHANGE || 'archive.commands.dlq',
      prefetch: parseInt(process.env.RABBITMQ_PREFETCH || '10', 10),
    },

    storage: {
      hotBucket: process.env.STORAGE_HOT_BUCKET || 'eracun-archive-hot-eu',
      warmBucket: process.env.STORAGE_WARM_BUCKET || 'eracun-archive-warm-eu',
      coldBucket: process.env.STORAGE_COLD_BUCKET || 'eracun-archive-cold-eu',
      endpoint: process.env.STORAGE_ENDPOINT,
      region: process.env.STORAGE_REGION || 'eu-west-1',
      clientSideEncryptionKey: process.env.ARCHIVE_ENVELOPE_KEY || '',
    },

    validation: {
      monthlyWindowDays: parseInt(process.env.VALIDATION_WINDOW_DAYS || '30', 10),
      chunkSize: parseInt(process.env.VALIDATION_CHUNK_SIZE || '10000', 10),
      digitalSignatureServiceUrl: process.env.DIGITAL_SIGNATURE_SERVICE_URL || 'http://localhost:9301',
    },

    observability: {
      metricsPort: parseInt(process.env.METRICS_PORT || '9310', 10),
      logLevel: (process.env.LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error') || 'info',
      tracingEndpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
    },
  };

  return configSchema.parse(rawConfig);
}

export const config = loadConfig();
