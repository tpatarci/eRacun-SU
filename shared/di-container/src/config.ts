/**
 * Configuration Management
 * Loads configuration from environment variables
 */

import { FeatureFlags, defaultFeatureFlags, productionFeatureFlags } from '@eracun/contracts';

export interface Config {
  environment: 'development' | 'staging' | 'production';
  serviceName: string;
  port: number;
  featureFlags: FeatureFlags;

  // Message Bus
  rabbitMQ: {
    url: string;
    prefetch: number;
  };

  kafka: {
    brokers: string[];
    clientId: string;
  };

  // Database
  database: {
    url: string;
    poolSize: number;
  };

  // Redis
  redis: {
    url: string;
  };

  // Monitoring
  monitoring: {
    prometheusPort: number;
    jaegerEndpoint: string;
  };

  // Security
  security: {
    jwtSecret: string;
    certificatePath: string;
  };
}

/**
 * Load configuration from environment variables
 */
export function loadConfig(): Config {
  const environment = (process.env.ENVIRONMENT || 'development') as Config['environment'];

  // Select feature flags based on environment
  const featureFlags = environment === 'production'
    ? productionFeatureFlags
    : defaultFeatureFlags;

  return {
    environment,
    serviceName: process.env.SERVICE_NAME || 'eracun-service',
    port: parseInt(process.env.PORT || '3000', 10),
    featureFlags,

    rabbitMQ: {
      url: process.env.RABBITMQ_URL || 'amqp://localhost:5672',
      prefetch: parseInt(process.env.RABBITMQ_PREFETCH || '10', 10),
    },

    kafka: {
      brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(','),
      clientId: process.env.KAFKA_CLIENT_ID || 'eracun-service',
    },

    database: {
      url: process.env.DATABASE_URL || 'postgresql://localhost:5432/eracun',
      poolSize: parseInt(process.env.DATABASE_POOL_SIZE || '20', 10),
    },

    redis: {
      url: process.env.REDIS_URL || 'redis://localhost:6379',
    },

    monitoring: {
      prometheusPort: parseInt(process.env.PROMETHEUS_PORT || '9090', 10),
      jaegerEndpoint: process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces',
    },

    security: {
      jwtSecret: process.env.JWT_SECRET || 'development-secret-change-in-production',
      certificatePath: process.env.CERTIFICATE_PATH || '/etc/eracun/certs',
    },
  };
}
