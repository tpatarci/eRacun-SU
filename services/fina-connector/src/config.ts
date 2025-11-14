import fs from 'fs';
import { logger } from './observability.js';

/**
 * TLS client authentication configuration
 */
export interface TLSConfig {
  /** Path to PEM encoded client certificate */
  certPath: string;
  /** Path to PEM encoded private key */
  keyPath: string;
  /** Optional CA bundle override */
  caPath?: string;
  /** Optional passphrase protecting the private key */
  passphrase?: string;
}

/**
 * Application configuration contract
 */
export interface AppConfig {
  port: number;
  finaWsdlUrl: string;
  finaEndpointUrl: string;
  finaTimeout: number;
  signatureServiceUrl: string;
  signatureTimeout: number;
  databaseUrl: string;
  rabbitMqUrl: string;
  fiscalizationQueueName: string;
  resultQueueName: string;
  maxRetries: number;
  offlineQueueEnabled: boolean;
  offlineQueueMaxAgeHours: number;
  retryDelaySeconds: number;
  /** Client TLS material for SOAP calls */
  tls?: TLSConfig;
}

const DEFAULT_CERT_PATH =
  '/etc/eracun/secrets/certificates/fina-demo-client.crt';
const DEFAULT_KEY_PATH =
  '/etc/eracun/secrets/certificates/fina-demo-client.key';
const DEFAULT_CA_PATH =
  '/etc/eracun/secrets/certificates/fina-root-ca.pem';

/**
 * Load configuration from environment variables
 */
export function loadConfig(): AppConfig {
  const tlsConfig = resolveTlsConfig();

  return {
    port: parseInt(process.env.PORT || '3003', 10),
    finaWsdlUrl:
      process.env.FINA_WSDL_URL ||
      'https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest?wsdl',
    finaEndpointUrl:
      process.env.FINA_ENDPOINT_URL ||
      'https://cistest.apis-it.hr:8449/FiskalizacijaServiceTest',
    finaTimeout: parseInt(process.env.FINA_TIMEOUT || '10000', 10),
    signatureServiceUrl:
      process.env.SIGNATURE_SERVICE_URL || 'http://localhost:3002',
    signatureTimeout: parseInt(process.env.SIGNATURE_TIMEOUT || '5000', 10),
    databaseUrl:
      process.env.DATABASE_URL || 'postgresql://localhost/eracun_fina',
    rabbitMqUrl: process.env.RABBITMQ_URL || 'amqp://localhost',
    fiscalizationQueueName:
      process.env.FISCALIZATION_QUEUE || 'fina.fiscalization.requests',
    resultQueueName:
      process.env.RESULT_QUEUE || 'fina.fiscalization.results',
    maxRetries: parseInt(process.env.MAX_RETRIES || '3', 10),
    offlineQueueEnabled: process.env.OFFLINE_QUEUE_ENABLED !== 'false',
    offlineQueueMaxAgeHours: parseInt(
      process.env.OFFLINE_QUEUE_MAX_AGE_HOURS || '48',
      10
    ),
    retryDelaySeconds: parseInt(process.env.RETRY_DELAY_SECONDS || '2', 10),
    tls: tlsConfig,
  };
}

function resolveTlsConfig(): TLSConfig | undefined {
  const certPath = process.env.FINA_TLS_CERT_PATH || DEFAULT_CERT_PATH;
  const keyPath = process.env.FINA_TLS_KEY_PATH || DEFAULT_KEY_PATH;
  const caPath = process.env.FINA_TLS_CA_PATH || DEFAULT_CA_PATH;
  const passphrase =
    process.env.FINA_TLS_KEY_PASSPHRASE ||
    readOptionalFile(process.env.FINA_TLS_KEY_PASSPHRASE_FILE);

  if (!pathConfigured(certPath) || !pathConfigured(keyPath)) {
    logger.warn(
      {
        certPath,
        keyPath,
      },
      'FINA TLS client certificate/key paths not configured – SOAP client will rely on default trust store only'
    );
    return undefined;
  }

  const tlsConfig: TLSConfig = {
    certPath,
    keyPath,
    passphrase,
  };

  if (pathConfigured(caPath)) {
    tlsConfig.caPath = caPath;
  }

  return tlsConfig;
}

function readOptionalFile(filePath?: string): string | undefined {
  if (!filePath) {
    return undefined;
  }

  try {
    return fs.readFileSync(filePath, 'utf-8').trim();
  } catch (error) {
    logger.warn(
      { error: (error as Error).message, filePath },
      'Unable to read TLS passphrase file'
    );
    return undefined;
  }
}

function pathConfigured(filePath?: string): boolean {
  if (!filePath) {
    return false;
  }

  try {
    return fs.existsSync(filePath);
  } catch (error) {
    logger.warn(
      { error: (error as Error).message, filePath },
      'Failed to verify TLS path'
    );
    return false;
  }
}
