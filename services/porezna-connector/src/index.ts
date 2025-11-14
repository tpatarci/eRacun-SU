/**
 * Porezna Uprava Connector Service
 *
 * Integration with Croatian Tax Authority APIs
 * Supports both real and mock implementations
 */

import { pino } from 'pino';
import type { IPoreznaClient } from './adapters/interfaces.js';
import { createMockPoreznaClient } from './adapters/mock-porezna.js';
import { createRealPoreznaClient, type PoreznaClientConfig } from './adapters/real-porezna.js';

// Logger
const logger = pino({
  name: 'porezna-connector',
  level: process.env.LOG_LEVEL || 'info',
});

// Configuration
const USE_MOCK = process.env.USE_MOCK_POREZNA === 'true';
const config: PoreznaClientConfig = {
  baseUrl: process.env.POREZNA_API_BASE_URL || 'https://api.porezna-uprava.hr/v1',
  apiKey: process.env.POREZNA_API_KEY || '',
  timeout: parseInt(process.env.POREZNA_TIMEOUT_MS || '10000', 10),
};

/**
 * Create Porezna client (mock or real)
 */
export function createPoreznaClient(useMock: boolean = USE_MOCK): IPoreznaClient {
  if (useMock) {
    logger.info('Creating MOCK Porezna client');
    return createMockPoreznaClient();
  }

  logger.info('Creating REAL Porezna client', {
    baseUrl: config.baseUrl,
  });
  return createRealPoreznaClient(config);
}

// Singleton instance
let clientInstance: IPoreznaClient | null = null;

/**
 * Get singleton Porezna client instance
 */
export function getPoreznaClient(): IPoreznaClient {
  if (!clientInstance) {
    clientInstance = createPoreznaClient();
  }
  return clientInstance;
}

// Export types and interfaces
export type { IPoreznaClient } from './adapters/interfaces.js';
export type {
  TaxReport,
  PoreznaResponse,
  VATRate,
  VATValidation,
  CompanyInfo,
  VATBreakdown,
} from './types/index.js';

// Main entry point for standalone execution
if (import.meta.url === `file://${process.argv[1]}`) {
  const client = getPoreznaClient();

  logger.info('Porezna Connector Service started', {
    mode: USE_MOCK ? 'MOCK' : 'REAL',
  });

  // Health check
  client
    .healthCheck()
    .then((healthy) => {
      logger.info('Health check result', { healthy });
    })
    .catch((error) => {
      logger.error({ error }, 'Health check failed');
    });
}
