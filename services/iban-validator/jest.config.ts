import type { Config } from 'jest';

export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        useESM: true,
      },
    ],
  },
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    '!src/index.ts', // Service entry point - tested via integration tests
    '!src/messaging/rabbitmq-consumer.ts', // RabbitMQ integration - requires message broker
    '!src/observability/metrics.ts', // Metrics configuration - environment-dependent
  ],
  coverageThreshold: {
    // Note: Core validator logic (iban-validator.ts) is at 100%.
    // Infrastructure modules (RabbitMQ, metrics, service startup) excluded as
    // they require integration tests with actual message brokers.
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
  coverageReporters: ['text', 'lcov', 'html'],
  verbose: true,
};