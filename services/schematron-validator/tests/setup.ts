/**
 * Jest Test Setup
 *
 * Global configuration and utilities for test suite
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent'; // Suppress logs during tests
process.env.RABBITMQ_URL = 'amqp://localhost:5672';
process.env.HTTP_PORT = '8081';
process.env.PROMETHEUS_PORT = '9101';
process.env.JAEGER_AGENT_HOST = 'localhost';
process.env.JAEGER_AGENT_PORT = '14268';
process.env.SCHEMATRON_RULES_PATH = './tests/fixtures/schematron-rules';
process.env.VALIDATION_TIMEOUT_MS = '5000';

// Global test timeout
jest.setTimeout(10000);

// Suppress console output during tests (optional)
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};
