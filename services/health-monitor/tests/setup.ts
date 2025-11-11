/**
 * Jest Test Setup
 * Configures test environment and mocks
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce noise in tests
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/health_test';
process.env.KAFKA_BROKERS = 'localhost:9092';
process.env.RABBITMQ_MANAGEMENT_URL = 'http://localhost:15672';
process.env.NOTIFICATION_SERVICE_URL = 'http://localhost:8080';

// Set test timeouts
jest.setTimeout(30000);

// Mock console methods to reduce test output noise
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  // Keep error for debugging
};
