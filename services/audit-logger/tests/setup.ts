/**
 * Jest test setup
 * Runs before all tests
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce noise in test output
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgresql://test:test@localhost:5432/audit_test';
process.env.KAFKA_BROKERS = 'localhost:9092';
process.env.KAFKA_TOPIC = 'audit-log-test';
process.env.KAFKA_GROUP_ID = 'audit-logger-test-group';
process.env.GRPC_PORT = '50052'; // Different port for tests
process.env.HTTP_PORT = '8081';  // Different port for tests

// Increase test timeout for integration tests
jest.setTimeout(30000);

// Mock console methods to reduce test noise
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};
