/**
 * Jest Test Setup
 *
 * Global setup and teardown for all tests
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Reduce log noise during tests
process.env.DATABASE_URL =
  process.env.DATABASE_URL || 'postgresql://test:test@localhost:5432/cert_test';
process.env.USE_CONSOLE_ALERTS = 'true'; // Use console alerts in tests

// Mock external services
jest.mock('../src/alerting', () => {
  const actual = jest.requireActual('../src/alerting');
  return {
    ...actual,
    NotificationServiceClient: jest.fn().mockImplementation(() => ({
      sendAlert: jest.fn().mockResolvedValue(undefined),
      testConnection: jest.fn().mockResolvedValue(true),
    })),
  };
});

// Global test timeout
jest.setTimeout(10000);

// Suppress console errors in tests (unless debugging)
if (!process.env.DEBUG_TESTS) {
  global.console.error = jest.fn();
}
