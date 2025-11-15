// Jest setup file
// Runs before all tests

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
process.env.JWT_SECRET = 'test-secret-key-for-testing';
process.env.BCRYPT_ROUNDS = '4'; // Faster for tests
process.env.ADMIN_PORTAL_IN_MEMORY_DB = 'true';
process.env.ADMIN_PORTAL_FORCE_IN_MEMORY_BUS = 'true';

// Mock console methods to reduce noise in test output
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};
