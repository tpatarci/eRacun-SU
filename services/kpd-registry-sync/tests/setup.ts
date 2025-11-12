// Jest setup file
// Add global test configuration here

// Increase timeout for integration tests if needed
jest.setTimeout(10000);

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error'; // Suppress logs during tests
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/eracun_test';
process.env.SYNC_ON_STARTUP = 'false'; // Don't auto-sync in tests
