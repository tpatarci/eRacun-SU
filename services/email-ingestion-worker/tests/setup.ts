/**
 * Jest Test Setup
 *
 * Global test configuration and setup/teardown hooks.
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent'; // Suppress logs during tests

// Mock environment variables
process.env.IMAP_USER = 'test@example.com';
process.env.IMAP_PASSWORD = 'test-password';
process.env.IMAP_HOST = 'imap.example.com';
process.env.IMAP_PORT = '993';
process.env.IMAP_TLS = 'true';

process.env.RABBITMQ_URL = 'amqp://localhost:5672';
process.env.RABBITMQ_EXCHANGE = 'test.exchange';
process.env.RABBITMQ_ROUTING_KEY = 'test.routing.key';

process.env.DB_HOST = 'localhost';
process.env.DB_PORT = '5432';
process.env.DB_NAME = 'test_eracun';
process.env.DB_USER = 'test_user';
process.env.DB_PASSWORD = 'test_password';

process.env.EMAIL_POLL_SCHEDULE = '*/1 * * * *';
process.env.EMAIL_MAILBOX = 'INBOX';
process.env.EMAIL_BATCH_SIZE = '10';

process.env.METRICS_PORT = '9091';

// Global test timeout
jest.setTimeout(10000);

// Cleanup after each test
afterEach(() => {
  jest.clearAllMocks();
});
