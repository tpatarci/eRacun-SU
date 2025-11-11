/**
 * Jest Test Setup
 *
 * Global test configuration and mocks
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent'; // Suppress logs during tests
process.env.SERVICE_NAME = 'notification-service-test';

// Mock environment variables
process.env.SMTP_HOST = 'smtp.test.com';
process.env.SMTP_PORT = '587';
process.env.SMTP_USER = 'test@eracun.hr';
process.env.SMTP_PASSWORD = 'test-password';
process.env.SMTP_FROM = 'test@eracun.hr';

process.env.TWILIO_ACCOUNT_SID = 'ACtest123';
process.env.TWILIO_AUTH_TOKEN = 'test-token';
process.env.TWILIO_FROM_NUMBER = '+385911234567';

process.env.POSTGRES_HOST = 'localhost';
process.env.POSTGRES_PORT = '5432';
process.env.POSTGRES_DB = 'eracun_test';
process.env.POSTGRES_USER = 'test';
process.env.POSTGRES_PASSWORD = 'test';

process.env.RABBITMQ_URL = 'amqp://localhost:5672';
process.env.NOTIFICATION_QUEUE = 'notifications.send.test';

// Global test timeout
jest.setTimeout(10000);

// Clean up after all tests
afterAll(async () => {
  // Allow async cleanup to complete
  await new Promise((resolve) => setTimeout(resolve, 100));
});
