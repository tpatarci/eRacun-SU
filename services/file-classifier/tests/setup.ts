/**
 * Jest Test Setup
 *
 * Global test configuration and setup/teardown hooks.
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent'; // Suppress logs during tests

// Mock environment variables
process.env.RABBITMQ_URL = 'amqp://localhost:5672';
process.env.RABBITMQ_EXCHANGE = 'test.exchange';
process.env.RABBITMQ_OUTPUT_EXCHANGE = 'test.output.exchange';
process.env.RABBITMQ_QUEUE = 'test.queue';
process.env.RABBITMQ_ROUTING_KEY = 'test.routing.key';
process.env.RABBITMQ_PREFETCH = '10';

process.env.SUPPORTED_MIME_TYPES = 'application/pdf,application/xml,text/xml,image/jpeg,image/png';
process.env.MAX_FILE_SIZE = '10485760'; // 10 MB
process.env.MIN_FILE_SIZE = '1';

process.env.PDF_MIME_TYPES = 'application/pdf';
process.env.XML_MIME_TYPES = 'application/xml,text/xml';
process.env.IMAGE_MIME_TYPES = 'image/jpeg,image/png,image/tiff';

process.env.METRICS_PORT = '9091';

// Global test timeout
jest.setTimeout(10000);

// Cleanup after each test
afterEach(() => {
  jest.clearAllMocks();
});
