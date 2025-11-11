/**
 * Jest Test Setup
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
process.env.SERVICE_NAME = 'retry-scheduler-test';

process.env.POSTGRES_HOST = 'localhost';
process.env.POSTGRES_PORT = '5432';
process.env.POSTGRES_DB = 'eracun_test';
process.env.POSTGRES_USER = 'test';
process.env.POSTGRES_PASSWORD = 'test';

process.env.RABBITMQ_URL = 'amqp://localhost:5672';
process.env.RETRY_QUEUE = 'retry.scheduled.test';

jest.setTimeout(10000);

afterAll(async () => {
  await new Promise((resolve) => setTimeout(resolve, 100));
});
