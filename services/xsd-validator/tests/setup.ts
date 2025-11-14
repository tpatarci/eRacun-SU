/**
 * Jest test setup
 * Runs before all tests
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent'; // Silence logs during tests
process.env.RABBITMQ_URL = 'amqp://localhost:5672';
process.env.SCHEMA_PATH = './tests/fixtures/schemas';

type ManualMock = ((...args: unknown[]) => void) & { mock: { calls: unknown[][] } };

function createManualMock(): ManualMock {
  const calls: unknown[][] = [];
  const fn = ((...args: unknown[]) => {
    calls.push(args);
  }) as ManualMock;
  fn.mock = { calls };
  return fn;
}

const jestLike = (globalThis as any).jest;
const createSpy: () => ManualMock = jestLike?.fn ?? createManualMock;

// Mock console methods to keep test output clean
global.console = {
  ...console,
  log: createSpy(),
  debug: createSpy(),
  info: createSpy(),
  warn: createSpy(),
  error: createSpy(),
};
