module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',
    // Exclude integration-only modules (require PostgreSQL/RabbitMQ)
    '!src/consumer.ts',
    '!src/publisher.ts',
    '!src/scheduler.ts',
    '!src/repository.ts',
  ],
  coverageThreshold: {
    // Note: Integration modules (repository, consumer, publisher, scheduler)
    // are tested via integration tests and excluded from unit test coverage.
    // To run full coverage: RUN_INTEGRATION_TESTS=true npm run test:coverage
    global: {
      branches: 58, // Slightly lower due to tracing initialization edge cases
      functions: 60,
      lines: 60,
      statements: 60,
    },
    // Strict coverage for pure logic modules
    './src/backoff.ts': {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  coverageDirectory: 'coverage',
  verbose: true,
  testTimeout: 10000,
};
