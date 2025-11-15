import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts', // Main entry point - tested via integration tests
    '!src/observability.ts', // Configuration module with environment-based branches
  ],
  coverageThreshold: {
    global: {
      branches: 79, // Environment config constants create untestable branches
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

export default config;
