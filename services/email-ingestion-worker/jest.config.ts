import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',
    '!src/observability.ts', // Configuration module
  ],
  coverageThreshold: {
    global: {
      branches: 50,
      functions: 82,
      lines: 88,
      statements: 88,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  coverageDirectory: 'coverage',
  verbose: true,
  testTimeout: 10000,
};

export default config;
