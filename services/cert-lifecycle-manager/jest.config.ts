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
    '!src/observability.ts', // Configuration module with environment-based branches
  ],
  coverageThreshold: {
    // Note: Certain error handling paths in cert-parser require mocking
    // internal node-forge PKCS#12 structures which is not practical.
    // Lines 57-58, 65-66, 138 handle edge cases (empty cert bags, null certs, unknown errors)
    // These are defensive checks that would require extensive mocking to test.
    global: {
      branches: 84, // Some error handling branches require complex node-forge mocking
      functions: 100,
      lines: 92,
      statements: 92,
    },
    // Strict coverage for pure validation logic
    './src/cert-validator.ts': {
      branches: 97,
      functions: 100,
      lines: 92,
      statements: 92,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  coverageDirectory: 'coverage',
  verbose: true,
  testTimeout: 10000,
};

export default config;
