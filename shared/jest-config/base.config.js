/**
 * Shared Jest Configuration for eRacun Services
 *
 * This configuration enforces 100% test coverage across all services.
 *
 * Philosophy:
 * This system handles legally binding financial documents with zero error tolerance.
 * Basic tests prove code isn't broken - 100% coverage is the bare minimum for a
 * system where failures result in:
 * - 66,360 EUR penalties for non-compliance
 * - Loss of VAT deduction rights
 * - 11-year audit liability
 * - Criminal prosecution for data destruction
 *
 * Usage:
 * In your service's jest.config.js:
 *
 * const baseConfig = require('../../shared/jest-config/base.config.js');
 * module.exports = {
 *   ...baseConfig,
 *   // Service-specific overrides if needed
 * };
 */

module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],

  // Root directory for tests
  roots: ['<rootDir>/tests', '<rootDir>/src'],

  // Test file patterns
  testMatch: ['**/tests/**/*.test.ts', '**/__tests__/**/*.test.ts', '**/?(*.)+(spec|test).ts'],

  // Coverage collection
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',          // Exclude type definitions
    '!src/**/index.ts',        // Entry points often just wire dependencies
    '!src/**/*.interface.ts',  // Interface files (no logic)
    '!src/**/*.type.ts',       // Type files (no logic)
    '!src/**/*.spec.ts',
    '!src/**/*.test.ts',
  ],

  // 100% COVERAGE REQUIRED - NON-NEGOTIABLE
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100
    }
  },

  // Coverage reporters
  coverageReporters: [
    'text',           // Console output
    'text-summary',   // Summary for CI
    'lcov',           // For coverage tools (Codecov, Coveralls)
    'html',           // HTML report for local viewing
    'json-summary'    // For CI scripts
  ],

  // Coverage directory
  coverageDirectory: '<rootDir>/coverage',

  // Module path aliases (adjust per service if needed)
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },

  // Transform settings
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: {
          strict: true,
          esModuleInterop: true,
          skipLibCheck: true,
        },
      },
    ],
  },

  // Setup files
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],

  // Fail fast on first test failure (optional, remove if you want all tests to run)
  bail: false,

  // Verbose output
  verbose: true,

  // Test timeout (10 seconds default)
  testTimeout: 10000,

  // Clear mocks between tests (prevent test pollution)
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,

  // Error on deprecated APIs
  errorOnDeprecated: true,

  // Detect open handles (prevent hanging tests)
  detectOpenHandles: true,

  // Force exit after tests complete (useful for CI)
  forceExit: true,

  // Maximum workers for parallel test execution
  maxWorkers: '50%',
};
