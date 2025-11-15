import type { Config } from 'jest';

export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@eracun/contracts$': '<rootDir>/../../shared/contracts/src/index.ts',
  },
  roots: ['<rootDir>/tests/properties'],
  testMatch: ['**/*.property.test.ts'],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      { tsconfig: '<rootDir>/tsconfig.jest.json', useESM: true },
    ],
  },
  maxWorkers: 1,
  testTimeout: 25000,
};