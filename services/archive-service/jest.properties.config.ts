import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests/properties'],
  testMatch: ['**/*.property.test.ts'],
  maxWorkers: 1,
  testTimeout: 20000,
};

export default config;
