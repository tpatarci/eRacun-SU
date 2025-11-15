/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests/properties'],
  testMatch: ['**/*.property.test.ts'],
  maxWorkers: 1,
  testTimeout: 20000,
};
