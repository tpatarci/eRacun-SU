import type { Config } from 'jest';
import baseConfig from '../../shared/jest-config/base.config.js';

const config: Config = {
  ...baseConfig,
  displayName: 'pdf-parser',
  moduleNameMapper: {
    ...(baseConfig.moduleNameMapper || {}),
    '^amqplib$': '<rootDir>/../../shared/test-doubles/amqplib-mocks.ts',
    '^amqplib-mocks$': '<rootDir>/../../shared/test-doubles/amqplib-mocks.ts',
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: '<rootDir>/tsconfig.jest.json',
      },
    ],
  },
  collectCoverageFrom: Array.from(
    new Set([
      ...(baseConfig.collectCoverageFrom || []),
      '!src/index.ts',
      '!src/observability.ts',
    ])
  ),
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};

export default config;
