import type { Config } from 'jest';
import baseConfig from '../../shared/jest-config/base.config.js';

const config: Config = {
  ...baseConfig,
  displayName: 'digital-signature-service',
  moduleNameMapper: {
    ...(baseConfig.moduleNameMapper || {}),
    '^@eracun/contracts$': '<rootDir>/../../shared/contracts/src/index.ts',
    '^memfs$': '<rootDir>/../../shared/test-doubles/memfs.ts',
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
    new Set([...(baseConfig.collectCoverageFrom || []), '!src/index.ts'])
  ),
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};

export default config;
