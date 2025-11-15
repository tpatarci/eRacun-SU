import type { Config } from 'jest';
import baseConfig from '../../shared/jest-config/base.config.js';

const config: Config = {
  ...baseConfig,
  displayName: 'xml-parser',
  moduleNameMapper: {
    ...(baseConfig.moduleNameMapper || {}),
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  collectCoverageFrom: Array.from(
    new Set([
      ...(baseConfig.collectCoverageFrom || []),
      '!src/index.ts',
      '!src/**/*.spec.ts',
      '!src/**/*.test.ts',
    ])
  ),
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};

export default config;
