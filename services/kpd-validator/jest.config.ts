import type { Config } from 'jest';
import baseConfig from '../../shared/jest-config/base.config.js';

const config: Config = {
  ...baseConfig,
  displayName: 'kpd-validator',
  moduleNameMapper: {
    ...(baseConfig.moduleNameMapper || {}),
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  collectCoverageFrom: Array.from(
    new Set([
      ...(baseConfig.collectCoverageFrom || []),
      '!src/index.ts',
      '!src/**/*.test.ts',
      '!src/**/*.spec.ts',
    ])
  ),
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};

export default config;
