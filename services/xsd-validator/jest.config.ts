import type { Config } from 'jest';
import baseConfig from '../../shared/jest-config/base.config.js';

const config: Config = {
  ...baseConfig,
  displayName: 'xsd-validator',
  moduleNameMapper: {
    ...(baseConfig.moduleNameMapper || {}),
    '^@eracun/contracts$': '<rootDir>/../../shared/contracts/src/index.ts',
    '^libxmljs2$': '<rootDir>/tests/mocks/libxmljs2.ts',
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: '<rootDir>/tsconfig.jest.json',
        diagnostics: false,
      },
    ],
  },
  collectCoverageFrom: Array.from(
    new Set([...(baseConfig.collectCoverageFrom || []), '!src/index.ts'])
  ),
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};

export default config;
