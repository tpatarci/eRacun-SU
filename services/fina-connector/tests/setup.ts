import { jest } from '@jest/globals';

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';

jest.setTimeout(20000);
