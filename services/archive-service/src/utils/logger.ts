/**
 * Structured Logging with Pino
 *
 * JSON-formatted logs with request ID correlation.
 * See: CLAUDE.md §3.2 (Reliability Patterns)
 */

import pino from 'pino';
import { config } from '../config';

export function createLogger(name: string): pino.Logger {
  return pino({
    name,
    level: config.observability.logLevel,
    formatters: {
      level: (label) => {
        return { level: label };
      },
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    ...(config.environment === 'development' && {
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname',
        },
      },
    }),
  });
}
