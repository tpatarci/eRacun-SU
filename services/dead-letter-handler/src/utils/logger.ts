/**
 * Structured logger using Pino
 *
 * Provides JSON-formatted logs with context propagation
 */

import pino from 'pino';

const logLevel = process.env.LOG_LEVEL || 'info';

/**
 * Create a child logger with component context
 *
 * @param component - Component name for log context
 * @returns Pino logger instance
 */
export function createLogger(component: string): pino.Logger {
  return pino({
    level: logLevel,
    formatters: {
      level: (label) => {
        return { level: label };
      },
    },
  }).child({ component });
}
