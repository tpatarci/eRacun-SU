/**
 * Global Error Handler Middleware
 * Catches all errors and returns standardized error responses
 */

import { Request, Response, NextFunction } from 'express';
import { ErrorCode } from '@eracun/contracts';
import pino from 'pino';

const logger = pino({ name: 'error-handler' });

export interface AppError extends Error {
  statusCode?: number;
  code?: ErrorCode | string;
  details?: any;
}

export function errorHandler(
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Log error
  logger.error({
    error: {
      name: err.name,
      message: err.message,
      code: err.code,
      stack: err.stack,
    },
    requestId: req.requestId,
    path: req.path,
    method: req.method,
  }, 'Request error');

  // Determine status code
  const statusCode = err.statusCode || 500;

  // Send error response
  res.status(statusCode).json({
    error: {
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message || 'An unexpected error occurred',
      details: err.details,
      timestamp: new Date().toISOString(),
      correlationId: req.requestId,
    },
  });
}

/**
 * Create an application error
 */
export function createError(
  message: string,
  statusCode: number = 500,
  code?: ErrorCode | string,
  details?: any
): AppError {
  const error = new Error(message) as AppError;
  error.statusCode = statusCode;
  error.code = code;
  error.details = details;
  return error;
}
