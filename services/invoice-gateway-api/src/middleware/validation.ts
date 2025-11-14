/**
 * Request Validation Middleware using Zod
 */

import { Request, Response, NextFunction } from 'express';
import { z, ZodError } from 'zod';
import { createError } from './error-handler';

/**
 * Validate request body against Zod schema
 */
export function validateBody<T>(schema: z.ZodType<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = createError(
          'Request validation failed',
          400,
          'VALIDATION_ERROR',
          {
            errors: error.errors.map((err) => ({
              path: err.path.join('.'),
              message: err.message,
              code: err.code,
            })),
          }
        );
        next(validationError);
      } else {
        next(error);
      }
    }
  };
}

/**
 * Validate request params against Zod schema
 */
export function validateParams<T>(schema: z.ZodType<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.params = schema.parse(req.params);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = createError(
          'Parameter validation failed',
          400,
          'VALIDATION_ERROR',
          {
            errors: error.errors.map((err) => ({
              path: err.path.join('.'),
              message: err.message,
              code: err.code,
            })),
          }
        );
        next(validationError);
      } else {
        next(error);
      }
    }
  };
}
