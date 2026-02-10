import { type Request, type Response, type NextFunction } from 'express';
import type { ZodSchema } from 'zod';
import { logger } from '../../shared/logger.js';
import { ValidationError, buildErrorResponse } from '../errors.js';

export function validationMiddleware(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const errors = result.error.errors.map((e) => ({
        field: e.path.join('.'),
        message: e.message,
      }));

      logger.warn({
        errors,
        requestId: req.id,
      }, 'Validation failed');

      const validationError = new ValidationError('Validation failed', errors);
      const errorResponse = buildErrorResponse(validationError, req.id, 400);

      res.status(400).json(errorResponse);
      return;
    }

    // Attach validated data to request
    (req as any).validatedBody = result.data;
    next();
  };
}
