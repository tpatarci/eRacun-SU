import type { Request, type Response, type NextFunction } from 'express';
import type { ZodSchema } from 'zod';
import { logger } from '../../shared/logger.js';

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

      res.status(400).json({
        error: 'Validation failed',
        errors,
        requestId: req.id,
      });
      return;
    }

    // Attach validated data to request
    (req as any).validatedBody = result.data;
    next();
  };
}
