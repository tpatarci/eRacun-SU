/**
 * Idempotency Middleware
 * Ensures duplicate requests return the same response
 */

import { Request, Response, NextFunction } from 'express';
import { Container } from 'inversify';

// In-memory idempotency store (production should use Redis)
const idempotencyStore = new Map<string, {
  response: any;
  timestamp: number;
  statusCode: number;
}>();

// Clean up old entries (older than 24 hours)
setInterval(() => {
  const now = Date.now();
  const oneDayMs = 24 * 60 * 60 * 1000;

  for (const [key, value] of idempotencyStore.entries()) {
    if (now - value.timestamp > oneDayMs) {
      idempotencyStore.delete(key);
    }
  }
}, 60 * 60 * 1000); // Run every hour

declare global {
  namespace Express {
    interface Request {
      idempotencyKey?: string;
    }
  }
}

export function idempotencyMiddleware(container: Container) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Only apply to POST requests
    if (req.method !== 'POST') {
      return next();
    }

    const idempotencyKey = req.headers['x-idempotency-key'] as string;

    // Idempotency key is required for POST requests
    if (!idempotencyKey) {
      res.status(400).json({
        error: {
          code: 'MISSING_IDEMPOTENCY_KEY',
          message: 'X-Idempotency-Key header is required for POST requests',
          timestamp: new Date().toISOString(),
          correlationId: req.requestId,
        },
      });
      return;
    }

    // Validate idempotency key format (should be UUID)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(idempotencyKey)) {
      res.status(400).json({
        error: {
          code: 'INVALID_IDEMPOTENCY_KEY',
          message: 'X-Idempotency-Key must be a valid UUID',
          timestamp: new Date().toISOString(),
          correlationId: req.requestId,
        },
      });
      return;
    }

    // Check if we've seen this idempotency key before
    const cached = idempotencyStore.get(idempotencyKey);
    if (cached) {
      // Return cached response
      res.status(cached.statusCode).json(cached.response);
      return;
    }

    // Attach idempotency key to request
    req.idempotencyKey = idempotencyKey;

    // Intercept res.json to cache the response
    const originalJson = res.json.bind(res);
    res.json = function (body: any) {
      // Cache the response
      idempotencyStore.set(idempotencyKey, {
        response: body,
        timestamp: Date.now(),
        statusCode: res.statusCode,
      });

      return originalJson(body);
    };

    next();
  };
}
