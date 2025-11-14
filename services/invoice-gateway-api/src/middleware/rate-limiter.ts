/**
 * Rate Limiting Middleware
 * Limits requests to 100 per minute per client IP
 */

import rateLimit from 'express-rate-limit';

export const rateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: {
      code: 'ERR_4004',
      message: 'Rate limit exceeded. Maximum 100 requests per minute.',
      retryAfter: 60,
      timestamp: new Date().toISOString(),
    },
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Key generator: use IP address
  keyGenerator: (req) => {
    return req.ip || req.socket.remoteAddress || 'unknown';
  },
  // Skip successful requests from rate limit
  skipSuccessfulRequests: false,
  // Skip failed requests from rate limit
  skipFailedRequests: false,
});
