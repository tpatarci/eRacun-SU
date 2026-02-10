/**
 * Base API Error class
 *
 * All API errors extend this class with a specific error code
 */
export class APIError extends Error {
  constructor(
    message: string,
    public code: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'APIError';
  }
}

/**
 * Not Found Error (404)
 *
 * Used when a requested resource cannot be found
 */
export class NotFoundError extends APIError {
  constructor(message: string, cause?: Error) {
    super(message, 'NOT_FOUND', cause);
    this.name = 'NotFoundError';
  }
}

/**
 * Validation Error (400)
 *
 * Used when request validation fails
 */
export class ValidationError extends APIError {
  constructor(message: string, public errors?: Array<{ field: string; message: string }>, cause?: Error) {
    super(message, 'VALIDATION_ERROR', cause);
    this.name = 'ValidationError';
  }
}

/**
 * Internal Server Error (500)
 *
 * Used for unexpected server errors
 */
export class InternalError extends APIError {
  constructor(message: string, cause?: Error) {
    super(message, 'INTERNAL_ERROR', cause);
    this.name = 'InternalError';
  }
}

/**
 * Unauthorized Error (401)
 *
 * Used when authentication is required but missing or invalid
 */
export class UnauthorizedError extends APIError {
  constructor(message: string = 'Unauthorized', cause?: Error) {
    super(message, 'UNAUTHORIZED', cause);
    this.name = 'UnauthorizedError';
  }
}

/**
 * Forbidden Error (403)
 *
 * Used when the client is authenticated but lacks permission
 */
export class ForbiddenError extends APIError {
  constructor(message: string = 'Forbidden', cause?: Error) {
    super(message, 'FORBIDDEN', cause);
    this.name = 'ForbiddenError';
  }
}

/**
 * Conflict Error (409)
 *
 * Used when the request conflicts with the current state of the server
 */
export class ConflictError extends APIError {
  constructor(message: string, cause?: Error) {
    super(message, 'CONFLICT', cause);
    this.name = 'ConflictError';
  }
}

/**
 * Bad Request Error (400)
 *
 * Used when the request is malformed or invalid
 */
export class BadRequestError extends APIError {
  constructor(message: string, cause?: Error) {
    super(message, 'BAD_REQUEST', cause);
    this.name = 'BadRequestError';
  }
}
