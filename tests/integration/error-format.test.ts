import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express, { Application } from 'express';

// Mock all dependencies
jest.mock('../../src/shared/db', () => ({
  initDb: jest.fn(),
  query: jest.fn().mockResolvedValue({ rows: [] }),
  getPool: jest.fn().mockReturnValue({
    query: jest.fn().mockResolvedValue({ rows: [] }),
  }),
  closePool: jest.fn(),
}));

jest.mock('../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock('../../src/jobs/invoice-submission', () => ({
  initializeInvoiceSubmission: jest.fn(),
  submitInvoiceForProcessing: jest.fn(),
  getInvoiceSubmissionService: jest.fn().mockReturnValue({
    shutdown: jest.fn().mockResolvedValue(undefined),
  }),
}));

import { createApp } from '../../src/api/app.js';
import { NotFoundError, ValidationError, InternalError, UnauthorizedError, ForbiddenError, ConflictError, BadRequestError } from '../../src/api/errors.js';
import { validationMiddleware } from '../../src/api/middleware/validate.js';
import { invoiceSubmissionSchema } from '../../src/api/schemas.js';

describe('Error Response Format Integration Tests', () => {
  let app: Application;

  beforeEach(() => {
    jest.clearAllMocks();
    app = createApp();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Validation Error Response Format', () => {
    const validInvoiceData = {
      oib: '12345678903',
      invoiceNumber: '1/PP1/1',
      amount: '1250.00',
      paymentMethod: 'T',
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: '2026-01-15T10:30:00Z',
    };

    it('should return standardized error format for validation failure', async () => {
      const invalidData = {
        ...validInvoiceData,
        oib: '123', // Too short
      };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: expect.any(String),
      });
      expect(response.body.errors).toBeDefined();
      expect(Array.isArray(response.body.errors)).toBe(true);
      expect(response.body.errors.length).toBeGreaterThan(0);
    });

    it('should return errors array with field and message properties', async () => {
      const invalidData = {
        ...validInvoiceData,
        oib: '123',
        amount: 'abc',
      };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body.errors).toBeInstanceOf(Array);
      response.body.errors.forEach((error: any) => {
        expect(error).toHaveProperty('field');
        expect(error).toHaveProperty('message');
        expect(typeof error.field).toBe('string');
        expect(typeof error.message).toBe('string');
      });
    });

    it('should include requestId in response header', async () => {
      const invalidData = {
        ...validInvoiceData,
        oib: '123',
      };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.headers['x-request-id']).toBeDefined();
      expect(response.body.requestId).toBe(response.headers['x-request-id']);
    });

    it('should use custom requestId if provided', async () => {
      const customRequestId = 'my-custom-request-id-123';

      const response = await request(app)
        .post('/api/v1/invoices')
        .set('X-Request-ID', customRequestId)
        .send({ ...validInvoiceData, oib: '123' })
        .expect(400);

      expect(response.body.requestId).toBe(customRequestId);
      expect(response.headers['x-request-id']).toBe(customRequestId);
    });

    it('should return multiple validation errors', async () => {
      const invalidData = {
        ...validInvoiceData,
        oib: '123', // Too short
        amount: 'abc', // Invalid format
        paymentMethod: 'X', // Invalid enum
      };

      const response = await request(app)
        .post('/api/v1/invoices')
        .send(invalidData)
        .expect(400);

      expect(response.body.errors).toBeInstanceOf(Array);
      expect(response.body.errors.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Not Found Error Response Format', () => {
    it('should return standardized 404 error format', async () => {
      const nonExistentId = '00000000-0000-0000-0000-000000000000';

      const response = await request(app)
        .get(`/api/v1/invoices/${nonExistentId}`)
        .expect(404);

      expect(response.body).toMatchObject({
        code: 'NOT_FOUND',
        message: 'Invoice not found',
        requestId: expect.any(String),
      });
      expect(response.body.errors).toBeUndefined();
    });

    it('should return 404 for invoice status endpoint', async () => {
      const nonExistentId = '00000000-0000-0000-0000-000000000000';

      const response = await request(app)
        .get(`/api/v1/invoices/${nonExistentId}/status`)
        .expect(404);

      expect(response.body).toMatchObject({
        code: 'NOT_FOUND',
        message: 'Invoice not found',
        requestId: expect.any(String),
      });
    });
  });

  describe('Bad Request Error Response Format', () => {
    it('should return standardized 400 error format', async () => {
      const response = await request(app)
        .get('/api/v1/invoices')
        .expect(400);

      expect(response.body).toMatchObject({
        code: 'BAD_REQUEST',
        message: 'Missing required query parameter: oib',
        requestId: expect.any(String),
      });
      expect(response.body.errors).toBeUndefined();
    });
  });

  describe('Error Handler Consistency', () => {
    it('should always return code, message, and requestId fields', async () => {
      // Test validation error
      const validationResponse = await request(app)
        .post('/api/v1/invoices')
        .send({ oib: '123' })
        .expect(400);

      expect(validationResponse.body).toHaveProperty('code');
      expect(validationResponse.body).toHaveProperty('message');
      expect(validationResponse.body).toHaveProperty('requestId');

      // Test not found error
      const notFoundResponse = await request(app)
        .get('/api/v1/invoices/00000000-0000-0000-0000-000000000000')
        .expect(404);

      expect(notFoundResponse.body).toHaveProperty('code');
      expect(notFoundResponse.body).toHaveProperty('message');
      expect(notFoundResponse.body).toHaveProperty('requestId');

      // Test bad request error
      const badRequestResponse = await request(app)
        .get('/api/v1/invoices')
        .expect(400);

      expect(badRequestResponse.body).toHaveProperty('code');
      expect(badRequestResponse.body).toHaveProperty('message');
      expect(badRequestResponse.body).toHaveProperty('requestId');
    });

    it('should return consistent requestId across response header and body', async () => {
      const customRequestId = 'test-consistency-id-123';

      const response = await request(app)
        .post('/api/v1/invoices')
        .set('X-Request-ID', customRequestId)
        .send({ oib: '123' })
        .expect(400);

      expect(response.body.requestId).toBe(response.headers['x-request-id']);
      expect(response.body.requestId).toBe(customRequestId);
    });

    it('should include X-Request-ID header in all error responses', async () => {
      const responses = await Promise.all([
        request(app).post('/api/v1/invoices').send({ oib: '123' }),
        request(app).get('/api/v1/invoices/00000000-0000-0000-0000-000000000000'),
        request(app).get('/api/v1/invoices'),
      ]);

      responses.forEach(response => {
        expect(response.headers['x-request-id']).toBeDefined();
        expect(typeof response.headers['x-request-id']).toBe('string');
        expect(response.headers['x-request-id'].length).toBeGreaterThan(0);
      });
    });
  });

  describe('Error Response Structure', () => {
    it('should not include stack trace in error response', async () => {
      const response = await request(app)
        .post('/api/v1/invoices')
        .send({ oib: '123' })
        .expect(400);

      expect(response.body).not.toHaveProperty('stack');
      expect(response.body).not.toHaveProperty('cause');
    });

    it('should only include errors array for validation errors', async () => {
      // Validation error should have errors array
      const validationResponse = await request(app)
        .post('/api/v1/invoices')
        .send({ oib: '123' })
        .expect(400);

      expect(validationResponse.body.errors).toBeDefined();

      // Not found error should not have errors array
      const notFoundResponse = await request(app)
        .get('/api/v1/invoices/00000000-0000-0000-0000-000000000000')
        .expect(404);

      expect(notFoundResponse.body.errors).toBeUndefined();
    });

    it('should return machine-readable error codes', async () => {
      const testCases = [
        {
          request: () => request(app).post('/api/v1/invoices').send({ oib: '123' }),
          expectedStatus: 400,
          expectedCode: 'VALIDATION_ERROR',
        },
        {
          request: () => request(app).get('/api/v1/invoices/00000000-0000-0000-0000-000000000000'),
          expectedStatus: 404,
          expectedCode: 'NOT_FOUND',
        },
        {
          request: () => request(app).get('/api/v1/invoices/'),
          expectedStatus: 400,
          expectedCode: 'BAD_REQUEST',
        },
      ];

      for (const testCase of testCases) {
        const response = await testCase.request().expect(testCase.expectedStatus);
        expect(response.body.code).toBe(testCase.expectedCode);
        expect(typeof response.body.code).toBe('string');
        expect(response.body.code).toMatch(/^[A-Z_]+$/);
      }
    });
  });

  describe('Request ID Generation and Tracking', () => {
    it('should generate unique request IDs for different requests', async () => {
      const requestIds = new Set<string>();

      for (let i = 0; i < 5; i++) {
        const response = await request(app)
          .post('/api/v1/invoices')
          .send({ oib: '123' })
          .expect(400);

        requestIds.add(response.body.requestId);
      }

      // All request IDs should be unique (except in very rare UUID collision cases)
      expect(requestIds.size).toBe(5);
    });

    it('should generate valid UUID request IDs', async () => {
      const response = await request(app)
        .post('/api/v1/invoices')
        .send({ oib: '123' })
        .expect(400);

      // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      expect(response.body.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    });

    it('should preserve request ID through middleware chain', async () => {
      const customRequestId = 'middleware-test-id-456';

      const response = await request(app)
        .post('/api/v1/invoices')
        .set('X-Request-ID', customRequestId)
        .send({ oib: '123' })
        .expect(400);

      // The same ID should be in the header, response body, and logs
      expect(response.headers['x-request-id']).toBe(customRequestId);
      expect(response.body.requestId).toBe(customRequestId);
    });
  });

  describe('Error Response Content Type', () => {
    it('should return JSON content type for all errors', async () => {
      const responses = await Promise.all([
        request(app).post('/api/v1/invoices').send({ oib: '123' }),
        request(app).get('/api/v1/invoices/00000000-0000-0000-0000-000000000000'),
        request(app).get('/api/v1/invoices'),
      ]);

      responses.forEach(response => {
        expect(response.headers['content-type']).toMatch(/application\/json/);
      });
    });

    it('should return valid JSON that can be parsed', async () => {
      const response = await request(app)
        .post('/api/v1/invoices')
        .send({ oib: '123' })
        .expect(400);

      // Verify it's valid JSON
      expect(() => JSON.parse(JSON.stringify(response.body))).not.toThrow();

      // Verify required fields exist and are correct type
      expect(typeof response.body.code).toBe('string');
      expect(typeof response.body.message).toBe('string');
      expect(typeof response.body.requestId).toBe('string');
      if (response.body.errors) {
        expect(Array.isArray(response.body.errors)).toBe(true);
      }
    });
  });

  describe('HTTP Status Code Mapping', () => {
    it('should return 400 for validation errors', async () => {
      const response = await request(app)
        .post('/api/v1/invoices')
        .send({ oib: '123' })
        .expect(400);

      expect(response.body.code).toBe('VALIDATION_ERROR');
    });

    it('should return 404 for not found errors', async () => {
      const response = await request(app)
        .get('/api/v1/invoices/00000000-0000-0000-0000-000000000000')
        .expect(404);

      expect(response.body.code).toBe('NOT_FOUND');
    });

    it('should return 400 for bad request errors', async () => {
      const response = await request(app)
        .get('/api/v1/invoices')
        .expect(400);

      expect(response.body.code).toBe('BAD_REQUEST');
    });
  });
});
