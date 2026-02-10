import { invoiceSubmissionSchema, invoiceIdParamSchema, oibQuerySchema } from '../../../src/api/schemas';
import { validationMiddleware } from '../../../src/api/middleware/validate';
import type { Request, Response } from 'express';

// Mock the logger
jest.mock('../../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

describe('API Schemas', () => {
  describe('invoiceSubmissionSchema', () => {
    const validInvoiceData = {
      oib: '12345678903',
      invoiceNumber: '1/PP1/1',
      amount: '1250.00',
      paymentMethod: 'T' as const,
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: '2026-01-15T10:30:00Z',
    };

    it('should accept valid invoice data', () => {
      const result = invoiceSubmissionSchema.safeParse(validInvoiceData);
      expect(result.success).toBe(true);
    });

    it('should require oib', () => {
      const result = invoiceSubmissionSchema.safeParse({
        ...validInvoiceData,
        oib: undefined,
      });
      expect(result.success).toBe(false);
    });

    it('should validate OIB length (11 digits)', () => {
      const result = invoiceSubmissionSchema.safeParse({
        ...validInvoiceData,
        oib: '123', // Too short
      });
      expect(result.success).toBe(false);
    });

    it('should validate OIB is numeric', () => {
      const result = invoiceSubmissionSchema.safeParse({
        ...validInvoiceData,
        oib: 'abcdefghijk',
      });
      expect(result.success).toBe(false);
    });

    it('should validate amount is positive', () => {
      const result = invoiceSubmissionSchema.safeParse({
        ...validInvoiceData,
        amount: '0',
      });
      expect(result.success).toBe(false);
    });

    it('should validate amount format', () => {
      const result = invoiceSubmissionSchema.safeParse({
        ...validInvoiceData,
        amount: 'abc',
      });
      expect(result.success).toBe(false);
    });

    it('should validate payment method enum', () => {
      const validMethods = ['G', 'K', 'C', 'T', 'O'];

      for (const method of validMethods) {
        const result = invoiceSubmissionSchema.safeParse({
          ...validInvoiceData,
          paymentMethod: method as any,
        });
        expect(result.success).toBe(true);
      }

      const invalidResult = invoiceSubmissionSchema.safeParse({
        ...validInvoiceData,
        paymentMethod: 'X',
      });
      expect(invalidResult.success).toBe(false);
    });

    it('should accept VAT breakdown', () => {
      const result = invoiceSubmissionSchema.safeParse({
        ...validInvoiceData,
        vatBreakdown: [
          { base: '1000.00', rate: '25.00', amount: '250.00' },
        ],
      });
      expect(result.success).toBe(true);
    });
  });

  describe('invoiceIdParamSchema', () => {
    it('should accept valid UUID', () => {
      const result = invoiceIdParamSchema.safeParse('550e8400-e29b-41d4-a716-446655440000');
      expect(result.success).toBe(true);
    });

    it('should reject invalid UUID', () => {
      const result = invoiceIdParamSchema.safeParse('not-a-uuid');
      expect(result.success).toBe(false);
    });
  });

  describe('oibQuerySchema', () => {
    it('should accept valid OIB query', () => {
      const result = oibQuerySchema.safeParse({
        oib: '12345678903',
      });
      expect(result.success).toBe(true);
    });

    it('should have default limit and offset', () => {
      const result = oibQuerySchema.safeParse({
        oib: '12345678903',
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.limit).toBe(50);
        expect(result.data.offset).toBe(0);
      }
    });
  });
});

describe('Validation Error Response Format', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;

  beforeEach(() => {
    mockReq = {
      headers: {},
      body: {},
      id: 'test-request-id',
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    mockNext = jest.fn();
  });

  it('should return standardized error format for validation failure', async () => {
    mockReq.body = {
      oib: '123', // Too short
      invoiceNumber: '1/PP1/1',
      amount: '1250.00',
      paymentMethod: 'T',
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: '2026-01-15T10:30:00Z',
    };

    const middleware = validationMiddleware(invoiceSubmissionSchema);
    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).not.toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: 'test-request-id',
        errors: expect.arrayContaining([
          expect.objectContaining({
            field: expect.any(String),
            message: expect.any(String),
          }),
        ]),
      })
    );
  });

  it('should return standardized error format for multiple validation failures', async () => {
    mockReq.body = {
      oib: '123', // Too short
      invoiceNumber: '1/PP1/1',
      amount: 'abc', // Invalid format
      paymentMethod: 'X', // Invalid enum
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: 'invalid-date', // Invalid datetime
    };

    const middleware = validationMiddleware(invoiceSubmissionSchema);
    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).not.toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        requestId: 'test-request-id',
        errors: expect.any(Array),
      })
    );

    // Verify errors array has multiple entries
    const jsonCall = (mockRes.json as jest.Mock).mock.calls[0][0];
    expect(jsonCall.errors.length).toBeGreaterThan(1);
  });

  it('should not call json on successful validation', async () => {
    mockReq.body = {
      oib: '12345678903',
      invoiceNumber: '1/PP1/1',
      amount: '1250.00',
      paymentMethod: 'T',
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: '2026-01-15T10:30:00Z',
    };

    const middleware = validationMiddleware(invoiceSubmissionSchema);
    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockRes.status).not.toHaveBeenCalled();
    expect(mockRes.json).not.toHaveBeenCalled();
  });
});
