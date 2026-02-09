import { request } from 'express';
import { validationMiddleware } from '../../../src/api/middleware/validate';
import { invoiceSubmissionSchema, invoiceIdParamSchema, oibQuerySchema } from '../../../src/api/schemas';

// Mock the logger
jest.mock('../../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

describe('Validation Middleware', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;

  beforeEach(() => {
    mockReq = {
      headers: {},
      body: {},
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    mockNext = jest.fn();
  });

  it('should pass valid data', async () => {
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
  });

  it('should reject invalid OIB', async () => {
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
    expect(mockRes.json).toHaveBeenCalled();
  });

  it('should reject invalid payment method', async () => {
    mockReq.body = {
      oib: '12345678903',
      invoiceNumber: '1/PP1/1',
      amount: '1250.00',
      paymentMethod: 'X', // Invalid
      businessPremises: 'PP1',
      cashRegister: '1',
      dateTime: '2026-01-15T10:30:00Z',
    };

    const middleware = validationMiddleware(invoiceSubmissionSchema);

    await middleware(mockReq as Request, mockRes as Response, mockNext);

    expect(mockNext).not.toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(400);
  });

  it('should reject non-numeric OIB', async () => {
    mockReq.body = {
      oib: 'abcdefghijk', // Letters instead of digits
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
  });
});
