import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { Job } from 'bullmq';
import { createInvoiceQueue, processFinaSubmission, JobType } from '../../../src/jobs/queue';
import { fiscalizeInvoice } from '../../../src/fina/fina-client';
import * as finaClientModule from '../../../src/fina/fina-client';
import { loadUserConfig } from '../../../src/shared/tenant-config';

// Mock the logger
jest.mock('../../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

// Mock the FINA client module
jest.mock('../../../src/fina/fina-client', () => ({
  fiscalizeInvoice: jest.fn().mockResolvedValue({
    jir: 'test-jir-123',
  }),
  createFINAClient: jest.fn(),
}));

// Mock tenant config loader
jest.mock('../../../src/shared/tenant-config', () => ({
  loadUserConfig: jest.fn(),
}));

// Mock the invoice repository
jest.mock('../../../src/archive/invoice-repository', () => ({
  updateInvoiceStatus: jest.fn().mockResolvedValue(undefined),
}));

// Mock FINA client instance
const mockFinaClient = {
  initialize: jest.fn().mockResolvedValue(undefined),
  fiscalizeInvoice: jest.fn().mockResolvedValue({
    success: true,
    jir: 'test-jir-123',
  }),
  close: jest.fn().mockResolvedValue(undefined),
};

describe('Job Queue', () => {
  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();

    // Setup default mock returns
    (loadUserConfig as jest.Mock).mockResolvedValue({
      fina: {
        wsdlUrl: 'https://test.fina.hr',
        certPath: '/test/cert.p12',
        certPassphrase: 'test123',
      },
    });
    (finaClientModule.createFINAClient as jest.Mock).mockReturnValue(mockFinaClient);
  });

  describe('createInvoiceQueue', () => {
    it('should create a queue with correct name', () => {
      const queue = createInvoiceQueue('redis://localhost:6379');

      expect(queue).toBeDefined();
      expect(queue.name).toBe(JobType.SUBMIT_TO_FINA);

      queue.close();
    });

    it('should parse custom redis URL', () => {
      const queue = createInvoiceQueue('redis://redis.example.com:6380');

      expect(queue).toBeDefined();

      queue.close();
    });
  });

  describe('processFinaSubmission', () => {
    it('should process job and return status update', async () => {
      const mockJob = {
        id: 'test-job-id',
        data: {
          invoiceId: 'inv-123',
          userId: 'user-123',
          oib: '12345678903',
          invoiceNumber: '1/PP1/1',
          originalXml: '<test>',
          signedXml: '<signed>',
        },
      } as unknown as Job;

      const result = await processFinaSubmission(mockJob);

      expect(result).toEqual({
        invoiceId: 'inv-123',
        status: 'submitted',
        jir: 'test-jir-123',
      });
      expect(loadUserConfig).toHaveBeenCalledWith('user-123');
      expect(mockFinaClient.initialize).toHaveBeenCalled();
      expect(mockFinaClient.fiscalizeInvoice).toHaveBeenCalled();
      expect(mockFinaClient.close).toHaveBeenCalled();
    });

    it('should handle FINA errors and return failed status', async () => {
      mockFinaClient.fiscalizeInvoice.mockResolvedValueOnce({
        success: false,
        error: new Error('FINA error'),
      });

      const mockJob = {
        id: 'test-job-id',
        data: {
          invoiceId: 'inv-123',
          userId: 'user-123',
          oib: '12345678903',
          invoiceNumber: '1/PP1/1',
          originalXml: '<test>',
          signedXml: '<signed>',
        },
      } as unknown as Job;

      const result = await processFinaSubmission(mockJob);

      expect(result).toEqual({
        invoiceId: 'inv-123',
        status: 'failed',
        error: 'FINA error',
      });
    });

    it('should return failed status when FINA config is missing', async () => {
      (loadUserConfig as jest.Mock).mockResolvedValueOnce({
        fina: null,
      });

      const mockJob = {
        id: 'test-job-id',
        data: {
          invoiceId: 'inv-123',
          userId: 'user-123',
          oib: '12345678903',
          invoiceNumber: '1/PP1/1',
          originalXml: '<test>',
          signedXml: '<signed>',
        },
      } as unknown as Job;

      const result = await processFinaSubmission(mockJob);

      expect(result).toEqual({
        invoiceId: 'inv-123',
        status: 'failed',
        error: 'FINA configuration not found for user. Please configure your fiscalization settings.',
      });
    });
  });
});
