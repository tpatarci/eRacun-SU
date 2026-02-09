import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { Job } from 'bullmq';
import { createInvoiceQueue, processFinaSubmission, JobType } from '../../../src/jobs/queue';
import { fiscalizeInvoice } from '../../../src/fina/fina-client';

// Mock the logger
jest.mock('../../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

// Mock the FINA client
jest.mock('../../../src/fina/fina-client', () => ({
  fiscalizeInvoice: jest.fn().mockResolvedValue({
    jir: 'test-jir-123',
  }),
}));

// Mock the invoice repository
jest.mock('../../../src/archive/invoice-repository', () => ({
  updateInvoiceStatus: jest.fn().mockResolvedValue(undefined),
}));

describe('Job Queue', () => {
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
      expect(fiscalizeInvoice).toHaveBeenCalledWith({
        oib: '12345678903',
        invoiceNumber: '1/PP1/1',
        dateTime: expect.any(String),
        businessPremises: 'PP1',
        cashRegister: '1',
        totalAmount: '0',
        signedXml: '<signed>',
      });
    });

    it('should handle FINA errors and return failed status', async () => {
      (fiscalizeInvoice as jest.Mock).mockRejectedValueOnce(new Error('FINA error'));

      const mockJob = {
        id: 'test-job-id',
        data: {
          invoiceId: 'inv-123',
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
  });
});
