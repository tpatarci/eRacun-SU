import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import {
  getInvoiceSubmissionService,
  initializeInvoiceSubmission,
  InvoiceSubmissionService,
  resetInvoiceSubmissionService,
} from '../../../src/jobs/invoice-submission';

// Mock the logger
jest.mock('../../../src/shared/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}));

// Mock BullMQ Queue and Worker
jest.mock('bullmq', () => {
  const mockQueue = {
    name: 'submit-to-fina',
    add: jest.fn().mockResolvedValue({ id: 'test-job-id' }),
    close: jest.fn().mockResolvedValue(undefined),
    getActiveCount: jest.fn().mockResolvedValue(0),
    getWaitingCount: jest.fn().mockResolvedValue(0),
    getCompletedCount: jest.fn().mockResolvedValue(0),
    getFailedCount: jest.fn().mockResolvedValue(0),
  };

  const mockWorker = {
    close: jest.fn().mockResolvedValue(undefined),
    on: jest.fn().mockReturnThis(),
  };

  return {
    Queue: jest.fn().mockImplementation(() => mockQueue),
    Worker: jest.fn().mockImplementation(() => mockWorker),
    Job: jest.fn(),
  };
});

// Mock the invoice repository
jest.mock('../../../src/archive/invoice-repository', () => ({
  updateInvoiceStatus: jest.fn().mockResolvedValue(undefined),
}));

describe('Invoice Submission Service', () => {
  let service: InvoiceSubmissionService;

  beforeEach(() => {
    jest.clearAllMocks();
    // Reset singleton for each test
    resetInvoiceSubmissionService();
    service = new InvoiceSubmissionService();
  });

  afterEach(async () => {
    // Clean up any initialized service
    // @ts-ignore - accessing private property for testing
    if (service.initialized) {
      await service.shutdown();
    }
  });

  describe('initialize', () => {
    it('should initialize the service', () => {
      expect(() => {
        service.initialize('redis://localhost:6379');
      }).not.toThrow();

      // @ts-ignore - accessing private property for testing
      expect(service.initialized).toBe(true);
    });

    it('should throw if already initialized', () => {
      service.initialize('redis://localhost:6379');

      expect(() => {
        service.initialize('redis://localhost:6379');
      }).toThrow('InvoiceSubmissionService already initialized');
    });
  });

  describe('submitInvoice', () => {
    it('should throw if service not initialized', async () => {
      await expect(
        service.submitInvoice({
          invoiceId: 'inv-123',
          oib: '12345678903',
          invoiceNumber: '1/PP1/1',
          originalXml: '<test>',
          signedXml: '<signed>',
        })
      ).rejects.toThrow('InvoiceSubmissionService not initialized');
    });

    it('should submit invoice to queue', async () => {
      service.initialize('redis://localhost:6379');

      const jobId = await service.submitInvoice({
        invoiceId: 'inv-123',
        oib: '12345678903',
        invoiceNumber: '1/PP1/1',
        originalXml: '<test>',
        signedXml: '<signed>',
      });

      expect(jobId).toBe('test-job-id');
    });
  });

  describe('getJobCounts', () => {
    it('should return job counts', async () => {
      service.initialize('redis://localhost:6379');

      const counts = await service.getJobCounts();

      expect(counts).toHaveProperty('active');
      expect(counts).toHaveProperty('waiting');
      expect(counts).toHaveProperty('completed');
      expect(counts).toHaveProperty('failed');
      expect(counts.active).toBe(0);
      expect(counts.waiting).toBe(0);
      expect(counts.completed).toBe(0);
      expect(counts.failed).toBe(0);
    });
  });

  describe('shutdown', () => {
    it('should shutdown the service', async () => {
      service.initialize('redis://localhost:6379');

      await expect(service.shutdown()).resolves.not.toThrow();

      // @ts-ignore - accessing private property for testing
      expect(service.initialized).toBe(false);
    });
  });
});
