/**
 * Integration Tests for Sync Flow
 *
 * Tests the complete sync workflow from DZS API to database updates
 */

import axios from 'axios';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { syncKPDCodes } from '../../src/sync';
import * as repository from '../../src/repository';
import { KPDCode } from '../../src/repository';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock repository
jest.mock('../../src/repository', () => ({
  getAllKPDCodes: jest.fn(),
  bulkInsertKPDCodes: jest.fn(),
  updateKPDCode: jest.fn(),
  softDeleteKPDCode: jest.fn(),
  getSyncStatistics: jest.fn(),
}));

// Mock observability
jest.mock('../../src/observability', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
  kpdCodesSynced: {
    inc: jest.fn(),
  },
  kpdSyncDuration: {
    observe: jest.fn(),
  },
  kpdSyncErrors: {
    inc: jest.fn(),
  },
  kpdLastSyncTimestamp: {
    set: jest.fn(),
  },
  traceOperation: jest.fn((name, fn) => fn({ setAttribute: jest.fn() })),
}));

describe('Sync Flow Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('End-to-End Sync Flow', () => {
    it('should complete full sync cycle with CSV data', async () => {
      // Load test fixture
      const csvPath = resolve(__dirname, '../fixtures/klasus-codes.csv');
      const csvData = readFileSync(csvPath, 'utf-8');

      // Mock DZS API to return CSV
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: csvData,
      });

      // Mock empty local database (first sync)
      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([]);
      (repository.bulkInsertKPDCodes as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 20,
        active_codes: 20,
        inactive_codes: 0,
      });

      // Execute sync
      const result = await syncKPDCodes();

      // Verify success
      expect(result.success).toBe(true);
      expect(result.codes_added).toBeGreaterThan(0);
      expect(result.codes_updated).toBe(0);
      expect(result.codes_deleted).toBe(0);
      expect(result.total_codes).toBe(20);

      // Verify repository was called
      expect(repository.getAllKPDCodes).toHaveBeenCalled();
      expect(repository.bulkInsertKPDCodes).toHaveBeenCalled();
      expect(repository.getSyncStatistics).toHaveBeenCalled();
    });

    it('should handle incremental sync with updates', async () => {
      const remoteCodes = [
        {
          code: '010101',
          description: 'Cattle (updated)', // Changed description
          level: 3,
          parent_code: '0101',
          effective_from: '2025-01-01',
          effective_to: null,
        },
        {
          code: '010102',
          description: 'Pigs',
          level: 3,
          parent_code: '0101',
          effective_from: '2025-01-01',
          effective_to: null,
        },
      ];

      const localCodes: KPDCode[] = [
        {
          kpd_code: '010101',
          description: 'Cattle (old)', // Original description
          level: 3,
          parent_code: '0101',
          active: true,
          effective_from: new Date('2025-01-01'),
          effective_to: null,
        },
      ];

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: remoteCodes,
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue(localCodes);
      (repository.bulkInsertKPDCodes as jest.Mock).mockResolvedValue(undefined);
      (repository.updateKPDCode as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 2,
        active_codes: 2,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_added).toBe(1); // 010102 is new
      expect(result.codes_updated).toBe(1); // 010101 updated
      expect(result.codes_deleted).toBe(0);
    });

    it('should handle sync with deletions', async () => {
      const remoteCodes = [
        {
          code: '010101',
          description: 'Cattle',
          level: 3,
          parent_code: '0101',
          effective_from: '2025-01-01',
          effective_to: null,
        },
      ];

      const localCodes: KPDCode[] = [
        {
          kpd_code: '010101',
          description: 'Cattle',
          level: 3,
          parent_code: '0101',
          active: true,
          effective_from: new Date('2025-01-01'),
          effective_to: null,
        },
        {
          kpd_code: '010102',
          description: 'Pigs (to be deleted)',
          level: 3,
          parent_code: '0101',
          active: true,
          effective_from: new Date('2025-01-01'),
          effective_to: null,
        },
      ];

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: remoteCodes,
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue(localCodes);
      (repository.softDeleteKPDCode as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 2,
        active_codes: 1,
        inactive_codes: 1,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_deleted).toBe(1);
      expect(repository.softDeleteKPDCode).toHaveBeenCalledWith('010102');
    });

    it('should track performance metrics', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: [],
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([]);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 0,
        active_codes: 0,
        inactive_codes: 0,
      });

      const startTime = Date.now();
      const result = await syncKPDCodes();
      const duration = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(result.duration_seconds).toBeGreaterThan(0);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds for empty dataset
    });
  });

  describe('Error Recovery', () => {
    it('should handle DZS API failure gracefully', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Network error'));

      const result = await syncKPDCodes();

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.codes_added).toBe(0);
      expect(result.codes_updated).toBe(0);
      expect(result.codes_deleted).toBe(0);
    });

    it('should handle database errors during sync', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: [
          {
            code: '010101',
            description: 'Cattle',
            level: 3,
            parent_code: '0101',
            effective_from: '2025-01-01',
            effective_to: null,
          },
        ],
      });

      (repository.getAllKPDCodes as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      );

      const result = await syncKPDCodes();

      expect(result.success).toBe(false);
      expect(result.error).toContain('Database connection failed');
    });

    it('should track sync duration even on failure', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Timeout'));

      const result = await syncKPDCodes();

      expect(result.success).toBe(false);
      expect(result.duration_seconds).toBeGreaterThan(0);
    });
  });

  describe('Data Integrity', () => {
    it('should preserve code hierarchy relationships', async () => {
      const remoteCodes = [
        {
          code: '01',
          description: 'Agricultural products',
          level: 1,
          parent_code: null,
          effective_from: '2025-01-01',
          effective_to: null,
        },
        {
          code: '0101',
          description: 'Live animals',
          level: 2,
          parent_code: '01',
          effective_from: '2025-01-01',
          effective_to: null,
        },
        {
          code: '010101',
          description: 'Cattle',
          level: 3,
          parent_code: '0101',
          effective_from: '2025-01-01',
          effective_to: null,
        },
      ];

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: remoteCodes,
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([]);
      (repository.bulkInsertKPDCodes as jest.Mock).mockImplementation((codes) => {
        // Verify hierarchy is preserved
        const level1 = codes.find((c: KPDCode) => c.kpd_code === '01');
        const level2 = codes.find((c: KPDCode) => c.kpd_code === '0101');
        const level3 = codes.find((c: KPDCode) => c.kpd_code === '010101');

        expect(level1?.parent_code).toBeNull();
        expect(level2?.parent_code).toBe('01');
        expect(level3?.parent_code).toBe('0101');

        return Promise.resolve();
      });

      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 3,
        active_codes: 3,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_added).toBe(3);
    });

    it('should preserve effective dates correctly', async () => {
      const remoteCodes = [
        {
          code: '010101',
          description: 'Cattle',
          level: 3,
          parent_code: '0101',
          effective_from: '2025-01-01',
          effective_to: '2025-12-31',
        },
      ];

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: remoteCodes,
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([]);
      (repository.bulkInsertKPDCodes as jest.Mock).mockImplementation((codes) => {
        const code = codes[0];
        expect(code.effective_from).toBeInstanceOf(Date);
        expect(code.effective_to).toBeInstanceOf(Date);

        return Promise.resolve();
      });

      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 1,
        active_codes: 1,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
    });
  });
});
