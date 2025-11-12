/**
 * Unit Tests for Sync Module
 */

import axios from 'axios';
import { syncKPDCodes, triggerManualSync, getLastSyncResult } from '../../src/sync';
import * as repository from '../../src/repository';
import { KPDCode } from '../../src/repository';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock repository module
jest.mock('../../src/repository', () => ({
  getAllKPDCodes: jest.fn(),
  insertKPDCode: jest.fn(),
  updateKPDCode: jest.fn(),
  softDeleteKPDCode: jest.fn(),
  bulkInsertKPDCodes: jest.fn(),
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

describe('Sync Module', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('syncKPDCodes', () => {
    const mockRemoteCodes: KPDCode[] = [
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
        description: 'Pigs',
        level: 3,
        parent_code: '0101',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      },
    ];

    const mockLocalCodes: KPDCode[] = [
      {
        kpd_code: '010101',
        description: 'Cattle (old)',
        level: 3,
        parent_code: '0101',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      },
      {
        kpd_code: '010103',
        description: 'Sheep',
        level: 3,
        parent_code: '0101',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      },
    ];

    it('should sync codes successfully with JSON response', async () => {
      // Mock DZS API response (JSON array)
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: mockRemoteCodes.map((code) => ({
          code: code.kpd_code,
          description: code.description,
          level: code.level,
          parent_code: code.parent_code,
          effective_from: code.effective_from.toISOString().split('T')[0],
          effective_to: code.effective_to,
        })),
      });

      // Mock repository responses
      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue(mockLocalCodes);
      (repository.bulkInsertKPDCodes as jest.Mock).mockResolvedValue(undefined);
      (repository.updateKPDCode as jest.Mock).mockResolvedValue(undefined);
      (repository.softDeleteKPDCode as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 3,
        active_codes: 2,
        inactive_codes: 1,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_added).toBe(1); // 010102 is new
      expect(result.codes_updated).toBe(1); // 010101 description changed
      expect(result.codes_deleted).toBe(1); // 010103 deleted
      expect(mockedAxios.get).toHaveBeenCalled();
    });

    it('should sync codes successfully with nested JSON response', async () => {
      // Mock DZS API response (JSON object with codes array)
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: {
          codes: mockRemoteCodes.map((code) => ({
            code: code.kpd_code,
            description: code.description,
            level: code.level,
            parent_code: code.parent_code,
            effective_from: code.effective_from.toISOString().split('T')[0],
            effective_to: code.effective_to,
          })),
        },
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([]);
      (repository.bulkInsertKPDCodes as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 2,
        active_codes: 2,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_added).toBe(2); // Both codes are new
    });

    it('should handle network timeout error', async () => {
      const error: any = new Error('timeout');
      error.code = 'ECONNABORTED';
      error.isAxiosError = true;
      mockedAxios.isAxiosError = jest.fn().mockReturnValue(true);
      mockedAxios.get.mockRejectedValue(error);

      const result = await syncKPDCodes();

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle DZS API error response', async () => {
      const error: any = new Error('API Error');
      error.isAxiosError = true;
      error.response = {
        status: 500,
        data: { error: 'Internal Server Error' },
      };
      mockedAxios.isAxiosError = jest.fn().mockReturnValue(true);
      mockedAxios.get.mockRejectedValue(error);

      const result = await syncKPDCodes();

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle unexpected response format', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: { unexpected: 'format' }, // Neither array nor {codes: [...]}
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(false);
      expect(result.error).toContain('Unexpected DZS API response format');
    });

    it('should handle CSV string response', async () => {
      const csvData = `code,description,level,parent_code,effective_from,effective_to
010101,Cattle,3,0101,2025-01-01,
010102,Pigs,3,0101,2025-01-01,`;

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: csvData,
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([]);
      (repository.bulkInsertKPDCodes as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 2,
        active_codes: 2,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_added).toBeGreaterThan(0);
    });

    it('should not update code if no changes detected', async () => {
      const identicalCode: KPDCode = {
        kpd_code: '010101',
        description: 'Cattle',
        level: 3,
        parent_code: '0101',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      };

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: [
          {
            code: identicalCode.kpd_code,
            description: identicalCode.description,
            level: identicalCode.level,
            parent_code: identicalCode.parent_code,
            effective_from: identicalCode.effective_from.toISOString().split('T')[0],
            effective_to: identicalCode.effective_to,
          },
        ],
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([identicalCode]);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 1,
        active_codes: 1,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_added).toBe(0);
      expect(result.codes_updated).toBe(0);
      expect(result.codes_deleted).toBe(0);
      expect(repository.updateKPDCode).not.toHaveBeenCalled();
    });

    it('should track sync duration', async () => {
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

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.duration_seconds).toBeGreaterThan(0);
    });
  });

  describe('triggerManualSync', () => {
    it('should trigger manual sync', async () => {
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

      const result = await triggerManualSync();

      expect(result).toBeDefined();
      expect(result.success).toBe(true);
    });
  });

  describe('getLastSyncResult', () => {
    it('should return null (not yet implemented)', async () => {
      const result = await getLastSyncResult();
      expect(result).toBeNull();
    });
  });

  describe('Code Comparison Logic', () => {
    it('should detect new codes', async () => {
      const newCode: KPDCode = {
        kpd_code: '020101',
        description: 'Sawlogs',
        level: 3,
        parent_code: '0201',
        active: true,
        effective_from: new Date('2025-01-01'),
        effective_to: null,
      };

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: [
          {
            code: newCode.kpd_code,
            description: newCode.description,
            level: newCode.level,
            parent_code: newCode.parent_code,
            effective_from: newCode.effective_from.toISOString().split('T')[0],
            effective_to: newCode.effective_to,
          },
        ],
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([]);
      (repository.bulkInsertKPDCodes as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 1,
        active_codes: 1,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_added).toBe(1);
      expect(repository.bulkInsertKPDCodes).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            kpd_code: '020101',
          }),
        ])
      );
    });

    it('should detect updated codes', async () => {
      const updatedCode = {
        code: '010101',
        description: 'Cattle (updated)', // Changed description
        level: 3,
        parent_code: '0101',
        effective_from: '2025-01-01',
        effective_to: null,
      };

      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: [updatedCode],
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([
        {
          kpd_code: '010101',
          description: 'Cattle (old)', // Original description
          level: 3,
          parent_code: '0101',
          active: true,
          effective_from: new Date('2025-01-01'),
          effective_to: null,
        },
      ]);
      (repository.updateKPDCode as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 1,
        active_codes: 1,
        inactive_codes: 0,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_updated).toBe(1);
      expect(repository.updateKPDCode).toHaveBeenCalled();
    });

    it('should detect deleted codes', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: [], // No remote codes
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([
        {
          kpd_code: '010101',
          description: 'Cattle',
          level: 3,
          parent_code: '0101',
          active: true, // Active locally but not in remote
          effective_from: new Date('2025-01-01'),
          effective_to: null,
        },
      ]);
      (repository.softDeleteKPDCode as jest.Mock).mockResolvedValue(undefined);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 1,
        active_codes: 0,
        inactive_codes: 1,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_deleted).toBe(1);
      expect(repository.softDeleteKPDCode).toHaveBeenCalledWith('010101');
    });

    it('should not delete already inactive codes', async () => {
      mockedAxios.get.mockResolvedValue({
        status: 200,
        data: [],
      });

      (repository.getAllKPDCodes as jest.Mock).mockResolvedValue([
        {
          kpd_code: '010101',
          description: 'Cattle',
          level: 3,
          parent_code: '0101',
          active: false, // Already inactive
          effective_from: new Date('2025-01-01'),
          effective_to: new Date('2025-06-01'),
        },
      ]);
      (repository.getSyncStatistics as jest.Mock).mockResolvedValue({
        total_codes: 1,
        active_codes: 0,
        inactive_codes: 1,
      });

      const result = await syncKPDCodes();

      expect(result.success).toBe(true);
      expect(result.codes_deleted).toBe(0);
      expect(repository.softDeleteKPDCode).not.toHaveBeenCalled();
    });
  });
});
