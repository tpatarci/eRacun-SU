/**
 * Unit Tests for Repository Module
 */

import { Pool, PoolClient } from 'pg';
import {
  KPDCode,
  initializePool,
  getPool,
  closePool,
  checkDatabaseHealth,
  initializeSchema,
  insertKPDCode,
  updateKPDCode,
  softDeleteKPDCode,
  getAllKPDCodes,
  getKPDCode,
  getActiveKPDCodes,
  searchKPDCodes,
  getKPDCodesPaginated,
  getSyncStatistics,
  bulkInsertKPDCodes,
} from '../../src/repository';

// Mock pg module
jest.mock('pg', () => {
  const mPool = {
    query: jest.fn(),
    connect: jest.fn(),
    end: jest.fn(),
    on: jest.fn(),
    totalCount: 20,
    idleCount: 15,
  };
  return {
    Pool: jest.fn(() => mPool),
  };
});

describe('Repository Module', () => {
  let mockPool: any;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    mockPool = new Pool();
  });

  describe('Connection Pool', () => {
    it('should initialize connection pool', () => {
      const pool = initializePool();
      expect(pool).toBeDefined();
      expect(Pool).toHaveBeenCalled();
    });

    it('should get existing pool', () => {
      const pool1 = initializePool();
      const pool2 = getPool();
      expect(pool2).toBe(pool1);
    });

    it('should close connection pool', async () => {
      initializePool();
      mockPool.end.mockResolvedValue(undefined);

      await closePool();
      expect(mockPool.end).toHaveBeenCalled();
    });

    it('should check database health successfully', async () => {
      mockPool.query.mockResolvedValue({
        rows: [{ health: 1 }],
      });

      const healthy = await checkDatabaseHealth();
      expect(healthy).toBe(true);
      expect(mockPool.query).toHaveBeenCalledWith('SELECT 1 AS health');
    });

    it('should return false on database health check failure', async () => {
      mockPool.query.mockRejectedValue(new Error('Connection failed'));

      const healthy = await checkDatabaseHealth();
      expect(healthy).toBe(false);
    });
  });

  describe('Schema Initialization', () => {
    it('should initialize database schema', async () => {
      mockPool.query.mockResolvedValue({});

      await initializeSchema();
      expect(mockPool.query).toHaveBeenCalled();
    });

    it('should handle schema initialization errors', async () => {
      mockPool.query.mockRejectedValue(new Error('Schema error'));

      await expect(initializeSchema()).rejects.toThrow('Schema error');
    });
  });

  describe('CRUD Operations', () => {
    const sampleCode: KPDCode = {
      kpd_code: '010101',
      description: 'Cattle',
      level: 3,
      parent_code: '0101',
      active: true,
      effective_from: new Date('2025-01-01'),
      effective_to: null,
    };

    describe('insertKPDCode', () => {
      it('should insert new KPD code', async () => {
        mockPool.query.mockResolvedValue({});

        await insertKPDCode(sampleCode);
        expect(mockPool.query).toHaveBeenCalled();
      });

      it('should handle insert errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Insert failed'));

        await expect(insertKPDCode(sampleCode)).rejects.toThrow('Insert failed');
      });
    });

    describe('updateKPDCode', () => {
      it('should update existing KPD code', async () => {
        mockPool.query.mockResolvedValue({ rowCount: 1 });

        await updateKPDCode(sampleCode);
        expect(mockPool.query).toHaveBeenCalled();
      });

      it('should insert if code not found on update', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rowCount: 0 }) // Update returns 0 rows
          .mockResolvedValueOnce({}); // Insert succeeds

        await updateKPDCode(sampleCode);
        expect(mockPool.query).toHaveBeenCalledTimes(2);
      });

      it('should handle update errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Update failed'));

        await expect(updateKPDCode(sampleCode)).rejects.toThrow('Update failed');
      });
    });

    describe('softDeleteKPDCode', () => {
      it('should soft delete KPD code', async () => {
        mockPool.query.mockResolvedValue({ rowCount: 1 });

        await softDeleteKPDCode('010101');
        expect(mockPool.query).toHaveBeenCalled();
      });

      it('should handle code not found on soft delete', async () => {
        mockPool.query.mockResolvedValue({ rowCount: 0 });

        await softDeleteKPDCode('999999');
        expect(mockPool.query).toHaveBeenCalled();
      });

      it('should handle soft delete errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Delete failed'));

        await expect(softDeleteKPDCode('010101')).rejects.toThrow('Delete failed');
      });
    });

    describe('getAllKPDCodes', () => {
      it('should get all KPD codes', async () => {
        const mockCodes = [sampleCode, { ...sampleCode, kpd_code: '010102' }];
        mockPool.query.mockResolvedValue({ rows: mockCodes });

        const codes = await getAllKPDCodes();
        expect(codes).toEqual(mockCodes);
        expect(mockPool.query).toHaveBeenCalled();
      });

      it('should handle get all codes errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Query failed'));

        await expect(getAllKPDCodes()).rejects.toThrow('Query failed');
      });
    });

    describe('getKPDCode', () => {
      it('should get specific KPD code', async () => {
        mockPool.query.mockResolvedValue({ rows: [sampleCode] });

        const code = await getKPDCode('010101');
        expect(code).toEqual(sampleCode);
        expect(mockPool.query).toHaveBeenCalledWith(expect.any(String), ['010101']);
      });

      it('should return null if code not found', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        const code = await getKPDCode('999999');
        expect(code).toBeNull();
      });

      it('should handle get code errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Query failed'));

        await expect(getKPDCode('010101')).rejects.toThrow('Query failed');
      });
    });

    describe('getActiveKPDCodes', () => {
      it('should get only active KPD codes', async () => {
        const activeCodes = [sampleCode];
        mockPool.query.mockResolvedValue({ rows: activeCodes });

        const codes = await getActiveKPDCodes();
        expect(codes).toEqual(activeCodes);
        expect(mockPool.query).toHaveBeenCalled();
      });

      it('should handle get active codes errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Query failed'));

        await expect(getActiveKPDCodes()).rejects.toThrow('Query failed');
      });
    });

    describe('searchKPDCodes', () => {
      it('should search KPD codes by description', async () => {
        const searchResults = [sampleCode];
        mockPool.query.mockResolvedValue({ rows: searchResults });

        const codes = await searchKPDCodes('cattle', 100);
        expect(codes).toEqual(searchResults);
        expect(mockPool.query).toHaveBeenCalled();
      });

      it('should use default limit if not provided', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await searchKPDCodes('test');
        expect(mockPool.query).toHaveBeenCalledWith(
          expect.any(String),
          expect.arrayContaining(['test', '%test%', 100])
        );
      });

      it('should handle search errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Search failed'));

        await expect(searchKPDCodes('test')).rejects.toThrow('Search failed');
      });
    });

    describe('getKPDCodesPaginated', () => {
      it('should get paginated KPD codes', async () => {
        const mockCodes = [sampleCode];
        mockPool.query
          .mockResolvedValueOnce({ rows: [{ total: '100' }] }) // Count query
          .mockResolvedValueOnce({ rows: mockCodes }); // Data query

        const result = await getKPDCodesPaginated(1, 10);
        expect(result.codes).toEqual(mockCodes);
        expect(result.total).toBe(100);
      });

      it('should handle pagination errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Pagination failed'));

        await expect(getKPDCodesPaginated(1, 10)).rejects.toThrow('Pagination failed');
      });
    });

    describe('getSyncStatistics', () => {
      it('should get sync statistics', async () => {
        mockPool.query.mockResolvedValue({
          rows: [
            {
              total_codes: '50000',
              active_codes: '48000',
              inactive_codes: '2000',
            },
          ],
        });

        const stats = await getSyncStatistics();
        expect(stats.total_codes).toBe(50000);
        expect(stats.active_codes).toBe(48000);
        expect(stats.inactive_codes).toBe(2000);
      });

      it('should handle statistics errors', async () => {
        mockPool.query.mockRejectedValue(new Error('Stats failed'));

        await expect(getSyncStatistics()).rejects.toThrow('Stats failed');
      });
    });

    describe('bulkInsertKPDCodes', () => {
      it('should bulk insert KPD codes', async () => {
        const codes = [sampleCode, { ...sampleCode, kpd_code: '010102' }];
        const mockClient = {
          query: jest.fn().mockResolvedValue({}),
          release: jest.fn(),
        };
        mockPool.connect.mockResolvedValue(mockClient);

        await bulkInsertKPDCodes(codes);

        expect(mockPool.connect).toHaveBeenCalled();
        expect(mockClient.query).toHaveBeenCalledWith('BEGIN');
        expect(mockClient.query).toHaveBeenCalledWith('COMMIT');
        expect(mockClient.release).toHaveBeenCalled();
      });

      it('should rollback on bulk insert error', async () => {
        const codes = [sampleCode];
        const mockClient = {
          query: jest.fn()
            .mockResolvedValueOnce({}) // BEGIN
            .mockRejectedValueOnce(new Error('Insert failed')), // INSERT fails
          release: jest.fn(),
        };
        mockPool.connect.mockResolvedValue(mockClient);

        await expect(bulkInsertKPDCodes(codes)).rejects.toThrow('Insert failed');

        expect(mockClient.query).toHaveBeenCalledWith('BEGIN');
        expect(mockClient.query).toHaveBeenCalledWith('ROLLBACK');
        expect(mockClient.release).toHaveBeenCalled();
      });
    });
  });
});
