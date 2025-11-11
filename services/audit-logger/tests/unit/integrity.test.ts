/**
 * Unit tests for integrity.ts
 * Tests hash chain verification logic
 */

import { Pool } from 'pg';
import {
  verifyIntegrity,
  verifyFullIntegrity,
  verifyInvoiceIntegrity,
} from '../../src/integrity';
import * as observability from '../../src/observability';
import * as writer from '../../src/writer';

// Mock dependencies
jest.mock('pg');
jest.mock('../../src/observability');
jest.mock('../../src/writer');

describe('integrity.ts', () => {
  let mockPool: jest.Mocked<Pool>;
  let mockQuery: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup mock pool
    mockQuery = jest.fn();
    mockPool = {
      query: mockQuery,
    } as any;

    (writer.getPool as jest.Mock).mockReturnValue(mockPool);

    // Mock observability
    (observability.auditIntegrityVerifications as any) = { inc: jest.fn() };
    (observability.auditIntegrityErrors as any) = { inc: jest.fn() };
    (observability.createSpan as any) = jest.fn().mockReturnValue({
      end: jest.fn(),
      setAttribute: jest.fn(),
    });
    (observability.setSpanError as any) = jest.fn();
    (observability.logger as any) = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
  });

  describe('verifyIntegrity', () => {
    it('should verify valid hash chain', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'hash-001',
          timestamp_ms: '1700000001000',
        },
        {
          event_id: 'evt-003',
          event_hash: 'hash-003',
          previous_hash: 'hash-002',
          timestamp_ms: '1700000002000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyIntegrity(1700000000000, 1700000003000);

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(3);
      expect(result.broken_chains).toEqual([]);
      expect(observability.auditIntegrityVerifications.inc).toHaveBeenCalledWith({
        result: 'valid',
      });
    });

    it('should detect broken hash chain', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'hash-001',
          timestamp_ms: '1700000001000',
        },
        {
          event_id: 'evt-003',
          event_hash: 'hash-003',
          previous_hash: 'WRONG-HASH', // Broken chain!
          timestamp_ms: '1700000002000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyIntegrity(1700000000000, 1700000003000);

      expect(result.integrity_valid).toBe(false);
      expect(result.total_events).toBe(3);
      expect(result.broken_chains).toContain('evt-003');
      expect(observability.auditIntegrityErrors.inc).toHaveBeenCalled();
      expect(observability.logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          event_id: 'evt-003',
          expected: 'hash-002',
          actual: 'WRONG-HASH',
        }),
        expect.stringContaining('Hash chain broken')
      );
    });

    it('should handle multiple broken chains', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'WRONG-1',
          timestamp_ms: '1700000001000',
        },
        {
          event_id: 'evt-003',
          event_hash: 'hash-003',
          previous_hash: 'hash-002',
          timestamp_ms: '1700000002000',
        },
        {
          event_id: 'evt-004',
          event_hash: 'hash-004',
          previous_hash: 'WRONG-2',
          timestamp_ms: '1700000003000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyIntegrity(1700000000000, 1700000004000);

      expect(result.integrity_valid).toBe(false);
      expect(result.broken_chains).toEqual(['evt-002', 'evt-004']);
    });

    it('should handle first event with null previous_hash', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null, // First event
          timestamp_ms: '1700000000000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyIntegrity(1700000000000, 1700000001000);

      expect(result.integrity_valid).toBe(true);
      expect(result.broken_chains).toEqual([]);
    });

    it('should return valid for empty event set', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      const result = await verifyIntegrity(1700000000000, 1700000001000);

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(0);
      expect(result.broken_chains).toEqual([]);
    });

    it('should measure verification time', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      const result = await verifyIntegrity(1700000000000, 1700000001000);

      expect(result.verification_time_ms).toBeGreaterThanOrEqual(0);
      expect(typeof result.verification_time_ms).toBe('number');
    });

    it('should query with correct time range', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      await verifyIntegrity(1700000000000, 1700010000000);

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE timestamp_ms BETWEEN $1 AND $2'),
        [1700000000000, 1700010000000]
      );
    });

    it('should order events by timestamp and id', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      await verifyIntegrity(1700000000000, 1700010000000);

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('ORDER BY timestamp_ms ASC, id ASC'),
        expect.any(Array)
      );
    });

    it('should throw error on database failure', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Database connection lost'));

      await expect(verifyIntegrity(1700000000000, 1700010000000)).rejects.toThrow(
        'Database connection lost'
      );
      expect(observability.setSpanError).toHaveBeenCalled();
    });
  });

  describe('verifyFullIntegrity', () => {
    it('should verify entire audit log', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'hash-001',
          timestamp_ms: '1700000001000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyFullIntegrity();

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(2);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('SELECT event_id, event_hash, previous_hash, timestamp_ms'),
        []
      );
    });

    it('should not filter by timestamp (full scan)', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      await verifyFullIntegrity();

      const query = mockQuery.mock.calls[0][0];
      expect(query).not.toContain('WHERE');
      expect(query).not.toContain('timestamp_ms BETWEEN');
    });

    it('should log warning for full integrity check', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      await verifyFullIntegrity();

      expect(observability.logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Full integrity verification')
      );
    });
  });

  describe('verifyInvoiceIntegrity', () => {
    it('should verify hash chain for specific invoice', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'hash-001',
          timestamp_ms: '1700000001000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyInvoiceIntegrity('inv-001');

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(2);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE invoice_id = $1'),
        ['inv-001']
      );
    });

    it('should detect broken chain within invoice events', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'WRONG-HASH',
          timestamp_ms: '1700000001000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyInvoiceIntegrity('inv-001');

      expect(result.integrity_valid).toBe(false);
      expect(result.broken_chains).toContain('evt-002');
    });

    it('should handle invoice with no events', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      const result = await verifyInvoiceIntegrity('inv-999');

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(0);
      expect(result.broken_chains).toEqual([]);
    });

    it('should handle invoice with single event', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyInvoiceIntegrity('inv-001');

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(1);
    });
  });

  describe('Hash Chain Edge Cases', () => {
    it('should handle events with same timestamp (ordered by id)', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'hash-001',
          timestamp_ms: '1700000000000', // Same timestamp
        },
        {
          event_id: 'evt-003',
          event_hash: 'hash-003',
          previous_hash: 'hash-002',
          timestamp_ms: '1700000000000', // Same timestamp
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyIntegrity(1700000000000, 1700000001000);

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(3);
    });

    it('should handle large event sets efficiently', async () => {
      // Generate 1000 events with valid chain
      const mockRows = Array.from({ length: 1000 }, (_, i) => ({
        event_id: `evt-${String(i + 1).padStart(4, '0')}`,
        event_hash: `hash-${String(i + 1).padStart(4, '0')}`,
        previous_hash: i === 0 ? null : `hash-${String(i).padStart(4, '0')}`,
        timestamp_ms: String(1700000000000 + i * 1000),
      }));

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const startTime = Date.now();
      const result = await verifyIntegrity(1700000000000, 1700001000000);
      const duration = Date.now() - startTime;

      expect(result.integrity_valid).toBe(true);
      expect(result.total_events).toBe(1000);
      expect(duration).toBeLessThan(1000); // Should complete in <1s
    });

    it('should detect corruption in middle of large chain', async () => {
      // Generate 1000 events with corruption at event 500
      const mockRows = Array.from({ length: 1000 }, (_, i) => ({
        event_id: `evt-${String(i + 1).padStart(4, '0')}`,
        event_hash: `hash-${String(i + 1).padStart(4, '0')}`,
        previous_hash:
          i === 0
            ? null
            : i === 500
            ? 'CORRUPTED-HASH' // Corruption!
            : `hash-${String(i).padStart(4, '0')}`,
        timestamp_ms: String(1700000000000 + i * 1000),
      }));

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const result = await verifyIntegrity(1700000000000, 1700001000000);

      expect(result.integrity_valid).toBe(false);
      expect(result.broken_chains).toContain('evt-0500');
      expect(result.broken_chains.length).toBe(1); // Only one break
    });
  });

  describe('Performance and Observability', () => {
    it('should create tracing span', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      await verifyIntegrity(1700000000000, 1700000001000);

      expect(observability.createSpan).toHaveBeenCalledWith('verify_integrity');
    });

    it('should record success metrics', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      await verifyIntegrity(1700000000000, 1700000001000);

      expect(observability.auditIntegrityVerifications.inc).toHaveBeenCalledWith({
        result: 'valid',
      });
    });

    it('should record failure metrics', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          event_hash: 'hash-001',
          previous_hash: null,
          timestamp_ms: '1700000000000',
        },
        {
          event_id: 'evt-002',
          event_hash: 'hash-002',
          previous_hash: 'WRONG',
          timestamp_ms: '1700000001000',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      await verifyIntegrity(1700000000000, 1700000002000);

      expect(observability.auditIntegrityVerifications.inc).toHaveBeenCalledWith({
        result: 'invalid',
      });
      expect(observability.auditIntegrityErrors.inc).toHaveBeenCalled();
    });
  });
});
