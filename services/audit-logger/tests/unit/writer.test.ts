/**
 * Unit tests for writer.ts
 * Tests hash calculation, event writing, queries, and error handling
 */

import { Pool } from 'pg';
import {
  calculateEventHash,
  getLastEventHash,
  writeAuditEvent,
  getAuditTrail,
  queryAuditEvents,
  initPool,
  closePool,
  AuditEvent,
} from '../../src/writer';
import * as observability from '../../src/observability';

// Mock dependencies
jest.mock('pg');
jest.mock('../../src/observability');

describe('writer.ts', () => {
  let mockPool: jest.Mocked<Pool>;
  let mockQuery: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup mock pool
    mockQuery = jest.fn();
    mockPool = {
      query: mockQuery,
      on: jest.fn(),
      end: jest.fn(),
    } as any;

    (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => mockPool);

    // Mock observability functions
    (observability.auditEventsWritten as any) = { inc: jest.fn() };
    (observability.auditWriteDuration as any) = { observe: jest.fn() };
    (observability.auditDbConnections as any) = { inc: jest.fn(), dec: jest.fn() };
    (observability.createSpan as any) = jest.fn().mockReturnValue({ end: jest.fn(), setAttribute: jest.fn() });
    (observability.setSpanError as any) = jest.fn();
    (observability.logger as any) = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
  });

  afterEach(async () => {
    await closePool();
  });

  describe('calculateEventHash', () => {
    it('should calculate deterministic SHA-256 hash', () => {
      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: { schema_type: 'UBL_2_1' },
        previous_hash: 'abc123',
      };

      const hash1 = calculateEventHash(event);
      const hash2 = calculateEventHash(event);

      // Same input = same hash
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex string
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce different hashes for different events', () => {
      const event1: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
      };

      const event2: AuditEvent = {
        ...event1,
        event_id: 'evt-002',
      };

      const hash1 = calculateEventHash(event1);
      const hash2 = calculateEventHash(event2);

      expect(hash1).not.toBe(hash2);
    });

    it('should include previous_hash in calculation', () => {
      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
      };

      const hash1 = calculateEventHash({ ...event, previous_hash: 'abc123' });
      const hash2 = calculateEventHash({ ...event, previous_hash: 'def456' });

      expect(hash1).not.toBe(hash2);
    });

    it('should handle missing previous_hash (first event)', () => {
      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
      };

      const hash = calculateEventHash(event);

      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('getLastEventHash', () => {
    it('should return hash of most recent event', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ event_hash: 'abc123' }],
      });

      const hash = await getLastEventHash();

      expect(hash).toBe('abc123');
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1')
      );
    });

    it('should return null if no events exist (first event)', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
      });

      const hash = await getLastEventHash();

      expect(hash).toBeNull();
    });

    it('should throw error on database failure', async () => {
      const dbError = new Error('Connection failed');
      mockQuery.mockRejectedValueOnce(dbError);

      await expect(getLastEventHash()).rejects.toThrow('Connection failed');
      expect(observability.setSpanError).toHaveBeenCalled();
    });
  });

  describe('writeAuditEvent', () => {
    let mockClient: any;
    let mockClientQuery: jest.Mock;
    let mockRelease: jest.Mock;

    beforeEach(() => {
      // Setup mock client for transaction
      mockClientQuery = jest.fn();
      mockRelease = jest.fn();
      mockClient = {
        query: mockClientQuery,
        release: mockRelease,
      };

      // Mock pool.connect() to return our mock client
      mockPool.connect = jest.fn().mockResolvedValue(mockClient);
    });

    it('should write event with hash chain using transaction', async () => {
      // Mock transaction queries: BEGIN, SELECT FOR UPDATE, INSERT, COMMIT
      mockClientQuery
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [{ event_hash: 'previous-hash-123' }] }) // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [] }) // INSERT
        .mockResolvedValueOnce({ rows: [] }); // COMMIT

      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        user_id: 'user-123',
        request_id: 'req-001',
        metadata: { schema_type: 'UBL_2_1' },
      };

      await writeAuditEvent(event);

      // Verify transaction flow
      expect(mockClientQuery).toHaveBeenCalledTimes(4);
      expect(mockClientQuery.mock.calls[0][0]).toBe('BEGIN');
      expect(mockClientQuery.mock.calls[1][0]).toContain('SELECT event_hash FROM audit_events');
      expect(mockClientQuery.mock.calls[1][0]).toContain('FOR UPDATE');
      expect(mockClientQuery.mock.calls[2][0]).toContain('INSERT INTO audit_events');
      expect(mockClientQuery.mock.calls[3][0]).toBe('COMMIT');

      // Verify INSERT parameters
      const insertCall = mockClientQuery.mock.calls[2];
      expect(insertCall[1][0]).toBe('evt-001'); // event_id
      expect(insertCall[1][1]).toBe('inv-001'); // invoice_id
      expect(insertCall[1][8]).toBe('previous-hash-123'); // previous_hash
      expect(insertCall[1][9]).toMatch(/^[a-f0-9]{64}$/); // event_hash

      // Verify client released
      expect(mockRelease).toHaveBeenCalled();

      // Verify metrics were updated
      expect(observability.auditEventsWritten.inc).toHaveBeenCalledWith({
        service: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
      });
      expect(observability.auditWriteDuration.observe).toHaveBeenCalled();
    });

    it('should write first event with null previous_hash', async () => {
      // Mock transaction queries for first event (no previous hash)
      mockClientQuery
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [] }) // SELECT FOR UPDATE (no rows = first event)
        .mockResolvedValueOnce({ rows: [] }) // INSERT
        .mockResolvedValueOnce({ rows: [] }); // COMMIT

      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
      };

      await writeAuditEvent(event);

      const insertCall = mockClientQuery.mock.calls[2];
      expect(insertCall[1][8]).toBeNull(); // previous_hash should be null
    });

    it('should use provided event_hash if present', async () => {
      mockClientQuery
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [] }) // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [] }) // INSERT
        .mockResolvedValueOnce({ rows: [] }); // COMMIT

      const customHash = 'a'.repeat(64);
      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
        event_hash: customHash,
      };

      await writeAuditEvent(event);

      const insertCall = mockClientQuery.mock.calls[2];
      expect(insertCall[1][9]).toBe(customHash);
    });

    it('should throw error on database failure and rollback', async () => {
      mockClientQuery
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [] }) // SELECT FOR UPDATE
        .mockRejectedValueOnce(new Error('INSERT failed')); // INSERT fails

      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
      };

      await expect(writeAuditEvent(event)).rejects.toThrow('INSERT failed');

      // Verify ROLLBACK was called
      expect(mockClientQuery).toHaveBeenCalledWith('ROLLBACK');

      // Verify client was released
      expect(mockRelease).toHaveBeenCalled();

      expect(observability.setSpanError).toHaveBeenCalled();
    });

    it('should handle missing optional fields', async () => {
      mockClientQuery
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [] }) // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [] }) // INSERT
        .mockResolvedValueOnce({ rows: [] }); // COMMIT

      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
        // user_id omitted (optional)
      };

      await writeAuditEvent(event);

      const insertCall = mockClientQuery.mock.calls[2];
      expect(insertCall[1][5]).toBeNull(); // user_id should be null
    });

    it('should use SELECT FOR UPDATE to prevent race conditions', async () => {
      // This test verifies the fix for the hash chain race condition
      // See P1 review comment: concurrent writers must not read same previous_hash
      mockClientQuery
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [{ event_hash: 'locked-hash' }] }) // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [] }) // INSERT
        .mockResolvedValueOnce({ rows: [] }); // COMMIT

      const event: AuditEvent = {
        event_id: 'evt-001',
        invoice_id: 'inv-001',
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_STARTED',
        timestamp_ms: 1700000000000,
        request_id: 'req-001',
        metadata: {},
      };

      await writeAuditEvent(event);

      // Verify SELECT FOR UPDATE was used (not just SELECT)
      const selectQuery = mockClientQuery.mock.calls[1][0];
      expect(selectQuery).toContain('FOR UPDATE');
      expect(selectQuery).toContain('ORDER BY id DESC LIMIT 1');

      // Verify the locked hash was used as previous_hash
      const insertCall = mockClientQuery.mock.calls[2];
      expect(insertCall[1][8]).toBe('locked-hash');
    });
  });

  describe('getAuditTrail', () => {
    it('should return events for invoice_id', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          invoice_id: 'inv-001',
          service_name: 'xsd-validator',
          event_type: 'VALIDATION_STARTED',
          timestamp_ms: '1700000000000',
          user_id: 'user-123',
          request_id: 'req-001',
          metadata: JSON.stringify({ schema_type: 'UBL_2_1' }),
          previous_hash: null,
          event_hash: 'abc123',
        },
        {
          event_id: 'evt-002',
          invoice_id: 'inv-001',
          service_name: 'xsd-validator',
          event_type: 'VALIDATION_PASSED',
          timestamp_ms: '1700000001000',
          user_id: 'user-123',
          request_id: 'req-001',
          metadata: JSON.stringify({ validation_duration_ms: 50 }),
          previous_hash: 'abc123',
          event_hash: 'def456',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const events = await getAuditTrail('inv-001');

      expect(events).toHaveLength(2);
      expect(events[0].event_id).toBe('evt-001');
      expect(events[0].metadata).toEqual({ schema_type: 'UBL_2_1' });
      expect(events[1].event_id).toBe('evt-002');
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE invoice_id = $1'),
        ['inv-001']
      );
    });

    it('should return empty array if no events found', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });

      const events = await getAuditTrail('inv-999');

      expect(events).toEqual([]);
    });

    it('should parse metadata JSON correctly', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          invoice_id: 'inv-001',
          service_name: 'xsd-validator',
          event_type: 'VALIDATION_FAILED',
          timestamp_ms: '1700000000000',
          request_id: 'req-001',
          metadata: '{"error":"Missing required field","line_number":42}',
          event_hash: 'abc123',
        },
      ];

      mockQuery.mockResolvedValueOnce({ rows: mockRows });

      const events = await getAuditTrail('inv-001');

      expect(events[0].metadata).toEqual({
        error: 'Missing required field',
        line_number: 42,
      });
    });
  });

  describe('queryAuditEvents', () => {
    it('should filter by service_name', async () => {
      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '5' }] }) // COUNT query
        .mockResolvedValueOnce({ rows: [] }); // Data query

      await queryAuditEvents({ service_name: 'xsd-validator' });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE service_name = $1'),
        expect.arrayContaining(['xsd-validator'])
      );
    });

    it('should filter by event_type', async () => {
      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '3' }] })
        .mockResolvedValueOnce({ rows: [] });

      await queryAuditEvents({ event_type: 'VALIDATION_FAILED' });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE event_type = $1'),
        expect.arrayContaining(['VALIDATION_FAILED'])
      );
    });

    it('should filter by timestamp range', async () => {
      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '10' }] })
        .mockResolvedValueOnce({ rows: [] });

      await queryAuditEvents({
        start_timestamp_ms: 1700000000000,
        end_timestamp_ms: 1700010000000,
      });

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('timestamp_ms >= $1'),
        expect.arrayContaining([1700000000000, 1700010000000])
      );
    });

    it('should combine multiple filters', async () => {
      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '2' }] })
        .mockResolvedValueOnce({ rows: [] });

      await queryAuditEvents({
        service_name: 'xsd-validator',
        event_type: 'VALIDATION_FAILED',
        start_timestamp_ms: 1700000000000,
      });

      const countCall = mockQuery.mock.calls[0];
      expect(countCall[0]).toContain('WHERE');
      expect(countCall[0]).toContain('service_name');
      expect(countCall[0]).toContain('event_type');
      expect(countCall[0]).toContain('timestamp_ms');
    });

    it('should apply default pagination (limit 100, offset 0)', async () => {
      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '150' }] })
        .mockResolvedValueOnce({ rows: [] });

      const result = await queryAuditEvents({});

      const dataCall = mockQuery.mock.calls[1];
      expect(dataCall[1]).toContain(100); // limit
      expect(dataCall[1]).toContain(0);   // offset
    });

    it('should apply custom pagination', async () => {
      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '150' }] })
        .mockResolvedValueOnce({ rows: [] });

      await queryAuditEvents({ limit: 50, offset: 25 });

      const dataCall = mockQuery.mock.calls[1];
      expect(dataCall[1]).toContain(50); // limit
      expect(dataCall[1]).toContain(25); // offset
    });

    it('should return events and total count', async () => {
      const mockRows = [
        {
          event_id: 'evt-001',
          invoice_id: 'inv-001',
          service_name: 'xsd-validator',
          event_type: 'VALIDATION_STARTED',
          timestamp_ms: '1700000000000',
          request_id: 'req-001',
          metadata: '{}',
          event_hash: 'abc123',
        },
      ];

      mockQuery
        .mockResolvedValueOnce({ rows: [{ count: '42' }] })
        .mockResolvedValueOnce({ rows: mockRows });

      const result = await queryAuditEvents({});

      expect(result.total).toBe(42);
      expect(result.events).toHaveLength(1);
      expect(result.events[0].event_id).toBe('evt-001');
    });
  });

  describe('Pool Management', () => {
    it('should initialize pool with environment variables', () => {
      process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
      process.env.DATABASE_POOL_MIN = '5';
      process.env.DATABASE_POOL_MAX = '25';

      initPool();

      expect(Pool).toHaveBeenCalledWith(
        expect.objectContaining({
          connectionString: 'postgresql://test:test@localhost:5432/test',
          min: 5,
          max: 25,
        })
      );
    });

    it('should use default pool sizes if not specified', () => {
      delete process.env.DATABASE_POOL_MIN;
      delete process.env.DATABASE_POOL_MAX;

      initPool();

      expect(Pool).toHaveBeenCalledWith(
        expect.objectContaining({
          min: 10,
          max: 50,
        })
      );
    });

    it('should close pool cleanly', async () => {
      initPool();
      await closePool();

      expect(mockPool.end).toHaveBeenCalled();
    });
  });
});
