import {
  createInvoice,
  updateInvoiceStatus,
  getInvoiceById,
  getInvoicesByOIB,
  updateStatus,
} from '../../../src/archive/invoice-repository';
import { initDb, query } from '../../../src/shared/db';

// Mock the db module
jest.mock('../../../src/shared/db', () => ({
  initDb: jest.fn(),
  query: jest.fn(),
  getPool: jest.fn(),
}));

describe('Invoice Repository', () => {
  const mockQuery = query as jest.MockedFunction<typeof query>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('createInvoice', () => {
    it('should insert invoice and return result (Test 7.2)', async () => {
      const mockInvoice = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        oib: '12345678903',
        invoice_number: '1/PP1/1',
        original_xml: '<Invoice/>',
        signed_xml: '<Invoice><Signature/></Invoice>',
        status: 'pending',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockInvoice] });

      const result = await createInvoice({
        oib: '12345678903',
        invoiceNumber: '1/PP1/1',
        originalXml: '<Invoice/>',
        signedXml: '<Invoice><Signature/></Invoice>',
      });

      expect(result).toEqual(mockInvoice);
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0]).toContain('INSERT INTO invoices');
    });

    it('should use parameterized queries (Test 7.8, 7.9)', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      await createInvoice({
        oib: '12345678903',
        invoiceNumber: '1/PP1/1',
        originalXml: '<Invoice/>',
        signedXml: '<Invoice><Signature/></Invoice>',
      });

      const sql = mockQuery.mock.calls[0][0];
      const params = mockQuery.mock.calls[0][1];

      // Check for parameterized queries ($1, $2, etc.)
      expect(sql).toMatch(/\$[1-4]/);
      expect(params).toHaveLength(4);
    });
  });

  describe('updateInvoiceStatus', () => {
    it('should update status and JIR (Test 7.3)', async () => {
      mockQuery.mockResolvedValue({ rowCount: 1 });

      await updateInvoiceStatus(
        '550e8400-e29b-41d4-a716-446655440000',
        'completed',
        'JIR-12345',
        { success: true }
      );

      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][1]).toEqual(['completed', 'JIR-12345', '{"success":true}', '550e8400-e29b-41d4-a716-446655440000']);
    });
  });

  describe('getInvoiceById', () => {
    it('should return invoice by ID (Test 7.4)', async () => {
      const mockInvoice = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        oib: '12345678903',
        status: 'completed',
      };

      mockQuery.mockResolvedValue({ rows: [mockInvoice] });

      const result = await getInvoiceById('550e8400-e29b-41d4-a716-446655440000');

      expect(result).toEqual(mockInvoice);
      expect(mockQuery.mock.calls[0][1]).toEqual(['550e8400-e29b-41d4-a716-446655440000']);
    });

    it('should return null for non-existent ID', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const result = await getInvoiceById('nonexistent-id');

      expect(result).toBeNull();
    });
  });

  describe('getInvoicesByOIB', () => {
    it('should return invoices by OIB (Test 7.5)', async () => {
      const mockInvoices = [
        { id: '1', oib: '12345678903' },
        { id: '2', oib: '12345678903' },
      ];

      mockQuery.mockResolvedValue({ rows: mockInvoices });

      const result = await getInvoicesByOIB('12345678903');

      expect(result).toEqual(mockInvoices);
      expect(mockQuery.mock.calls[0][1]).toEqual(['12345678903', 50, 0]);
    });

    it('should support custom limit and offset', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      await getInvoicesByOIB('12345678903', 100, 50);

      expect(mockQuery.mock.calls[0][1]).toEqual(['12345678903', 100, 50]);
    });
  });

  describe('updateStatus', () => {
    it('should update invoice status', async () => {
      mockQuery.mockResolvedValue({ rowCount: 1 });

      await updateStatus('550e8400-e29b-41d4-a716-446655440000', 'processing');

      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][1]).toEqual(['processing', '550e8400-e29b-41d4-a716-446655440000']);
    });
  });

  describe('SQL Injection Safety (Test 7.7)', () => {
    it('should safely handle malicious input in ID', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      // SQL injection attempt
      const maliciousId = "'; DROP TABLE invoices; --";

      await getInvoiceById(maliciousId);

      // The query should use parameterized statement
      const sql = mockQuery.mock.calls[0][0];
      expect(sql).toContain('$1');
      // Malicious string should be passed as parameter, not interpolated
      expect(mockQuery.mock.calls[0][1]).toEqual([maliciousId]);
    });
  });
});
