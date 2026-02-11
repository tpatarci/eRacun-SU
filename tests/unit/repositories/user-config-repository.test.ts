import {
  createConfig,
  getConfigs,
  getConfig,
  updateConfig,
  deleteConfig,
} from '../../../src/repositories/user-config-repository';
import { query } from '../../../src/shared/db';

// Mock the db module
jest.mock('../../../src/shared/db', () => ({
  initDb: jest.fn(),
  query: jest.fn(),
  getPool: jest.fn(),
}));

describe('User Config Repository', () => {
  const mockQuery = query as jest.MockedFunction<typeof query>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('createConfig', () => {
    it('should insert config and return result', async () => {
      const mockConfig = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        user_id: 'user-123',
        service_name: 'fina' as const,
        config: { wsdlUrl: 'https://test.com', certPath: '/path/to/cert' },
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockConfig] });

      const result = await createConfig({
        userId: 'user-123',
        serviceName: 'fina',
        config: { wsdlUrl: 'https://test.com', certPath: '/path/to/cert' },
      });

      expect(result).toEqual(mockConfig);
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0]).toContain('INSERT INTO user_configurations');
    });

    it('should insert config for imap service', async () => {
      const mockConfig = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        user_id: 'user-123',
        service_name: 'imap' as const,
        config: { host: 'imap.example.com', port: 993 },
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockConfig] });

      const result = await createConfig({
        userId: 'user-123',
        serviceName: 'imap',
        config: { host: 'imap.example.com', port: 993 },
      });

      expect(result).toEqual(mockConfig);
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });

    it('should use parameterized queries', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      await createConfig({
        userId: 'user-123',
        serviceName: 'fina',
        config: { key: 'value' },
      });

      const sql = mockQuery.mock.calls[0][0];
      const params = mockQuery.mock.calls[0][1];

      // Check for parameterized queries ($1, $2, $3)
      expect(sql).toMatch(/\$[1-3]/);
      expect(params).toHaveLength(3);
      expect(params[0]).toBe('user-123');
      expect(params[1]).toBe('fina');
      expect(params[2]).toBe(JSON.stringify({ key: 'value' }));
    });

    it('should serialize config as JSON', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      const configData = { nested: { key: 'value' }, array: [1, 2, 3] };

      await createConfig({
        userId: 'user-123',
        serviceName: 'fina',
        config: configData,
      });

      const params = mockQuery.mock.calls[0][1];
      expect(params[2]).toBe(JSON.stringify(configData));
    });
  });

  describe('getConfigs', () => {
    it('should return all configs for user ordered by created_at DESC', async () => {
      const mockConfigs = [
        {
          id: 'config-1',
          user_id: 'user-123',
          service_name: 'fina' as const,
          config: { key: 'value1' },
          created_at: new Date('2024-01-02'),
          updated_at: new Date(),
        },
        {
          id: 'config-2',
          user_id: 'user-123',
          service_name: 'imap' as const,
          config: { key: 'value2' },
          created_at: new Date('2024-01-01'),
          updated_at: new Date(),
        },
      ];

      mockQuery.mockResolvedValue({ rows: mockConfigs });

      const result = await getConfigs('user-123');

      expect(result).toEqual(mockConfigs);
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0]).toContain('SELECT * FROM user_configurations WHERE user_id = $1 ORDER BY created_at DESC');
      expect(mockQuery.mock.calls[0][1]).toEqual(['user-123']);
    });

    it('should return empty array for user with no configs', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const result = await getConfigs('nonexistent-user');

      expect(result).toEqual([]);
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });
  });

  describe('getConfig', () => {
    it('should return config by user ID and service name', async () => {
      const mockConfig = {
        id: 'config-1',
        user_id: 'user-123',
        service_name: 'fina' as const,
        config: { wsdlUrl: 'https://test.com' },
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockConfig] });

      const result = await getConfig('user-123', 'fina');

      expect(result).toEqual(mockConfig);
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][1]).toEqual(['user-123', 'fina']);
    });

    it('should return imap config', async () => {
      const mockConfig = {
        id: 'config-2',
        user_id: 'user-123',
        service_name: 'imap' as const,
        config: { host: 'imap.example.com' },
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockConfig] });

      const result = await getConfig('user-123', 'imap');

      expect(result).toEqual(mockConfig);
      expect(mockQuery.mock.calls[0][1]).toEqual(['user-123', 'imap']);
    });

    it('should return null for non-existent config', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const result = await getConfig('user-123', 'fina');

      expect(result).toBeNull();
    });
  });

  describe('updateConfig', () => {
    it('should update config and return result', async () => {
      const mockConfig = {
        id: 'config-1',
        user_id: 'user-123',
        service_name: 'fina' as const,
        config: { wsdlUrl: 'https://new-url.com', certPath: '/new/path' },
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockConfig] });

      const result = await updateConfig('user-123', 'fina', {
        wsdlUrl: 'https://new-url.com',
        certPath: '/new/path',
      });

      expect(result).toEqual(mockConfig);
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0]).toContain('UPDATE user_configurations');
      expect(mockQuery.mock.calls[0][0]).toContain('SET config = $1, updated_at = NOW()');
    });

    it('should serialize config as JSON', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      const configData = { updated: 'value', nested: { data: 123 } };

      await updateConfig('user-123', 'fina', configData);

      const params = mockQuery.mock.calls[0][1];
      expect(params[0]).toBe(JSON.stringify(configData));
    });

    it('should use parameterized queries', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      await updateConfig('user-123', 'fina', { key: 'value' });

      const sql = mockQuery.mock.calls[0][0];
      const params = mockQuery.mock.calls[0][1];

      // Check for parameterized queries ($1, $2, $3)
      expect(sql).toMatch(/\$[1-3]/);
      expect(params).toHaveLength(3);
      expect(params[0]).toBe(JSON.stringify({ key: 'value' }));
      expect(params[1]).toBe('user-123');
      expect(params[2]).toBe('fina');
    });

    it('should include WHERE clause for user and service', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      await updateConfig('user-123', 'imap', { host: 'new.example.com' });

      const sql = mockQuery.mock.calls[0][0];
      expect(sql).toContain('WHERE user_id = $2 AND service_name = $3');
    });
  });

  describe('deleteConfig', () => {
    it('should delete config by user ID and service name', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      await deleteConfig('user-123', 'fina');

      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0]).toContain('DELETE FROM user_configurations WHERE user_id = $1 AND service_name = $2');
      expect(mockQuery.mock.calls[0][1]).toEqual(['user-123', 'fina']);
    });

    it('should delete imap config', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      await deleteConfig('user-123', 'imap');

      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][1]).toEqual(['user-123', 'imap']);
    });

    it('should not return value', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const result = await deleteConfig('user-123', 'fina');

      expect(result).toBeUndefined();
    });
  });

  describe('SQL Injection Safety', () => {
    it('should safely handle malicious input in userId', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      // SQL injection attempt
      const maliciousUserId = "'; DROP TABLE user_configurations; --";

      await getConfig(maliciousUserId, 'fina');

      // The query should use parameterized statement
      const sql = mockQuery.mock.calls[0][0];
      expect(sql).toContain('$1');
      expect(sql).toContain('$2');
      // Malicious string should be passed as parameter, not interpolated
      expect(mockQuery.mock.calls[0][1]).toEqual([maliciousUserId, 'fina']);
    });

    it('should safely handle malicious input in serviceName', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const maliciousService = "fina'; DROP TABLE user_configurations; --";

      await getConfig('user-123', maliciousService as 'fina' | 'imap');

      const sql = mockQuery.mock.calls[0][0];
      expect(sql).toContain('$1');
      expect(sql).toContain('$2');
      expect(mockQuery.mock.calls[0][1]).toEqual(['user-123', maliciousService]);
    });

    it('should safely handle malicious input in config data', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      const maliciousConfig = { key: "value'; DROP TABLE user_configurations; --" };

      await createConfig({
        userId: 'user-123',
        serviceName: 'fina',
        config: maliciousConfig,
      });

      const params = mockQuery.mock.calls[0][1];
      // Malicious string should be passed as parameter
      expect(params[2]).toBe(JSON.stringify(maliciousConfig));
    });

    it('should safely handle malicious input in update config', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      const maliciousConfig = { key: "value'; DROP TABLE user_configurations; --" };

      await updateConfig('user-123', 'fina', maliciousConfig);

      const params = mockQuery.mock.calls[0][1];
      // Malicious string should be passed as parameter
      expect(params[0]).toBe(JSON.stringify(maliciousConfig));
    });
  });
});
