import {
  createUser,
  getUserById,
  getUserByEmail,
  updateUser,
} from '../../../src/repositories/user-repository';
import { query } from '../../../src/shared/db';

// Mock the db module
jest.mock('../../../src/shared/db', () => ({
  initDb: jest.fn(),
  query: jest.fn(),
  getPool: jest.fn(),
}));

describe('User Repository', () => {
  const mockQuery = query as jest.MockedFunction<typeof query>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should insert user and return result', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'test@example.com',
        password_hash: 'hashedpassword123',
        name: 'Test User',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await createUser({
        email: 'test@example.com',
        passwordHash: 'hashedpassword123',
        name: 'Test User',
      });

      expect(result).toEqual(mockUser);
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0]).toContain('INSERT INTO users');
    });

    it('should insert user without optional name field', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'test@example.com',
        password_hash: 'hashedpassword123',
        name: null,
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await createUser({
        email: 'test@example.com',
        passwordHash: 'hashedpassword123',
      });

      expect(result).toEqual(mockUser);
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });

    it('should use parameterized queries', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      await createUser({
        email: 'test@example.com',
        passwordHash: 'hashedpassword123',
        name: 'Test User',
      });

      const sql = mockQuery.mock.calls[0][0];
      const params = mockQuery.mock.calls[0][1];

      // Check for parameterized queries ($1, $2, $3)
      expect(sql).toMatch(/\$[1-3]/);
      expect(params).toHaveLength(3);
      expect(params).toEqual(['test@example.com', 'hashedpassword123', 'Test User']);
    });
  });

  describe('getUserById', () => {
    it('should return user by ID', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'test@example.com',
        password_hash: 'hashedpassword123',
        name: 'Test User',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await getUserById('550e8400-e29b-41d4-a716-446655440000');

      expect(result).toEqual(mockUser);
      expect(mockQuery.mock.calls[0][1]).toEqual(['550e8400-e29b-41d4-a716-446655440000']);
    });

    it('should return null for non-existent ID', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const result = await getUserById('nonexistent-id');

      expect(result).toBeNull();
    });
  });

  describe('getUserByEmail', () => {
    it('should return user by email', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'test@example.com',
        password_hash: 'hashedpassword123',
        name: 'Test User',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await getUserByEmail('test@example.com');

      expect(result).toEqual(mockUser);
      expect(mockQuery.mock.calls[0][1]).toEqual(['test@example.com']);
    });

    it('should return null for non-existent email', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const result = await getUserByEmail('nonexistent@example.com');

      expect(result).toBeNull();
    });
  });

  describe('updateUser', () => {
    it('should update user email', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'newemail@example.com',
        password_hash: 'hashedpassword123',
        name: 'Test User',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await updateUser('550e8400-e29b-41d4-a716-446655440000', {
        email: 'newemail@example.com',
      });

      expect(result).toEqual(mockUser);
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery.mock.calls[0][0]).toContain('UPDATE users');
      expect(mockQuery.mock.calls[0][0]).toContain('email = $1');
    });

    it('should update user password hash', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'test@example.com',
        password_hash: 'newhashedpassword',
        name: 'Test User',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await updateUser('550e8400-e29b-41d4-a716-446655440000', {
        passwordHash: 'newhashedpassword',
      });

      expect(result).toEqual(mockUser);
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });

    it('should update user name', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'test@example.com',
        password_hash: 'hashedpassword123',
        name: 'Updated Name',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await updateUser('550e8400-e29b-41d4-a716-446655440000', {
        name: 'Updated Name',
      });

      expect(result).toEqual(mockUser);
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });

    it('should update multiple fields at once', async () => {
      const mockUser = {
        id: '550e8400-e29b-41d4-a716-446655440000',
        email: 'newemail@example.com',
        password_hash: 'newhashedpassword',
        name: 'Updated Name',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockQuery.mockResolvedValue({ rows: [mockUser] });

      const result = await updateUser('550e8400-e29b-41d4-a716-446655440000', {
        email: 'newemail@example.com',
        passwordHash: 'newhashedpassword',
        name: 'Updated Name',
      });

      expect(result).toEqual(mockUser);
      expect(mockQuery).toHaveBeenCalledTimes(1);

      const sql = mockQuery.mock.calls[0][0];
      expect(sql).toContain('email =');
      expect(sql).toContain('password_hash =');
      expect(sql).toContain('name =');
      expect(sql).toContain('updated_at = NOW()');
    });

    it('should use parameterized queries', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      await updateUser('550e8400-e29b-41d4-a716-446655440000', {
        email: 'newemail@example.com',
      });

      const sql = mockQuery.mock.calls[0][0];
      const params = mockQuery.mock.calls[0][1];

      // Check for parameterized queries
      expect(sql).toContain('$1');
      expect(sql).toContain('$2');
      expect(params).toHaveLength(2);
    });
  });

  describe('SQL Injection Safety', () => {
    it('should safely handle malicious input in ID', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      // SQL injection attempt
      const maliciousId = "'; DROP TABLE users; --";

      await getUserById(maliciousId);

      // The query should use parameterized statement
      const sql = mockQuery.mock.calls[0][0];
      expect(sql).toContain('$1');
      // Malicious string should be passed as parameter, not interpolated
      expect(mockQuery.mock.calls[0][1]).toEqual([maliciousId]);
    });

    it('should safely handle malicious input in email', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const maliciousEmail = "test@example.com'; DROP TABLE users; --";

      await getUserByEmail(maliciousEmail);

      const sql = mockQuery.mock.calls[0][0];
      expect(sql).toContain('$1');
      expect(mockQuery.mock.calls[0][1]).toEqual([maliciousEmail]);
    });

    it('should safely handle malicious input in update data', async () => {
      mockQuery.mockResolvedValue({ rows: [{}] });

      const maliciousEmail = "new@example.com'; DROP TABLE users; --";

      await updateUser('550e8400-e29b-41d4-a716-446655440000', {
        email: maliciousEmail,
      });

      const params = mockQuery.mock.calls[0][1];
      // Malicious string should be passed as parameter
      expect(params).toContain(maliciousEmail);
    });
  });
});
