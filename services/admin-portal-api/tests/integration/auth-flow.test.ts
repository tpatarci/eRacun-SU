import request from 'supertest';
import { createApp } from '../../src/index';
import { initializePool, getUserRepository } from '../../src/users/repository';
import { UserRole } from '../../src/auth/types';

describe('Authentication Flow Integration Tests', () => {
  let app: any;
  let testUserId: number;
  let authToken: string;

  beforeAll(async () => {
    // Set required environment variables
    process.env.JWT_SECRET = 'test-secret-key-for-testing-only';
    process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgresql://localhost:5432/admin_portal_test';
    process.env.BCRYPT_ROUNDS = '4'; // Faster for tests

    app = createApp();

    // Initialize database pool
    initializePool();

    // Create test user
    const userRepo = getUserRepository();
    try {
      const testUser = await userRepo.createUser({
        email: 'test@example.com',
        password: 'TestPassword123!@#',
        role: UserRole.ADMIN,
      });
      testUserId = testUser.id;
    } catch (err) {
      // User might already exist from previous test run
      const existingUser = await userRepo.getUserByEmail('test@example.com');
      if (existingUser) {
        testUserId = existingUser.id;
      } else {
        throw err;
      }
    }
  });

  afterAll(async () => {
    // Cleanup test user
    const userRepo = getUserRepository();
    await userRepo.deactivateUser(testUserId);

    // Close database pool
    const pool = initializePool();
    await pool.end();
  });

  describe('POST /api/v1/auth/login', () => {
    it('should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'TestPassword123!@#',
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe('test@example.com');

      // Save token for subsequent tests
      authToken = response.body.token;
    });

    it('should reject login with invalid password', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'WrongPassword',
        });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should reject login with non-existent email', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'SomePassword123!',
        });

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should reject login with missing fields', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'Email and password required');
    });
  });

  describe('GET /api/v1/auth/me', () => {
    it('should get current user info with valid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('id', testUserId);
      expect(response.body).toHaveProperty('email', 'test@example.com');
      expect(response.body).toHaveProperty('role', UserRole.ADMIN);
    });

    it('should reject request without token', async () => {
      const response = await request(app).get('/api/v1/auth/me');

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
    });

    it('should reject request with invalid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer invalid-token-12345');

      expect(response.status).toBe(403);
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    it('should logout successfully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message', 'Logged out successfully');
    });
  });
});
