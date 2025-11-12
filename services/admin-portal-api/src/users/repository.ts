import { Pool, PoolConfig } from 'pg';
import bcrypt from 'bcrypt';
import { User, CreateUserRequest, UpdateUserRequest } from './types';
import { UserRole } from '../auth/types';
import { logger } from '../observability';

// PostgreSQL connection pool
let pool: Pool | null = null;

/**
 * Initialize database connection pool
 */
export function initializePool(config?: PoolConfig) {
  if (pool) {
    return pool;
  }

  const poolConfig: PoolConfig = config || {
    connectionString: process.env.DATABASE_URL,
    min: 10,
    max: 50,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  };

  pool = new Pool(poolConfig);

  // Log pool errors
  pool.on('error', (err) => {
    logger.error({
      error: err.message,
      stack: err.stack,
      msg: 'PostgreSQL pool error',
    });
  });

  logger.info('PostgreSQL connection pool initialized');

  return pool;
}

/**
 * Get database pool
 */
export function getPool(): Pool {
  if (!pool) {
    return initializePool();
  }
  return pool;
}

/**
 * User repository
 */
export class UserRepository {
  private pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  /**
   * Create a new user
   */
  async createUser(request: CreateUserRequest): Promise<User> {
    const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
    const passwordHash = await bcrypt.hash(request.password, bcryptRounds);

    const query = `
      INSERT INTO users (email, password_hash, role, active, created_at)
      VALUES ($1, $2, $3, true, NOW())
      RETURNING id, email, password_hash, role, active, created_at, last_login
    `;

    const result = await this.pool.query(query, [
      request.email,
      passwordHash,
      request.role,
    ]);

    return this.mapRowToUser(result.rows[0]);
  }

  /**
   * Get user by email
   */
  async getUserByEmail(email: string): Promise<User | null> {
    const query = `
      SELECT id, email, password_hash, role, active, created_at, last_login
      FROM users
      WHERE email = $1
    `;

    const result = await this.pool.query(query, [email]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRowToUser(result.rows[0]);
  }

  /**
   * Get user by ID
   */
  async getUserById(id: number): Promise<User | null> {
    const query = `
      SELECT id, email, password_hash, role, active, created_at, last_login
      FROM users
      WHERE id = $1
    `;

    const result = await this.pool.query(query, [id]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRowToUser(result.rows[0]);
  }

  /**
   * Get all users
   */
  async getAllUsers(): Promise<User[]> {
    const query = `
      SELECT id, email, password_hash, role, active, created_at, last_login
      FROM users
      ORDER BY created_at DESC
    `;

    const result = await this.pool.query(query);

    return result.rows.map((row) => this.mapRowToUser(row));
  }

  /**
   * Update user
   */
  async updateUser(id: number, updates: UpdateUserRequest): Promise<void> {
    const setParts: string[] = [];
    const values: any[] = [];
    let paramCount = 1;

    if (updates.role !== undefined) {
      setParts.push(`role = $${paramCount++}`);
      values.push(updates.role);
    }

    if (updates.active !== undefined) {
      setParts.push(`active = $${paramCount++}`);
      values.push(updates.active);
    }

    if (updates.password !== undefined) {
      const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
      const passwordHash = await bcrypt.hash(updates.password, bcryptRounds);
      setParts.push(`password_hash = $${paramCount++}`);
      values.push(passwordHash);
    }

    if (setParts.length === 0) {
      return; // Nothing to update
    }

    values.push(id);

    const query = `
      UPDATE users
      SET ${setParts.join(', ')}
      WHERE id = $${paramCount}
    `;

    await this.pool.query(query, values);
  }

  /**
   * Deactivate user
   */
  async deactivateUser(id: number): Promise<void> {
    const query = `
      UPDATE users
      SET active = false
      WHERE id = $1
    `;

    await this.pool.query(query, [id]);
  }

  /**
   * Update last login timestamp
   */
  async updateLastLogin(id: number): Promise<void> {
    const query = `
      UPDATE users
      SET last_login = NOW()
      WHERE id = $1
    `;

    await this.pool.query(query, [id]);
  }

  /**
   * Check if email exists
   */
  async emailExists(email: string): Promise<boolean> {
    const query = `
      SELECT COUNT(*) as count
      FROM users
      WHERE email = $1
    `;

    const result = await this.pool.query(query, [email]);
    return parseInt(result.rows[0].count, 10) > 0;
  }

  /**
   * Map database row to User object
   */
  private mapRowToUser(row: any): User {
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      role: row.role as UserRole,
      active: row.active,
      createdAt: row.created_at,
      lastLogin: row.last_login,
    };
  }
}

// Singleton instance
let userRepository: UserRepository | null = null;

/**
 * Get user repository instance
 */
export function getUserRepository(): UserRepository {
  if (!userRepository) {
    userRepository = new UserRepository(getPool());
  }
  return userRepository;
}
