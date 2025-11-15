import { Pool, PoolConfig } from 'pg';
import bcrypt from 'bcrypt';
import { User, CreateUserRequest, UpdateUserRequest } from './types';
import { UserRole } from '../auth/types';
import { logger } from '../observability';

function shouldUseInMemoryStore(): boolean {
  if (process.env.ADMIN_PORTAL_IN_MEMORY_DB === 'true') {
    return true;
  }
  if (process.env.ADMIN_PORTAL_IN_MEMORY_DB === 'false') {
    return false;
  }
  return process.env.NODE_ENV === 'test';
}

export function isInMemoryUserStoreEnabled(): boolean {
  return shouldUseInMemoryStore();
}

// PostgreSQL connection pool
let pool: Pool | null = null;

function createNoopPool(): Pool {
  return {
    query: async () => {
      throw new Error('In-memory repository does not expose SQL pool queries');
    },
    end: async () => {
      /* noop */
    },
    on: () => createNoopPool(),
  } as unknown as Pool;
}

/**
 * Initialize database connection pool
 */
export function initializePool(config?: PoolConfig) {
  if (pool) {
    return pool;
  }

  if (shouldUseInMemoryStore()) {
    logger.warn('Using in-memory user repository; skipping PostgreSQL pool initialization');
    pool = createNoopPool();
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

export interface IUserRepository {
  createUser(request: CreateUserRequest): Promise<User>;
  getUserByEmail(email: string): Promise<User | null>;
  getUserById(id: number): Promise<User | null>;
  getAllUsers(): Promise<User[]>;
  updateUser(id: number, updates: UpdateUserRequest): Promise<void>;
  deactivateUser(id: number): Promise<void>;
  updateLastLogin(id: number): Promise<void>;
  emailExists(email: string): Promise<boolean>;
}

/**
 * User repository backed by PostgreSQL
 */
export class UserRepository implements IUserRepository {
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

class InMemoryUserRepository implements IUserRepository {
  private users: User[] = [];
  private idSeq = 1;

  private cloneUser(user: User): User {
    return {
      ...user,
      createdAt: new Date(user.createdAt),
      lastLogin: user.lastLogin ? new Date(user.lastLogin) : null,
    };
  }

  private findByEmail(email: string): User | undefined {
    return this.users.find((user) => user.email === email);
  }

  private findById(id: number): User | undefined {
    return this.users.find((user) => user.id === id);
  }

  async createUser(request: CreateUserRequest): Promise<User> {
    const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
    const passwordHash = await bcrypt.hash(request.password, bcryptRounds);
    const now = new Date();
    const user: User = {
      id: this.idSeq++,
      email: request.email,
      passwordHash,
      role: request.role,
      active: true,
      createdAt: now,
      lastLogin: null,
    };
    this.users.push(user);
    return this.cloneUser(user);
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const user = this.findByEmail(email);
    return user ? this.cloneUser(user) : null;
  }

  async getUserById(id: number): Promise<User | null> {
    const user = this.findById(id);
    return user ? this.cloneUser(user) : null;
  }

  async getAllUsers(): Promise<User[]> {
    const sorted = [...this.users].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    return sorted.map((user) => this.cloneUser(user));
  }

  async updateUser(id: number, updates: UpdateUserRequest): Promise<void> {
    const user = this.findById(id);
    if (!user) {
      return;
    }

    if (updates.role !== undefined) {
      user.role = updates.role;
    }

    if (updates.active !== undefined) {
      user.active = updates.active;
    }

    if (updates.password !== undefined) {
      const bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
      user.passwordHash = await bcrypt.hash(updates.password, bcryptRounds);
    }
  }

  async deactivateUser(id: number): Promise<void> {
    const user = this.findById(id);
    if (user) {
      user.active = false;
    }
  }

  async updateLastLogin(id: number): Promise<void> {
    const user = this.findById(id);
    if (user) {
      user.lastLogin = new Date();
    }
  }

  async emailExists(email: string): Promise<boolean> {
    return this.findByEmail(email) !== undefined;
  }
}

// Singleton instance
let userRepository: IUserRepository | null = null;

/**
 * Get user repository instance
 */
export function getUserRepository(): IUserRepository {
  if (!userRepository) {
    userRepository = shouldUseInMemoryStore()
      ? new InMemoryUserRepository()
      : new UserRepository(getPool());
  }
  return userRepository;
}
