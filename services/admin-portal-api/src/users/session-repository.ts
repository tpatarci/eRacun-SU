import { Pool } from 'pg';
import { Session } from '../auth/types';
import { getPool, isInMemoryUserStoreEnabled } from './repository';
import { logger } from '../observability';

/**
 * Session repository
 */
export interface ISessionRepository {
  createSession(session: Session): Promise<void>;
  getSessionByToken(token: string): Promise<Session | null>;
  deleteSessionByToken(token: string): Promise<void>;
  deleteUserSessions(userId: number): Promise<void>;
  updateSessionToken(oldToken: string, newToken: string): Promise<void>;
  countActiveSessions(): Promise<number>;
  cleanupExpiredSessions(): Promise<number>;
}

export class SessionRepository implements ISessionRepository {
  private pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  /**
   * Create a new session
   */
  async createSession(session: Session): Promise<void> {
    const query = `
      INSERT INTO sessions (id, user_id, token, expires_at, created_at)
      VALUES ($1, $2, $3, $4, $5)
    `;

    await this.pool.query(query, [
      session.id,
      session.userId,
      session.token,
      session.expiresAt,
      session.createdAt,
    ]);
  }

  /**
   * Get session by token
   */
  async getSessionByToken(token: string): Promise<Session | null> {
    const query = `
      SELECT id, user_id, token, expires_at, created_at
      FROM sessions
      WHERE token = $1 AND expires_at > NOW()
    `;

    const result = await this.pool.query(query, [token]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRowToSession(result.rows[0]);
  }

  /**
   * Delete session by token
   */
  async deleteSessionByToken(token: string): Promise<void> {
    const query = `
      DELETE FROM sessions
      WHERE token = $1
    `;

    await this.pool.query(query, [token]);
  }

  /**
   * Delete all sessions for user
   */
  async deleteUserSessions(userId: number): Promise<void> {
    const query = `
      DELETE FROM sessions
      WHERE user_id = $1
    `;

    await this.pool.query(query, [userId]);
  }

  /**
   * Update session token (for token refresh)
   */
  async updateSessionToken(oldToken: string, newToken: string): Promise<void> {
    const query = `
      UPDATE sessions
      SET token = $1, expires_at = NOW() + INTERVAL '24 hours'
      WHERE token = $2
    `;

    await this.pool.query(query, [newToken, oldToken]);
  }

  /**
   * Count active sessions
   */
  async countActiveSessions(): Promise<number> {
    const query = `
      SELECT COUNT(*) as count
      FROM sessions
      WHERE expires_at > NOW()
    `;

    const result = await this.pool.query(query);
    return parseInt(result.rows[0].count, 10);
  }

  /**
   * Cleanup expired sessions
   */
  async cleanupExpiredSessions(): Promise<number> {
    const query = `
      DELETE FROM sessions
      WHERE expires_at <= NOW()
      RETURNING id
    `;

    const result = await this.pool.query(query);
    const deletedCount = result.rowCount || 0;

    if (deletedCount > 0) {
      logger.info({
        deleted_count: deletedCount,
        msg: 'Cleaned up expired sessions',
      });
    }

    return deletedCount;
  }

  /**
   * Map database row to Session object
   */
  private mapRowToSession(row: any): Session {
    return {
      id: row.id,
      userId: row.user_id,
      token: row.token,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
    };
  }
}

class InMemorySessionRepository implements ISessionRepository {
  private sessions: Session[] = [];

  async createSession(session: Session): Promise<void> {
    this.sessions.push({ ...session });
  }

  async getSessionByToken(token: string): Promise<Session | null> {
    const now = Date.now();
    const session = this.sessions.find((s) => s.token === token && s.expiresAt.getTime() > now);
    return session ? { ...session } : null;
  }

  async deleteSessionByToken(token: string): Promise<void> {
    this.sessions = this.sessions.filter((s) => s.token !== token);
  }

  async deleteUserSessions(userId: number): Promise<void> {
    this.sessions = this.sessions.filter((s) => s.userId !== userId);
  }

  async updateSessionToken(oldToken: string, newToken: string): Promise<void> {
    const session = this.sessions.find((s) => s.token === oldToken);
    if (session) {
      session.token = newToken;
      session.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    }
  }

  async countActiveSessions(): Promise<number> {
    const now = Date.now();
    return this.sessions.filter((s) => s.expiresAt.getTime() > now).length;
  }

  async cleanupExpiredSessions(): Promise<number> {
    const now = Date.now();
    const before = this.sessions.length;
    this.sessions = this.sessions.filter((s) => s.expiresAt.getTime() > now);
    return before - this.sessions.length;
  }
}

// Singleton instance
let sessionRepository: ISessionRepository | null = null;

/**
 * Get session repository instance
 */
export function getSessionRepository(): ISessionRepository {
  if (!sessionRepository) {
    sessionRepository = isInMemoryUserStoreEnabled()
      ? new InMemorySessionRepository()
      : new SessionRepository(getPool());
  }
  return sessionRepository;
}
