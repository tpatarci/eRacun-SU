import { Pool } from 'pg';
import { Session } from '../auth/types';
import { getPool } from './repository';
import { logger } from '../observability';

/**
 * Session repository
 */
export class SessionRepository {
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

// Singleton instance
let sessionRepository: SessionRepository | null = null;

/**
 * Get session repository instance
 */
export function getSessionRepository(): SessionRepository {
  if (!sessionRepository) {
    sessionRepository = new SessionRepository(getPool());
  }
  return sessionRepository;
}
