import { query } from '../shared/db.js';
import type { UserConfig } from '../shared/types.js';

export async function createConfig(data: {
  userId: string;
  serviceName: 'fina' | 'imap';
  config: Record<string, unknown>;
}): Promise<UserConfig> {
  const result = await query(
    `INSERT INTO user_configurations (user_id, service_name, config)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [data.userId, data.serviceName, JSON.stringify(data.config)]
  );
  return result.rows[0];
}

export async function getConfigs(userId: string): Promise<UserConfig[]> {
  const result = await query(
    'SELECT * FROM user_configurations WHERE user_id = $1 ORDER BY created_at DESC',
    [userId]
  );
  return result.rows;
}

export async function getConfig(
  userId: string,
  serviceName: 'fina' | 'imap'
): Promise<UserConfig | null> {
  const result = await query(
    'SELECT * FROM user_configurations WHERE user_id = $1 AND service_name = $2',
    [userId, serviceName]
  );
  return result.rows[0] || null;
}

export async function updateConfig(
  userId: string,
  serviceName: 'fina' | 'imap',
  config: Record<string, unknown>
): Promise<UserConfig> {
  const result = await query(
    `UPDATE user_configurations
     SET config = $1, updated_at = NOW()
     WHERE user_id = $2 AND service_name = $3
     RETURNING *`,
    [JSON.stringify(config), userId, serviceName]
  );
  return result.rows[0];
}

export async function deleteConfig(
  userId: string,
  serviceName: 'fina' | 'imap'
): Promise<void> {
  await query(
    'DELETE FROM user_configurations WHERE user_id = $1 AND service_name = $2',
    [userId, serviceName]
  );
}
