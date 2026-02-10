import { query } from '../shared/db.js';
import type { User } from '../shared/types.js';

export async function createUser(data: {
  email: string;
  passwordHash: string;
  name?: string;
}): Promise<User> {
  const result = await query(
    `INSERT INTO users (email, password_hash, name)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [data.email, data.passwordHash, data.name || null]
  );
  return result.rows[0];
}

export async function getUserById(id: string): Promise<User | null> {
  const result = await query('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows[0] || null;
}

export async function getUserByEmail(email: string): Promise<User | null> {
  const result = await query('SELECT * FROM users WHERE email = $1', [email]);
  return result.rows[0] || null;
}

export async function updateUser(
  id: string,
  data: {
    email?: string;
    passwordHash?: string;
    name?: string;
  }
): Promise<User> {
  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (data.email !== undefined) {
    updates.push(`email = $${paramIndex++}`);
    values.push(data.email);
  }
  if (data.passwordHash !== undefined) {
    updates.push(`password_hash = $${paramIndex++}`);
    values.push(data.passwordHash);
  }
  if (data.name !== undefined) {
    updates.push(`name = $${paramIndex++}`);
    values.push(data.name);
  }

  updates.push(`updated_at = NOW()`);
  values.push(id);

  const result = await query(
    `UPDATE users
     SET ${updates.join(', ')}
     WHERE id = $${paramIndex}
     RETURNING *`,
    values
  );
  return result.rows[0];
}
