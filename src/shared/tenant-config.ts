import { z } from 'zod';
import { getPool } from './db.js';

// Zod schemas for user configuration validation
export const finaConfigSchema = z.object({
  wsdlUrl: z.string().url(),
  certPath: z.string().min(1),
  certPassphrase: z.string(),
});

export const imapConfigSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  user: z.string().min(1),
  password: z.string().min(1),
});

export type UserFINAConfig = z.infer<typeof finaConfigSchema>;
export type UserIMAPConfig = z.infer<typeof imapConfigSchema>;

export interface UserConfiguration {
  fina?: UserFINAConfig;
  imap?: UserIMAPConfig;
}

/**
 * Load and validate user configuration from database.
 * @param userId - The user ID to load configuration for
 * @returns UserConfiguration object with validated configurations
 * @throws Error if configuration validation fails
 */
export async function loadUserConfig(userId: string): Promise<UserConfiguration> {
  const pool = getPool();
  const result = await pool.query(
    'SELECT service_name, config FROM user_configurations WHERE user_id = $1',
    [userId]
  );

  const config: UserConfiguration = {};
  const errors: string[] = [];

  for (const row of result.rows) {
    if (row.service_name === 'fina') {
      const validated = finaConfigSchema.safeParse(row.config);
      if (validated.success) {
        config.fina = validated.data;
      } else {
        const formatted = validated.error.issues
          .map((i) => `  ${i.path.join('.')}: ${i.message}`)
          .join('\n');
        errors.push(`Invalid FINA configuration:\n${formatted}`);
      }
    } else if (row.service_name === 'imap') {
      const validated = imapConfigSchema.safeParse(row.config);
      if (validated.success) {
        config.imap = validated.data;
      } else {
        const formatted = validated.error.issues
          .map((i) => `  ${i.path.join('.')}: ${i.message}`)
          .join('\n');
        errors.push(`Invalid IMAP configuration:\n${formatted}`);
      }
    }
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
  }

  return config;
}

/**
 * Validate a user configuration object without storing it.
 * Useful for pre-validation before saving to database.
 */
export function validateUserConfig(
  serviceName: 'fina' | 'imap',
  config: unknown
): { success: true; data: UserFINAConfig | UserIMAPConfig } | { success: false; errors: string[] } {
  const schema = serviceName === 'fina' ? finaConfigSchema : imapConfigSchema;
  const result = schema.safeParse(config);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues
    .map((i) => `  ${i.path.join('.')}: ${i.message}`)
    .join('\n');
  return { success: false, errors: [errors] };
}
