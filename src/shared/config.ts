import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

export const configSchema = z.object({
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  FINA_WSDL_URL: z.string().url(),
  FINA_CERT_PATH: z.string().min(1),
  FINA_CERT_PASSPHRASE: z.string().default(''),
  IMAP_HOST: z.string().default(''),
  IMAP_PORT: z.coerce.number().default(993),
  IMAP_USER: z.string().default(''),
  IMAP_PASS: z.string().default(''),
  PORT: z.coerce.number().default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

export type Config = z.infer<typeof configSchema>;

export function loadConfig(): Config {
  const result = configSchema.safeParse(process.env);
  if (!result.success) {
    const formatted = result.error.issues
      .map((i) => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${formatted}`);
  }
  return result.data;
}

// Config is loaded explicitly by the app on startup
// export const config = loadConfig();
