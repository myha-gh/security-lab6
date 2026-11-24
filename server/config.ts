import 'dotenv/config';
import { z } from 'zod';
const env = z.object({
  DATABASE_URL: z.string().startsWith('postgres'),
  APP_ORIGIN: z.string().url().default('http://localhost:5175'),
  TOKEN_PEPPER: z.string().min(32),
  RESEND_API_KEY: z.string().min(1),
  MAIL_FROM: z.string().min(1),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_REDIRECT_URI: z.string().url().optional(),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),
  TRUST_PROXY: z.enum(['true', 'false']).default('false'),
});
export function readConfig() {
  const result = env.safeParse(process.env);
  if (!result.success)
    throw new Error(
      `Перевірте .env: ${result.error.issues.map((i) => i.path.join('.') + ': ' + i.message).join('; ')}`,
    );
  const config = {
    ...result.data,
    GOOGLE_REDIRECT_URI:
      result.data.GOOGLE_REDIRECT_URI || new URL('/api/auth/google/callback', result.data.APP_ORIGIN).href,
  };
  if (config.NODE_ENV === 'production' && !config.APP_ORIGIN.startsWith('https://'))
    throw new Error('Production requires HTTPS');
  return config;
}

export type Config = ReturnType<typeof readConfig>;
