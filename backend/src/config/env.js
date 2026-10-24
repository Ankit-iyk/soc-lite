// src/config/env.js
// Loads .env once at startup. All other modules import from here
// so there is a single source of truth for configuration.

import 'dotenv/config';

/**
 * Safely masks database credentials for logs, preventing password exposure.
 * e.g., postgresql://user:secret@localhost:5432/db -> postgresql://user:****@localhost:5432/db
 */
export function getMaskedDatabaseUrl(url = process.env.DATABASE_URL) {
  if (!url) return '(not configured)';
  try {
    const parsed = new URL(url);
    if (parsed.password) {
      parsed.password = '****';
    }
    return parsed.toString();
  } catch {
    return '(invalid url format)';
  }
}

export const config = {
  port: parseInt(process.env.PORT ?? '3000', 10),
  nodeEnv: process.env.NODE_ENV ?? 'development',
  corsOrigin: process.env.CORS_ORIGIN ?? 'http://localhost:5173',
  databaseUrl: process.env.DATABASE_URL ?? '',
  jwtSecret: process.env.JWT_SECRET ?? '',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN ?? '8h',
};

// Validate critical variables in non-test environments
if (config.nodeEnv !== 'test') {
  if (!config.databaseUrl) {
    console.warn('⚠️  Warning: DATABASE_URL is not set in backend/.env');
  } else if (!config.databaseUrl.startsWith('postgresql://') && !config.databaseUrl.startsWith('postgres://')) {
    console.warn('⚠️  Warning: DATABASE_URL does not start with postgresql:// or postgres://');
  }
}
