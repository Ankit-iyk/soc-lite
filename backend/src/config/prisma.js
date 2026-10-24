// src/config/prisma.js
// Singleton PrismaClient instance.
// Using a singleton prevents exhausting PostgreSQL connection pools.

import { PrismaClient } from '@prisma/client';
import { config } from './env.js';

const logOptions = config.nodeEnv === 'development'
  ? ['warn', 'error']
  : ['error'];

export const prisma = new PrismaClient({
  log: logOptions,
});

/**
 * Ping the PostgreSQL database to verify connectivity.
 * Used by /api/health and startup checks.
 * @returns {Promise<{ ok: boolean, latencyMs?: number, error?: string }>}
 */
export async function checkDatabaseConnection() {
  const start = Date.now();
  try {
    await prisma.$queryRaw`SELECT 1`;
    return {
      ok: true,
      latencyMs: Date.now() - start,
    };
  } catch (err) {
    return {
      ok: false,
      error: err.message || 'Database connection failed',
    };
  }
}

export default prisma;
