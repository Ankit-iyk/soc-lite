// src/modules/health/health.routes.js
// GET /api/health — Liveness & readiness probe.
// Checks server status and tests the live PostgreSQL database connection via Prisma.

import { Router } from 'express';
import { checkDatabaseConnection } from '../../config/prisma.js';

const router = Router();

router.get('/', async (_req, res) => {
  const dbHealth = await checkDatabaseConnection();

  const isHealthy = dbHealth.ok;
  const statusCode = isHealthy ? 200 : 503;

  res.status(statusCode).json({
    success: isHealthy,
    service: 'soc-lite-backend',
    status: isHealthy ? 'ok' : 'degraded',
    database: {
      status: isHealthy ? 'connected' : 'disconnected',
      latencyMs: dbHealth.latencyMs,
      ...(dbHealth.error ? { message: 'Database connection failed' } : {}),
    },
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    phase: 2,
  });
});

export default router;
