// src/modules/dashboard/dashboard.routes.js
// Express routes for Dashboard (Phase 7).

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { getDashboardSummary } from './dashboard.controller.js';
import { streamDashboardUpdates } from './live.controller.js';

const router = Router();

// GET /api/dashboard/summary
// Protected: ADMIN, ANALYST, VIEWER have read-only access to dashboard metrics.
router.get(
  '/summary',
  requireAuth,
  requireRole('ADMIN', 'ANALYST', 'VIEWER'),
  getDashboardSummary
);

router.get(
  '/live',
  requireAuth,
  requireRole('ADMIN', 'ANALYST', 'VIEWER'),
  streamDashboardUpdates
);

export default router;
