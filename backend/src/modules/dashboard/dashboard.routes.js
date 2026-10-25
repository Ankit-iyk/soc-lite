// src/modules/dashboard/dashboard.routes.js
// Express routes for Dashboard (Phase 7).

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { getDashboardSummary } from './dashboard.controller.js';

const router = Router();

// GET /api/dashboard/summary
// Protected: ADMIN, ANALYST, VIEWER have read-only access to dashboard metrics.
router.get(
  '/summary',
  requireAuth,
  requireRole('ADMIN', 'ANALYST', 'VIEWER'),
  getDashboardSummary
);

export default router;
