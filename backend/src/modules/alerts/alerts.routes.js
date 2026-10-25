// src/modules/alerts/alerts.routes.js
// Express routes for Alert Management (Phase 5 Step 1).

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import {
  getAlerts,
  getAlertStats,
  getAlertById,
  updateAlertStatus,
} from './alerts.controller.js';

const router = Router();

// GET /api/alerts
// Protected: ADMIN, ANALYST, VIEWER can browse alerts.
router.get('/', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), getAlerts);

// GET /api/alerts/stats
// IMPORTANT: /stats must be registered BEFORE /:id to prevent route shadowing/conflicts.
// Protected: ADMIN, ANALYST, VIEWER can view aggregate metrics.
router.get('/stats', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), getAlertStats);

// GET /api/alerts/:id
// Protected: ADMIN, ANALYST, VIEWER can inspect alert details and evidence chain.
router.get('/:id', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), getAlertById);

// PATCH /api/alerts/:id/status
// Protected: ADMIN and ANALYST only can transition alert status.
router.patch('/:id/status', requireAuth, requireRole('ADMIN', 'ANALYST'), updateAlertStatus);

export default router;
