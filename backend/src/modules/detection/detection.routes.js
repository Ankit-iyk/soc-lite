// src/modules/detection/detection.routes.js
// Routes for Detection Engine operations.

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { triggerDetectionRun } from './detection.controller.js';

const router = Router();

// POST /api/detection/run
// Protected: ADMIN and ANALYST roles only. VIEWER is forbidden (403).
router.post('/run', requireAuth, requireRole('ADMIN', 'ANALYST'), triggerDetectionRun);

export default router;
