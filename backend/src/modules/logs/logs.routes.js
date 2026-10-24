// src/modules/logs/logs.routes.js
// Express routes for raw log ingestion and inspection.

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import * as logsController from './logs.controller.js';

const router = Router();

// Ingest logs — restricted to ADMIN and ANALYST
router.post('/ingest', requireAuth, requireRole('ADMIN', 'ANALYST'), logsController.ingestLogs);

// Query raw logs — accessible to all authenticated operators (ADMIN, ANALYST, VIEWER)
router.get('/', requireAuth, logsController.getRawLogs);

export default router;
