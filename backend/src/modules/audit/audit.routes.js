// src/modules/audit/audit.routes.js
// Express routes for Security Audit History & Inspection (Phase 12).

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { getAuditLogs, getAuditStats } from './audit.controller.js';

const router = Router();

// All audit trail endpoints require authentication and privileged operator status.
// ADMIN and ANALYST are allowed. VIEWER is strictly forbidden (403).
router.use(requireAuth);
router.use(requireRole('ADMIN', 'ANALYST'));

// GET /api/audit-logs/stats
// Aggregate audit event metrics (must be registered before /)
router.get('/stats', getAuditStats);

// GET /api/audit-logs
// Paginated, filterable audit history query
router.get('/', getAuditLogs);

export default router;
