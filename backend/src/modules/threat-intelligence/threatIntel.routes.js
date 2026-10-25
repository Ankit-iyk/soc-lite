// backend/src/modules/threat-intelligence/threatIntel.routes.js
// Route definitions and RBAC middleware bindings for Phase 9 Threat Intelligence.

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import {
  getIocs,
  getIocStats,
  getIocById,
  createIoc,
  updateIoc,
  deleteIoc,
  lookupIoc,
  getEnrichmentHistory,
  getIocCorrelation,
} from './threatIntel.controller.js';

const router = Router();

// All Threat Intelligence endpoints require an authenticated user session
router.use(requireAuth);

// ── Read-only endpoints (ADMIN, ANALYST, VIEWER) ───────────────────────────
router.get('/stats', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getIocStats);

// Allow both /iocs and root /
router.get('/iocs', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getIocs);
router.get('/', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getIocs);

router.get('/iocs/:id', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getIocById);
router.get('/iocs/:id/enrichment-history', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getEnrichmentHistory);
router.get('/iocs/:id/correlation', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getIocCorrelation);

// Direct root aliases
router.get('/:id', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getIocById);
router.get('/:id/enrichment-history', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getEnrichmentHistory);
router.get('/:id/correlation', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getIocCorrelation);

// ── Mutation endpoints (ADMIN, ANALYST) ───────────────────────────────────
router.post('/iocs', requireRole(['ADMIN', 'ANALYST']), createIoc);
router.post('/', requireRole(['ADMIN', 'ANALYST']), createIoc);

router.patch('/iocs/:id', requireRole(['ADMIN', 'ANALYST']), updateIoc);
router.patch('/:id', requireRole(['ADMIN', 'ANALYST']), updateIoc);

// Threat intelligence provider lookup (VIEWER strictly prohibited)
router.post('/iocs/:id/lookup', requireRole(['ADMIN', 'ANALYST']), lookupIoc);
router.post('/:id/lookup', requireRole(['ADMIN', 'ANALYST']), lookupIoc);

// ── Administrative deletion (ADMIN only) ──────────────────────────────────
router.delete('/iocs/:id', requireRole(['ADMIN']), deleteIoc);
router.delete('/:id', requireRole(['ADMIN']), deleteIoc);

export default router;
