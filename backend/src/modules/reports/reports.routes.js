// backend/src/modules/reports/reports.routes.js
// Route definitions and RBAC bindings for Phase 10 Security Reports.

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import {
  getReportTypes,
  previewReport,
  downloadReport,
} from './reports.controller.js';

const router = Router();

// All report endpoints require an authenticated session
router.use(requireAuth);

// ── GET /api/reports/types ────────────────────────────────────────────────────
// List available report types and their metadata.
// Allowed: ADMIN, ANALYST, VIEWER
router.get('/types', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), getReportTypes);

// ── GET /api/reports/preview ──────────────────────────────────────────────────
// Return JSON data for a report (useful for live preview in the UI).
// Allowed: ADMIN, ANALYST, VIEWER
// Query: type (required), startDate, endDate (optional ISO 8601)
router.get('/preview', requireRole(['ADMIN', 'ANALYST', 'VIEWER']), previewReport);

// ── GET /api/reports/download ─────────────────────────────────────────────────
// Generate and stream a PDF for a report.
// Allowed: ADMIN, ANALYST only (VIEWER cannot download)
// Query: type (required), startDate, endDate (optional ISO 8601)
router.get('/download', requireRole(['ADMIN', 'ANALYST']), downloadReport);

export default router;
