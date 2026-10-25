// src/modules/incidents/incidents.routes.js
// Express routes for Incident Tracking (Phase 6).
//
// Route ordering matters:
//   - GET /stats must be registered BEFORE GET /:id to prevent Express
//     interpreting the literal string "stats" as an `:id` parameter.
//
// Authorization summary:
//   Read  (list, stats, detail): ADMIN, ANALYST, VIEWER
//   Write (create, update, link, unlink, note): ADMIN, ANALYST

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import {
  getIncidents,
  getIncidentStats,
  getIncidentById,
  createIncident,
  updateIncident,
  linkAlerts,
  unlinkAlert,
  addIncidentNote,
} from './incidents.controller.js';

const router = Router();

// ── Read-only endpoints (ADMIN, ANALYST, VIEWER) ──────────────────────────

// GET /api/incidents
// Returns a paginated, filterable list of incidents.
router.get(
  '/',
  requireAuth,
  requireRole('ADMIN', 'ANALYST', 'VIEWER'),
  getIncidents,
);

// GET /api/incidents/stats
// IMPORTANT: registered before /:id to prevent route shadowing.
// Returns aggregate incident counts by status and severity.
router.get(
  '/stats',
  requireAuth,
  requireRole('ADMIN', 'ANALYST', 'VIEWER'),
  getIncidentStats,
);

// GET /api/incidents/:id
// Returns full incident detail, linked alerts, and investigation timeline.
router.get(
  '/:id',
  requireAuth,
  requireRole('ADMIN', 'ANALYST', 'VIEWER'),
  getIncidentById,
);

// ── Mutation endpoints (ADMIN, ANALYST only) ───────────────────────────────

// POST /api/incidents
// Creates a new incident, optionally linking initial alerts atomically.
router.post(
  '/',
  requireAuth,
  requireRole('ADMIN', 'ANALYST'),
  createIncident,
);

// PATCH /api/incidents/:id
// Partially updates title, description, severity, status, or assignee.
// Enforces status-transition policy and resolvedAt lifecycle.
router.patch(
  '/:id',
  requireAuth,
  requireRole('ADMIN', 'ANALYST'),
  updateIncident,
);

// POST /api/incidents/:id/alerts
// Links one or more existing alerts to an incident.
// Silently skips alerts already linked (idempotent for already-linked items).
router.post(
  '/:id/alerts',
  requireAuth,
  requireRole('ADMIN', 'ANALYST'),
  linkAlerts,
);

// DELETE /api/incidents/:id/alerts/:alertId
// Removes the link between a specific alert and the incident.
router.delete(
  '/:id/alerts/:alertId',
  requireAuth,
  requireRole('ADMIN', 'ANALYST'),
  unlinkAlert,
);

// POST /api/incidents/:id/notes
// Appends an investigation note to the incident timeline via AuditLog.
router.post(
  '/:id/notes',
  requireAuth,
  requireRole('ADMIN', 'ANALYST'),
  addIncidentNote,
);

export default router;
