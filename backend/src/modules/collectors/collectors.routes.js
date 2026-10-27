// src/modules/collectors/collectors.routes.js
// Routes for Windows Event Log collector agent management.
//
// Route groups:
//   Admin/user-facing management (requires JWT user auth):
//     POST   /api/collectors/tokens       — Provision a new agent token (ADMIN only)
//     GET    /api/collectors/tokens       — List all tokens (ADMIN only)
//     DELETE /api/collectors/tokens/:id   — Revoke a token (ADMIN only)
//     GET    /api/collectors              — List collectors + status (all authed roles)
//
//   Agent-facing endpoints (requires X-Agent-Token header):
//     POST   /api/collectors/checkin      — Heartbeat / status update
//     POST   /api/collectors/checkin/error— Report an error condition
//     POST   /api/collectors/ingest       — Batch-ingest Windows events

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { requireAgentAuth } from '../../middleware/agentAuth.js';
import {
  createAgentToken,
  listAgentTokens,
  revokeAgentToken,
  agentCheckin,
  agentReportError,
  agentIngest,
  listCollectors,
} from './collectors.controller.js';

const router = Router();

// ── Admin: token management ───────────────────────────────────────────────────
router.post('/tokens',       requireAuth, requireRole('ADMIN'), createAgentToken);
router.get('/tokens',        requireAuth, requireRole('ADMIN'), listAgentTokens);
router.delete('/tokens/:id', requireAuth, requireRole('ADMIN'), revokeAgentToken);

// ── Agent: authenticated via X-Agent-Token header ────────────────────────────
router.post('/checkin',       requireAgentAuth, agentCheckin);
router.post('/checkin/error', requireAgentAuth, agentReportError);
router.post('/ingest',        requireAgentAuth, agentIngest);

// ── Dashboard: visible to all authenticated users ─────────────────────────────
router.get('/', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), listCollectors);

export default router;
