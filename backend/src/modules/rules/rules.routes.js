// src/modules/rules/rules.routes.js
// Routes for Detection Rules management and configuration.

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { getRules, updateRule } from './rules.controller.js';

const router = Router();

// GET /api/rules
// Protected: ADMIN, ANALYST, VIEWER can view detection rules.
router.get('/', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), getRules);

// PUT /api/rules/:id
// Protected: ADMIN only can modify detection rules.
router.put('/:id', requireAuth, requireRole('ADMIN'), updateRule);

export default router;
