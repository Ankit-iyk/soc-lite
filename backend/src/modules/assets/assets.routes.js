// src/modules/assets/assets.routes.js
// Express routes for Asset Management (Phase 8).

import { Router } from 'express';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import {
  getAssets,
  getAssetStats,
  getAssetById,
  createAsset,
  updateAsset,
  decommissionAsset,
  deleteAsset,
} from './assets.controller.js';

const router = Router();

// GET /api/assets
// Protected: ADMIN, ANALYST, VIEWER can browse asset inventory.
router.get('/', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), getAssets);

// GET /api/assets/stats
// IMPORTANT: /stats must be registered BEFORE /:id to prevent route shadowing.
// Protected: ADMIN, ANALYST, VIEWER can view aggregate inventory metrics.
router.get('/stats', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), getAssetStats);

// GET /api/assets/:id
// Protected: ADMIN, ANALYST, VIEWER can inspect asset details and audit timeline.
router.get('/:id', requireAuth, requireRole('ADMIN', 'ANALYST', 'VIEWER'), getAssetById);

// POST /api/assets
// Protected: ADMIN and ANALYST can register new assets.
router.post('/', requireAuth, requireRole('ADMIN', 'ANALYST'), createAsset);

// PATCH /api/assets/:id
// Protected: ADMIN and ANALYST can update asset properties.
router.patch('/:id', requireAuth, requireRole('ADMIN', 'ANALYST'), updateAsset);

// PATCH /api/assets/:id/decommission
// Protected: ADMIN and ANALYST can decommission an asset.
router.patch('/:id/decommission', requireAuth, requireRole('ADMIN', 'ANALYST'), decommissionAsset);

// DELETE /api/assets/:id
// Protected: ADMIN only can permanently delete an asset.
router.delete('/:id', requireAuth, requireRole('ADMIN'), deleteAsset);

export default router;
