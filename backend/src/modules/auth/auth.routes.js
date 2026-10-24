// src/modules/auth/auth.routes.js
// Routes for user authentication.

import { Router } from 'express';
import * as authController from './auth.controller.js';
import { requireAuth } from '../../middleware/auth.js';

const router = Router();

// Public routes
router.post('/login', authController.login);

// Protected routes (require valid Bearer token)
router.post('/logout', requireAuth, authController.logout);
router.get('/me', requireAuth, authController.getMe);

export default router;
