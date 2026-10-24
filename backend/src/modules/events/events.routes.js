// src/modules/events/events.routes.js
// Express routes for normalized event querying and detail retrieval.

import { Router } from 'express';
import { requireAuth } from '../../middleware/auth.js';
import * as eventsController from './events.controller.js';

const router = Router();

// Query normalized events (with pagination & filters)
router.get('/', requireAuth, eventsController.getEvents);

// Get single event with originating raw log attached
router.get('/:id', requireAuth, eventsController.getEventById);

export default router;
