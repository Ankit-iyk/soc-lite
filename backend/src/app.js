// src/app.js
// Express application setup.
// We separate app setup from server startup (server.js) so it's
// easy to import the app in tests without starting a real server.

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from './config/env.js';
import { requestLogger } from './middleware/requestLogger.js';
import { errorHandler } from './middleware/errorHandler.js';
import healthRoutes from './modules/health/health.routes.js';
import authRoutes from './modules/auth/auth.routes.js';
import logRoutes from './modules/logs/logs.routes.js';
import eventRoutes from './modules/events/events.routes.js';
import detectionRoutes from './modules/detection/detection.routes.js';
import ruleRoutes from './modules/rules/rules.routes.js';
import alertRoutes from './modules/alerts/alerts.routes.js';
import incidentRoutes from './modules/incidents/incidents.routes.js';

import dashboardRoutes from './modules/dashboard/dashboard.routes.js';
import assetRoutes from './modules/assets/assets.routes.js';
import threatIntelRoutes from './modules/threat-intelligence/threatIntel.routes.js';
import reportRoutes from './modules/reports/reports.routes.js';
import auditRoutes from './modules/audit/audit.routes.js';

const app = express();

// ── Security headers (helmet adds ~15 HTTP headers for free) ──────────────
app.use(helmet());

// ── CORS — allow the frontend dev server to call the API ──────────────────
app.use(cors({
  origin: config.corsOrigin,
  credentials: true,
}));

// ── Body parsing ──────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Request logging ───────────────────────────────────────────────────────
app.use(requestLogger);

// ── API Routes ────────────────────────────────────────────────────────────
app.use('/api/health',              healthRoutes);
app.use('/api/auth',                authRoutes);
app.use('/api/logs',                logRoutes);
app.use('/api/events',              eventRoutes);
app.use('/api/detection',           detectionRoutes);
app.use('/api/rules',               ruleRoutes);
app.use('/api/alerts',              alertRoutes);
app.use('/api/incidents',           incidentRoutes);
app.use('/api/dashboard',           dashboardRoutes);
app.use('/api/assets',              assetRoutes);
app.use('/api/threat-intel',        threatIntelRoutes);
app.use('/api/threat-intelligence', threatIntelRoutes);
app.use('/api/reports',             reportRoutes);
app.use('/api/audit-logs',          auditRoutes);
app.use('/api/audit',               auditRoutes);

// ── 404 handler ───────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

// ── Global error handler (must be last) ───────────────────────────────────
app.use(errorHandler);

export default app;
