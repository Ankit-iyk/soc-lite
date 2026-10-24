// src/modules/detection/detection.controller.js
// Controller for manual detection engine triggers.

import { runDetection } from '../../detection/engine.js';

/**
 * POST /api/detection/run
 * Manually triggers a detection engine evaluation run.
 * Allowed roles: ADMIN, ANALYST (VIEWER is rejected by requireRole).
 */
export async function triggerDetectionRun(req, res, next) {
  try {
    const { ruleId, windowMinutes, limit } = req.body || {};

    const options = {
      userId: req.user.id,
      ipAddress: req.ip || req.socket?.remoteAddress || null,
    };

    if (ruleId !== undefined) {
      if (typeof ruleId !== 'string' || !ruleId.trim()) {
        return res.status(400).json({
          success: false,
          error: 'Invalid ruleId. Must be a non-empty string.',
        });
      }
      options.ruleId = ruleId.trim();
    }

    if (windowMinutes !== undefined) {
      const parsedWindow = parseInt(windowMinutes, 10);
      if (Number.isNaN(parsedWindow) || parsedWindow < 1 || parsedWindow > 10080) {
        return res.status(400).json({
          success: false,
          error: 'Invalid windowMinutes. Must be an integer between 1 and 10080 (7 days).',
        });
      }
      options.windowMinutes = parsedWindow;
    }

    if (limit !== undefined) {
      const parsedLimit = parseInt(limit, 10);
      if (Number.isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 5000) {
        return res.status(400).json({
          success: false,
          error: 'Invalid limit. Must be an integer between 1 and 5000.',
        });
      }
      options.limit = parsedLimit;
    }

    const summary = await runDetection(options);

    return res.status(200).json({
      success: true,
      message: `Detection run completed: ${summary.matchesFound} match(es) evaluated, ${summary.alertsCreated} alert(s) created, ${summary.alertsUpdated} alert(s) updated.`,
      data: summary,
    });
  } catch (err) {
    next(err);
  }
}
