// src/modules/dashboard/dashboard.validation.js
// Validation helpers for Dashboard API (Phase 7).

const ALLOWED_TIME_WINDOWS = ['24h', '7d'];

/**
 * Validates query parameters for GET /api/dashboard/summary.
 * @param {object} query - Express req.query object.
 * @returns {{ isValid: boolean, error?: string, sanitized?: { timeWindow: string, recentLimit: number } }}
 */
export function validateDashboardQuery(query = {}) {
  const sanitized = {
    timeWindow: '24h',
    recentLimit: 5,
  };

  if (query.timeWindow !== undefined && query.timeWindow !== null) {
    if (typeof query.timeWindow !== 'string') {
      return {
        isValid: false,
        error: `Query parameter "timeWindow" must be a string. Allowed values: ${ALLOWED_TIME_WINDOWS.join(', ')}.`,
      };
    }

    const trimmed = query.timeWindow.trim().toLowerCase();
    if (!ALLOWED_TIME_WINDOWS.includes(trimmed)) {
      return {
        isValid: false,
        error: `Invalid timeWindow "${query.timeWindow}". Allowed values: ${ALLOWED_TIME_WINDOWS.join(', ')}.`,
      };
    }

    sanitized.timeWindow = trimmed;
  }

  if (query.recentLimit !== undefined && query.recentLimit !== null) {
    const parsed = parseInt(query.recentLimit, 10);
    if (Number.isNaN(parsed) || parsed < 1 || parsed > 20) {
      return {
        isValid: false,
        error: 'Query parameter "recentLimit" must be an integer between 1 and 20.',
      };
    }
    sanitized.recentLimit = parsed;
  }

  return {
    isValid: true,
    sanitized,
  };
}
