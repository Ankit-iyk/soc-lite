// src/api/alerts.api.js
// API client methods for Alert Management (Phase 5).

import api from './client';

/**
 * Fetch paginated alerts with filters.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @param {object} [params] - { page, limit, status, severity, ruleId, search, startDate, endDate }
 * @returns {Promise<{ success: boolean, data: Array<object>, pagination: object }>}
 */
export async function getAlertsApi(params = {}) {
  const response = await api.get('/alerts', { params });
  return response.data;
}

/**
 * Fetch aggregate statistics for alerts (total, byStatus, bySeverity).
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @returns {Promise<{ success: boolean, data: { total: number, byStatus: object, bySeverity: object } }>}
 */
export async function getAlertStatsApi() {
  const response = await api.get('/alerts/stats');
  return response.data;
}

/**
 * Fetch single alert details by UUID, including rule configuration and evidence chain.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @param {string} id - Alert UUID
 * @returns {Promise<{ success: boolean, data: object }>}
 */
export async function getAlertByIdApi(id) {
  const response = await api.get(`/alerts/${id}`);
  return response.data;
}

/**
 * Transition an alert's status to ACKNOWLEDGED or CLOSED.
 * Allowed roles: ADMIN, ANALYST only.
 * @param {string} id - Alert UUID
 * @param {'ACKNOWLEDGED' | 'CLOSED'} status - Target alert status
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function updateAlertStatusApi(id, status) {
  const response = await api.patch(`/alerts/${id}/status`, { status });
  return response.data;
}
