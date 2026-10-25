// src/api/audit.api.js
// API client for Security Audit Trail & Activity Inspection (Phase 12).

import api from './client';

/**
 * Fetch paginated audit log entries with optional filters.
 * @param {object} params - { page, limit, action, targetType, userId, search, startDate, endDate }
 */
export async function getAuditLogsApi(params = {}) {
  const res = await api.get('/audit-logs', { params });
  return res.data;
}

/**
 * Fetch aggregate audit log statistics.
 */
export async function getAuditStatsApi() {
  const res = await api.get('/audit-logs/stats');
  return res.data;
}
