// src/api/incidents.api.js
// API client methods for Incident Tracking (Phase 6).
// All methods use the configured Axios instance so JWT headers,
// base URL, and global 401 handling are applied automatically.

import api from './client';

/**
 * Fetch a paginated list of incidents with optional filters.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @param {object} [params] - { page, limit, status, severity, assignedToId, search, startDate, endDate }
 * @returns {Promise<{ success: boolean, data: Array<object>, pagination: object }>}
 */
export async function getIncidentsApi(params = {}) {
  const response = await api.get('/incidents', { params });
  return response.data;
}

/**
 * Fetch aggregate incident statistics: total, byStatus, bySeverity.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @returns {Promise<{ success: boolean, data: { total: number, byStatus: object, bySeverity: object } }>}
 */
export async function getIncidentStatsApi() {
  const response = await api.get('/incidents/stats');
  return response.data;
}

/**
 * Fetch full incident detail by UUID.
 * Returns incident fields, assignedTo, alerts (with rules), and AuditLog timeline.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @param {string} id - Incident UUID
 * @returns {Promise<{ success: boolean, data: object }>}
 */
export async function getIncidentByIdApi(id) {
  const response = await api.get(`/incidents/${id}`);
  return response.data;
}

/**
 * Create a new incident.
 * Allowed roles: ADMIN, ANALYST only.
 * @param {object} payload - { title, description?, severity?, status?, assignedToId?, alertIds? }
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function createIncidentApi(payload) {
  const response = await api.post('/incidents', payload);
  return response.data;
}

/**
 * Update an existing incident (title, description, severity, status, assignedToId).
 * Allowed roles: ADMIN, ANALYST only.
 * @param {string} id - Incident UUID
 * @param {object} payload - { title?, description?, severity?, status?, assignedToId? }
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function updateIncidentApi(id, payload) {
  const response = await api.patch(`/incidents/${id}`, payload);
  return response.data;
}

/**
 * Link one or more alerts to an incident.
 * Allowed roles: ADMIN, ANALYST only.
 * @param {string} id - Incident UUID
 * @param {object} payload - { alertIds: string[] }
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function linkAlertsApi(id, payload) {
  const response = await api.post(`/incidents/${id}/alerts`, payload);
  return response.data;
}

/**
 * Unlink a single alert from an incident.
 * Allowed roles: ADMIN, ANALYST only.
 * @param {string} id - Incident UUID
 * @param {string} alertId - Alert UUID to unlink
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function unlinkAlertApi(id, alertId) {
  const response = await api.delete(`/incidents/${id}/alerts/${alertId}`);
  return response.data;
}

/**
 * Add an investigation note to an incident (stored in AuditLog).
 * Allowed roles: ADMIN, ANALYST only.
 * @param {string} id - Incident UUID
 * @param {object} payload - { note: string }
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function addIncidentNoteApi(id, payload) {
  const response = await api.post(`/incidents/${id}/notes`, payload);
  return response.data;
}
