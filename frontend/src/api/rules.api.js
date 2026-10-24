// src/api/rules.api.js
// API client methods for Detection Rules management and Detection Engine execution.

import api from './client';

/**
 * Fetch all detection rules from the backend.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @returns {Promise<{ success: boolean, data: Array<object> }>}
 */
export async function getRulesApi() {
  const response = await api.get('/rules');
  return response.data;
}

/**
 * Update a detection rule (enabled, severity, description, config).
 * Allowed roles: ADMIN only.
 * @param {string} id - DetectionRule UUID
 * @param {object} payload - { enabled?, description?, severity?, config? }
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function updateRuleApi(id, payload) {
  const response = await api.put(`/rules/${id}`, payload);
  return response.data;
}

/**
 * Manually trigger a detection engine evaluation run.
 * Allowed roles: ADMIN, ANALYST.
 * @param {object} [payload] - { ruleId?, windowMinutes?, limit? }
 * @returns {Promise<{ success: boolean, message: string, data: object }>}
 */
export async function runDetectionApi(payload = {}) {
  const response = await api.post('/detection/run', payload);
  return response.data;
}
