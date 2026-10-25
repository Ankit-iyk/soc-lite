// frontend/src/api/threatIntel.api.js
// API client for Threat Intelligence & IOC Integration (Phase 9).
// Uses the shared Axios client with automatic Bearer token injection and error handling.

import api from './client';

/**
 * Fetch paginated list of IOCs with optional search and filters.
 * @param {object} [params] - { page, limit, search, type, status, severity, sortBy, sortOrder }
 */
export async function getIocsApi(params = {}) {
  const response = await api.get('/threat-intel/iocs', { params });
  return response.data;
}

/**
 * Fetch aggregate statistics for Threat Intelligence.
 */
export async function getIocStatsApi() {
  const response = await api.get('/threat-intel/stats');
  return response.data;
}

/**
 * Fetch detailed indicator data including latest enrichments and correlations.
 * @param {string} id - Indicator UUID
 */
export async function getIocByIdApi(id) {
  const response = await api.get(`/threat-intel/iocs/${id}`);
  return response.data;
}

/**
 * Register a new threat indicator.
 * @param {object} payload - { type, value, severity, confidence, source, description, expiresAt }
 */
export async function createIocApi(payload) {
  const response = await api.post('/threat-intel/iocs', payload);
  return response.data;
}

/**
 * Update indicator metadata (severity, confidence, status, description, expiration).
 * @param {string} id - Indicator UUID
 * @param {object} payload - Partial updates
 */
export async function updateIocApi(id, payload) {
  const response = await api.patch(`/threat-intel/iocs/${id}`, payload);
  return response.data;
}

/**
 * Permanently delete an indicator (ADMIN only).
 * @param {string} id - Indicator UUID
 */
export async function deleteIocApi(id) {
  const response = await api.delete(`/threat-intel/iocs/${id}`);
  return response.data;
}

/**
 * Perform on-demand threat intelligence provider lookup.
 * @param {string} id - Indicator UUID
 * @param {object} [options] - { provider: string, forceRefresh: boolean }
 */
export async function lookupIocApi(id, options = {}) {
  const response = await api.post(`/threat-intel/iocs/${id}/lookup`, options);
  return response.data;
}

/**
 * Fetch full enrichment lookup history for an indicator.
 * @param {string} id - Indicator UUID
 */
export async function getEnrichmentHistoryApi(id) {
  const response = await api.get(`/threat-intel/iocs/${id}/enrichment-history`);
  return response.data;
}

/**
 * Fetch correlated assets, events, and alerts for an indicator.
 * @param {string} id - Indicator UUID
 */
export async function getIocCorrelationApi(id) {
  const response = await api.get(`/threat-intel/iocs/${id}/correlation`);
  return response.data;
}
