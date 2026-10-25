// src/api/assets.api.js
// API client for Asset Management (Phase 8).
// Uses the shared Axios instance with automatic Bearer token injection and 401 handling.

import api from './client';

/**
 * Fetch paginated list of assets with optional search and filters.
 * @param {object} [params] - { page, limit, search, status, criticality, type, environment, sortBy, sortOrder }
 */
export async function getAssetsApi(params = {}) {
  const response = await api.get('/assets', { params });
  return response.data;
}

/**
 * Fetch inventory aggregate statistics.
 */
export async function getAssetStatsApi() {
  const response = await api.get('/assets/stats');
  return response.data;
}

/**
 * Fetch full asset details including audit timeline.
 * @param {string} id - Asset UUID
 */
export async function getAssetByIdApi(id) {
  const response = await api.get(`/assets/${id}`);
  return response.data;
}

/**
 * Register a new monitored asset.
 * @param {object} payload - Asset data object
 */
export async function createAssetApi(payload) {
  const response = await api.post('/assets', payload);
  return response.data;
}

/**
 * Update an existing asset.
 * @param {string} id - Asset UUID
 * @param {object} payload - Partial update object
 */
export async function updateAssetApi(id, payload) {
  const response = await api.patch(`/assets/${id}`, payload);
  return response.data;
}

/**
 * Safely decommission an asset.
 * @param {string} id - Asset UUID
 */
export async function decommissionAssetApi(id) {
  const response = await api.patch(`/assets/${id}/decommission`);
  return response.data;
}

/**
 * Permanently delete an asset (ADMIN only).
 * @param {string} id - Asset UUID
 */
export async function deleteAssetApi(id) {
  const response = await api.delete(`/assets/${id}`);
  return response.data;
}
