// src/api/logs.api.js
// API methods for log ingestion, raw logs, and normalized events.

import api from './client';

/**
 * Ingest single or batch logs into the backend.
 * @param {object} payload - Either { source, content } or { logs: [{ source, content }, ...] }
 * @returns {Promise<object>} API response { success, message, data: { count, events } }
 */
export async function ingestLogsApi(payload) {
  const response = await api.post('/logs/ingest', payload);
  return response.data;
}

/**
 * Fetch paginated raw logs.
 * @param {object} params - { page, limit, source, search }
 * @returns {Promise<object>} API response { success, data: RawLog[], pagination }
 */
export async function getRawLogsApi(params = {}) {
  const response = await api.get('/logs', { params });
  return response.data;
}

/**
 * Fetch paginated normalized events with filters.
 * @param {object} params - { page, limit, eventType, severity, srcIp, dstIp, username, startDate, endDate }
 * @returns {Promise<object>} API response { success, data: Event[], pagination }
 */
export async function getEventsApi(params = {}) {
  const response = await api.get('/events', { params });
  return response.data;
}

/**
 * Fetch a single event by ID with its originating raw log.
 * @param {string} id - Event UUID
 * @returns {Promise<object>} API response { success, data: EventWithRawLog }
 */
export async function getEventByIdApi(id) {
  const response = await api.get(`/events/${id}`);
  return response.data;
}
