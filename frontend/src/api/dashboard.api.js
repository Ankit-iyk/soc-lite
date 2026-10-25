// src/api/dashboard.api.js
// API client for Security Operations Center Dashboard (Phase 7).
// Uses the shared configured Axios instance (with JWT injection & 401 handling).

import api from './client';

/**
 * Fetch aggregated dashboard metrics, charts, and recent activity.
 * @param {object} [params] - Query options: { timeWindow: '24h' | '7d', recentLimit: number }
 * @returns {Promise<{ success: boolean, data: { kpis: object, alertsOverTime: Array, alertSeverityDistribution: Array, incidentStatusDistribution: Array, recentAlerts: Array, recentIncidents: Array, generatedAt: string } }>}
 */
export async function getDashboardSummaryApi(params = {}) {
  const response = await api.get('/dashboard/summary', { params });
  return response.data;
}
