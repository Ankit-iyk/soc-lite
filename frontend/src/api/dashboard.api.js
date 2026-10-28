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

export function subscribeToDashboardUpdates(onUpdate, options = {}) {
  const abortController = new AbortController();
  let stopped = false;
  let reconnectTimer = null;
  let retryDelayMs = options.initialRetryDelayMs ?? 1_000;

  const baseUrl = api.defaults.baseURL || '/api';
  const normalizedBaseUrl = baseUrl.startsWith('http')
    ? `${baseUrl.replace(/\/$/, '')}/`
    : `${window.location.origin}/${baseUrl.replace(/^\//, '').replace(/\/$/, '')}/`;
  const liveUrl = new URL('dashboard/live', normalizedBaseUrl);

  const scheduleReconnect = () => {
    if (stopped || reconnectTimer) return;
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      retryDelayMs = Math.min(retryDelayMs * 2, 30_000);
      void connect();
    }, retryDelayMs);
  };

  async function connect() {
    try {
      const token = window.localStorage.getItem('soc_token');
      const response = await fetch(liveUrl, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: abortController.signal,
      });

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          return;
        }
        throw new Error(`Dashboard live stream returned HTTP ${response.status}`);
      }
      if (!response.body) {
        throw new Error('Dashboard live stream is not readable');
      }

      retryDelayMs = options.initialRetryDelayMs ?? 1_000;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (!stopped) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        let boundary = buffer.indexOf('\n\n');
        while (boundary >= 0) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          boundary = buffer.indexOf('\n\n');

          let eventType = 'message';
          const dataLines = [];
          for (const line of frame.split('\n')) {
            if (line.startsWith('event: ')) eventType = line.slice(7);
            if (line.startsWith('data: ')) dataLines.push(line.slice(6));
          }
          if (dataLines.length === 0 || eventType === 'connected') continue;

          try {
            onUpdate({
              type: eventType,
              payload: JSON.parse(dataLines.join('\n')),
            });
          } catch (error) {
            console.error('Invalid dashboard live update:', error);
          }
        }
      }
      scheduleReconnect();
    } catch (error) {
      if (!stopped && error.name !== 'AbortError') scheduleReconnect();
    }
  }

  void connect();

  return () => {
    stopped = true;
    abortController.abort();
    if (reconnectTimer) window.clearTimeout(reconnectTimer);
  };
}
