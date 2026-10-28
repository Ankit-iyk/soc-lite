// src/pages/Dashboard.jsx
// Security Operations Center Dashboard with Live Charts (Phase 7).
// Real database-backed metrics, Recharts time-series & distributions,
// and linked recent activity tables.

import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  BellDot,
  AlertTriangle,
  ShieldAlert,
  FolderOpen,
  Clock,
  RefreshCw,
  ArrowRight,
  Shield,
  Layers,
  AlertCircle,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts';
import {
  getDashboardSummaryApi,
  subscribeToDashboardUpdates,
} from '../api/dashboard.api';
import { runDetectionApi } from '../api/rules.api';
import { useAuth } from '../hooks/useAuth';

// ── Severity & Status Palette (matching index.css tokens) ────────────────────
const SEVERITY_COLORS = {
  CRITICAL: '#ff3b3b',
  HIGH:     '#ff7b00',
  MEDIUM:   '#f0b429',
  LOW:      '#00d4aa',
};

const INCIDENT_STATUS_COLORS = {
  OPEN:          '#ff7b00',
  INVESTIGATING: '#f0b429',
  RESOLVED:      '#00d4aa',
  CLOSED:        '#5b9bd5',
};

function getSeverityBadgeClass(sev) {
  switch (sev) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH':     return 'badge-high';
    case 'MEDIUM':   return 'badge-medium';
    case 'LOW':      return 'badge-low';
    default:         return 'badge-info';
  }
}

function getStatusBadgeClass(status) {
  switch (status) {
    case 'OPEN':          return 'badge-high';
    case 'ACKNOWLEDGED':  return 'badge-medium';
    case 'INVESTIGATING': return 'badge-medium';
    case 'RESOLVED':      return 'badge-low';
    case 'CLOSED':        return 'badge-info';
    default:              return 'badge-info';
  }
}

function formatLocalTime(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ── Custom Tooltip for Recharts (Dark Theme) ─────────────────────────────────
function CustomChartTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div
      style={{
        background: '#0d1520',
        border: '1px solid #1e3048',
        borderRadius: '6px',
        padding: '0.5rem 0.75rem',
        boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
        fontSize: '12px',
      }}
    >
      <p style={{ margin: '0 0 0.25rem', color: '#8bafc9', fontWeight: 600 }}>{label}</p>
      {payload.map((item) => (
        <p key={item.name} style={{ margin: 0, color: item.color || '#00d4aa' }}>
          <span style={{ fontWeight: 600 }}>{item.name}:</span> {item.value}
        </p>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const { user } = useAuth();
  const canRunDetection = user?.role === 'ADMIN' || user?.role === 'ANALYST';
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [timeWindow, setTimeWindow] = useState('24h'); // '24h' | '7d'
  const [autoRefreshInterval, setAutoRefreshInterval] = useState(0); // 0 = off, 30000, 60000
  const [runningDetection, setRunningDetection] = useState(false);
  const [detectionMessage, setDetectionMessage] = useState('');
  const liveRefreshTimerRef = useRef(null);
  const latestRequestRef = useRef(0);
  const inFlightRequestRef = useRef(null);

  // Track mount state to prevent memory leaks / state updates on unmounted component
  const isMountedRef = useRef(true);
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // ── Fetch Dashboard Data ───────────────────────────────────────────────────
  const fetchDashboardData = useCallback(
    async (isManualRefresh = false) => {
      const requestKey = timeWindow;
      const existingRequest = inFlightRequestRef.current;
      if (existingRequest?.key === requestKey) {
        return existingRequest.promise;
      }

      if (isManualRefresh) setRefreshing(true);
      const requestId = ++latestRequestRef.current;

      const promise = (async () => {
        try {
          const res = await getDashboardSummaryApi({ timeWindow, recentLimit: 5 });
          if (!isMountedRef.current || requestId !== latestRequestRef.current) return;

          if (res?.success && res.data) {
            setData(res.data);
            setError('');
          } else {
            setError(res?.error || 'Failed to retrieve dashboard metrics.');
          }
        } catch (err) {
          if (isMountedRef.current && requestId === latestRequestRef.current) {
            setError(
              err.response?.data?.error ||
                err.message ||
                'Failed to communicate with the security dashboard API.'
            );
          }
        } finally {
          if (isMountedRef.current && requestId === latestRequestRef.current) {
            setLoading(false);
            setRefreshing(false);
          }
          if (inFlightRequestRef.current?.key === requestKey) {
            inFlightRequestRef.current = null;
          }
        }
      })();

      inFlightRequestRef.current = { key: requestKey, promise };
      return promise;
    },
    [timeWindow]
  );

  // Initial fetch and trigger on timeWindow change
  useEffect(() => {
    let active = true;
    async function load() {
      if (active) {
        await fetchDashboardData(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [fetchDashboardData]);

  const handleRunDetection = useCallback(async () => {
    setRunningDetection(true);
    setDetectionMessage('');
    setError('');

    try {
      const response = await runDetectionApi({ windowMinutes: timeWindow === '7d' ? 10080 : 1440, limit: 5000 });
      if (!response?.success || !response.data) {
        throw new Error(response?.error || 'Detection run failed.');
      }

      const { matchesFound = 0, alertsCreated = 0, alertsUpdated = 0 } = response.data;
      setDetectionMessage(
        `Detection complete: ${matchesFound} match(es), ${alertsCreated} alert(s) created, ${alertsUpdated} updated.`
      );
      await fetchDashboardData(false);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to run detection.');
    } finally {
      setRunningDetection(false);
    }
  }, [fetchDashboardData, timeWindow]);

  // ── Automatic dashboard updates ────────────────────────────────────────────
  useEffect(() => {
    const unsubscribe = subscribeToDashboardUpdates(() => {
      if (liveRefreshTimerRef.current) window.clearTimeout(liveRefreshTimerRef.current);
      liveRefreshTimerRef.current = window.setTimeout(() => {
        liveRefreshTimerRef.current = null;
        fetchDashboardData(false);
      }, 250);
    });

    return () => {
      unsubscribe();
      if (liveRefreshTimerRef.current) {
        window.clearTimeout(liveRefreshTimerRef.current);
        liveRefreshTimerRef.current = null;
      }
    };
  }, [fetchDashboardData]);

  // ── Optional periodic refresh (SSE remains enabled as the primary updates) ─
  useEffect(() => {
    if (!autoRefreshInterval || autoRefreshInterval <= 0) return;

    const intervalId = setInterval(() => {
      fetchDashboardData(false);
    }, autoRefreshInterval);

    return () => clearInterval(intervalId);
  }, [autoRefreshInterval, fetchDashboardData]);

  const kpis = data?.kpis || {
    totalEvents: 0,
    totalAlerts: 0,
    openAlerts: 0,
    criticalHighAlerts: 0,
    openIncidents: 0,
    investigatingIncidents: 0,
  };

  const alertsOverTime = data?.alertsOverTime || [];
  const alertSeverityDistribution = data?.alertSeverityDistribution || [];
  const incidentStatusDistribution = data?.incidentStatusDistribution || [];
  const recentAlerts = data?.recentAlerts || [];
  const recentIncidents = data?.recentIncidents || [];

  const totalAlertsInWindow = alertsOverTime.reduce((sum, b) => sum + (b.count || 0), 0);
  const totalAlertsInDistribution = alertSeverityDistribution.reduce(
    (sum, b) => sum + (b.count || 0),
    0
  );
  const totalIncidentsInDistribution = incidentStatusDistribution.reduce(
    (sum, b) => sum + (b.count || 0),
    0
  );

  return (
    <div className="fade-in">
      {/* ── Page Header ───────────────────────────────────────────────────── */}
      <div
        className="page-header"
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem',
          marginBottom: '1.5rem',
        }}
      >
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Shield size={24} color="var(--color-accent)" />
            Security Operations Dashboard
          </h1>
          <p className="page-subtitle">
            Real-time security posture, threat detections, and incident metrics.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          {/* Time Window Selector */}
          <div
            style={{
              display: 'inline-flex',
              background: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              padding: '2px',
            }}
          >
            <button
              type="button"
              onClick={() => setTimeWindow('24h')}
              style={{
                background: timeWindow === '24h' ? 'var(--color-accent-glow)' : 'transparent',
                color: timeWindow === '24h' ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                border: 'none',
                borderRadius: '4px',
                padding: '0.35rem 0.75rem',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              24 Hours
            </button>
            <button
              type="button"
              onClick={() => setTimeWindow('7d')}
              style={{
                background: timeWindow === '7d' ? 'var(--color-accent-glow)' : 'transparent',
                color: timeWindow === '7d' ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                border: 'none',
                borderRadius: '4px',
                padding: '0.35rem 0.75rem',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              7 Days
            </button>
          </div>

          {/* Auto Refresh Select */}
          <select
            value={autoRefreshInterval}
            onChange={(e) => setAutoRefreshInterval(Number(e.target.value))}
            style={{
              background: 'var(--color-bg-surface)',
              color: 'var(--color-text-secondary)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              padding: '0.4rem 0.6rem',
              fontSize: '12px',
              fontWeight: 500,
              cursor: 'pointer',
              outline: 'none',
            }}
            title="Auto-refresh interval"
          >
            <option value={0}>Auto-refresh: Off</option>
            <option value={30000}>Auto-refresh: 30s</option>
            <option value={60000}>Auto-refresh: 60s</option>
          </select>

          {/* Manual Refresh Button */}
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => fetchDashboardData(true)}
            disabled={refreshing || loading}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '12px' }}
          >
            <RefreshCw
              size={14}
              className={refreshing ? 'animate-spin' : ''}
              style={{ transition: 'transform 0.5s' }}
            />
            {refreshing ? 'Updating…' : 'Refresh'}
          </button>

          {canRunDetection && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleRunDetection}
              disabled={runningDetection || loading}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '12px' }}
            >
              <Activity size={14} className={runningDetection ? 'animate-pulse' : ''} />
              {runningDetection ? 'Running detection…' : 'Run detection'}
            </button>
          )}
        </div>
      </div>

      {/* Last Updated Timestamp & Status Indicator */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '12px',
          color: 'var(--color-text-muted)',
          marginBottom: '1.25rem',
          paddingBottom: '0.75rem',
          borderBottom: '1px solid var(--color-border-subtle)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: error ? 'var(--color-critical)' : 'var(--color-accent)',
              display: 'inline-block',
            }}
          />
          <span>System Status: {error ? 'API Error' : 'Online & Monitoring'}</span>
        </div>

        <div>
          {data?.generatedAt ? (
            <span>Last synchronized: {new Date(data.generatedAt).toLocaleTimeString()}</span>
          ) : (
            <span>Synchronizing metrics…</span>
          )}
        </div>
      </div>

      {/* ── Detection Action Status ─────────────────────────────────────── */}
      {detectionMessage && (
        <div
          role="status"
          style={{
            background: 'rgba(70, 211, 105, 0.08)',
            border: '1px solid rgba(70, 211, 105, 0.28)',
            borderRadius: 'var(--radius-card)',
            padding: '0.75rem 1rem',
            marginBottom: '1.5rem',
            color: 'var(--color-accent)',
            fontSize: '13px',
            fontWeight: 500,
          }}
        >
          {detectionMessage}
        </div>
      )}

      {/* ── Error Banner with Retry ────────────────────────────────────────── */}
      {error && (
        <div
          style={{
            background: 'rgba(255, 59, 59, 0.1)',
            border: '1px solid rgba(255, 59, 59, 0.3)',
            borderRadius: 'var(--radius-card)',
            padding: '1rem 1.25rem',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <AlertCircle size={20} color="var(--color-critical)" />
            <span style={{ color: 'var(--color-critical)', fontSize: '13px', fontWeight: 500 }}>
              {error}
            </span>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => fetchDashboardData(true)}
            style={{ fontSize: '12px', padding: '0.35rem 0.8rem' }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Initial Loading Skeleton ───────────────────────────────────────── */}
      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1rem',
            }}
          >
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <div
                key={i}
                className="card"
                style={{
                  height: 100,
                  background: 'var(--color-bg-card)',
                  animation: 'pulse 1.5s infinite',
                }}
              />
            ))}
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
              gap: '1rem',
            }}
          >
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="card"
                style={{
                  height: 280,
                  background: 'var(--color-bg-card)',
                  animation: 'pulse 1.5s infinite',
                }}
              />
            ))}
          </div>
        </div>
      ) : (
        <>
          {/* ── KPI Metric Cards ────────────────────────────────────────────── */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '1rem',
              marginBottom: '1.5rem',
            }}
          >
            {/* 1. Total Events */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  TOTAL LOG EVENTS
                </span>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 6,
                    background: 'rgba(0, 212, 170, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Activity size={16} color="var(--color-accent)" />
                </div>
              </div>
              <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                {kpis.totalEvents.toLocaleString()}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                Normalized security log entries
              </div>
            </div>

            {/* 2. Total Alerts */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  TOTAL ALERTS
                </span>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 6,
                    background: 'rgba(240, 180, 41, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <BellDot size={16} color="var(--color-medium)" />
                </div>
              </div>
              <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                {kpis.totalAlerts.toLocaleString()}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                Detections fired across all rules
              </div>
            </div>

            {/* 3. Open Alerts */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  OPEN ALERTS
                </span>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 6,
                    background: 'rgba(255, 123, 0, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <AlertTriangle size={16} color="var(--color-high)" />
                </div>
              </div>
              <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-high)' }}>
                {kpis.openAlerts.toLocaleString()}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                Awaiting triage or acknowledgment
              </div>
            </div>

            {/* 4. Critical & High Alerts */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  CRITICAL & HIGH ALERTS
                </span>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 6,
                    background: 'rgba(255, 59, 59, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <ShieldAlert size={16} color="var(--color-critical)" />
                </div>
              </div>
              <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-critical)' }}>
                {kpis.criticalHighAlerts.toLocaleString()}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                Elevated threat severity detections
              </div>
            </div>

            {/* 5. Open Incidents */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  OPEN INCIDENTS
                </span>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 6,
                    background: 'rgba(255, 123, 0, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <FolderOpen size={16} color="var(--color-high)" />
                </div>
              </div>
              <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-high)' }}>
                {kpis.openIncidents.toLocaleString()}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                Active investigation cases
              </div>
            </div>

            {/* 6. Investigating Incidents */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
                  INVESTIGATING
                </span>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: 6,
                    background: 'rgba(240, 180, 41, 0.1)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Clock size={16} color="var(--color-medium)" />
                </div>
              </div>
              <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-medium)' }}>
                {kpis.investigatingIncidents.toLocaleString()}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                Under active analyst review
              </div>
            </div>
          </div>

          {/* ── Visual Charts Grid ─────────────────────────────────────────── */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
              gap: '1.25rem',
              marginBottom: '1.5rem',
            }}
          >
            {/* Chart 1: Alert Volume Over Time */}
            <div className="card" style={{ minHeight: 320, display: 'flex', flexDirection: 'column' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '1rem',
                }}
              >
                <div>
                  <div className="card-title" style={{ margin: 0 }}>
                    Alert Volume Over Time ({timeWindow === '7d' ? 'Past 7 Days' : 'Past 24 Hours'})
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    Total in period: {totalAlertsInWindow}
                  </div>
                </div>
                <Layers size={16} color="var(--color-accent)" />
              </div>

              {totalAlertsInWindow === 0 ? (
                <div
                  style={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.5rem',
                    color: 'var(--color-text-muted)',
                    fontSize: '12px',
                    border: '1px dashed var(--color-border)',
                    borderRadius: '8px',
                    padding: '2rem',
                  }}
                >
                  <BellDot size={24} color="var(--color-border)" />
                  <span>No alerts recorded in this time window.</span>
                </div>
              ) : (
                <div style={{ width: '100%', height: 240 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                      data={alertsOverTime}
                      margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00d4aa" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#00d4aa" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e3048" vertical={false} />
                      <XAxis
                        dataKey="label"
                        stroke="#4d7a9e"
                        fontSize={11}
                        tickLine={false}
                        interval={timeWindow === '24h' ? 3 : 0}
                      />
                      <YAxis
                        stroke="#4d7a9e"
                        fontSize={11}
                        tickLine={false}
                        allowDecimals={false}
                      />
                      <Tooltip content={<CustomChartTooltip />} />
                      <Area
                        type="monotone"
                        dataKey="count"
                        name="Alerts"
                        stroke="#00d4aa"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#alertGrad)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {/* Chart 2: Alert Severity Distribution */}
            <div className="card" style={{ minHeight: 320, display: 'flex', flexDirection: 'column' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '1rem',
                }}
              >
                <div>
                  <div className="card-title" style={{ margin: 0 }}>
                    Alerts by Severity
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    Total alerts: {totalAlertsInDistribution}
                  </div>
                </div>
                <ShieldAlert size={16} color="var(--color-high)" />
              </div>

              {totalAlertsInDistribution === 0 ? (
                <div
                  style={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.5rem',
                    color: 'var(--color-text-muted)',
                    fontSize: '12px',
                    border: '1px dashed var(--color-border)',
                    borderRadius: '8px',
                    padding: '2rem',
                  }}
                >
                  <ShieldAlert size={24} color="var(--color-border)" />
                  <span>No alerts available to display.</span>
                </div>
              ) : (
                <div style={{ width: '100%', height: 240 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={alertSeverityDistribution}
                        dataKey="count"
                        nameKey="severity"
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={80}
                        paddingAngle={4}
                      >
                        {alertSeverityDistribution.map((entry) => (
                          <Cell
                            key={entry.severity}
                            fill={SEVERITY_COLORS[entry.severity] || '#5b9bd5'}
                            stroke="#0d1520"
                            strokeWidth={2}
                          />
                        ))}
                      </Pie>
                      <Tooltip content={<CustomChartTooltip />} />
                      <Legend
                        verticalAlign="bottom"
                        height={36}
                        formatter={(val) => (
                          <span style={{ fontSize: '11px', color: '#8bafc9', fontWeight: 500 }}>
                            {val}
                          </span>
                        )}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {/* Chart 3: Incident Status Breakdown */}
            <div className="card" style={{ minHeight: 320, display: 'flex', flexDirection: 'column' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '1rem',
                }}
              >
                <div>
                  <div className="card-title" style={{ margin: 0 }}>
                    Incidents by Status
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    Total cases: {totalIncidentsInDistribution}
                  </div>
                </div>
                <FolderOpen size={16} color="var(--color-medium)" />
              </div>

              {totalIncidentsInDistribution === 0 ? (
                <div
                  style={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.5rem',
                    color: 'var(--color-text-muted)',
                    fontSize: '12px',
                    border: '1px dashed var(--color-border)',
                    borderRadius: '8px',
                    padding: '2rem',
                  }}
                >
                  <FolderOpen size={24} color="var(--color-border)" />
                  <span>No incidents recorded.</span>
                </div>
              ) : (
                <div style={{ width: '100%', height: 240 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={incidentStatusDistribution}
                      margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e3048" vertical={false} />
                      <XAxis
                        dataKey="status"
                        stroke="#4d7a9e"
                        fontSize={11}
                        tickLine={false}
                      />
                      <YAxis
                        stroke="#4d7a9e"
                        fontSize={11}
                        tickLine={false}
                        allowDecimals={false}
                      />
                      <Tooltip content={<CustomChartTooltip />} />
                      <Bar dataKey="count" name="Incidents" radius={[4, 4, 0, 0]}>
                        {incidentStatusDistribution.map((entry) => (
                          <Cell
                            key={entry.status}
                            fill={INCIDENT_STATUS_COLORS[entry.status] || '#5b9bd5'}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>

          {/* ── Recent Activity Section (Alerts & Incidents) ───────────────── */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))',
              gap: '1.25rem',
            }}
          >
            {/* Recent Alerts Card */}
            <div className="card">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '1rem',
                  paddingBottom: '0.5rem',
                  borderBottom: '1px solid var(--color-border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <BellDot size={16} color="var(--color-accent)" />
                  <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Recent Threat Detections
                  </span>
                </div>
                <Link
                  to="/alerts"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    fontSize: '12px',
                    color: 'var(--color-accent)',
                    textDecoration: 'none',
                    fontWeight: 500,
                  }}
                >
                  View all alerts <ArrowRight size={12} />
                </Link>
              </div>

              {recentAlerts.length === 0 ? (
                <div
                  style={{
                    padding: '2rem 1rem',
                    textAlign: 'center',
                    color: 'var(--color-text-muted)',
                    fontSize: '12px',
                  }}
                >
                  No alerts generated yet. Ingest logs and run detection to generate alerts.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12.5px' }}>
                    <thead>
                      <tr
                        style={{
                          textAlign: 'left',
                          color: 'var(--color-text-muted)',
                          fontSize: '11px',
                          borderBottom: '1px solid var(--color-border)',
                        }}
                      >
                        <th style={{ padding: '0.5rem 0.75rem' }}>SEVERITY</th>
                        <th style={{ padding: '0.5rem 0.75rem' }}>TITLE</th>
                        <th style={{ padding: '0.5rem 0.75rem' }}>RULE</th>
                        <th style={{ padding: '0.5rem 0.75rem' }}>STATUS</th>
                        <th style={{ padding: '0.5rem 0.75rem', textAlign: 'right' }}>FIRED</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentAlerts.map((alert) => (
                        <tr
                          key={alert.id}
                          style={{
                            borderBottom: '1px solid var(--color-border-subtle)',
                            transition: 'background 0.15s ease',
                          }}
                        >
                          <td style={{ padding: '0.6rem 0.75rem' }}>
                            <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td
                            style={{
                              padding: '0.6rem 0.75rem',
                              fontWeight: 500,
                              color: 'var(--color-text-primary)',
                              maxWidth: 200,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={alert.title}
                          >
                            <Link
                              to="/alerts"
                              style={{ color: 'inherit', textDecoration: 'none' }}
                              className="hover:underline"
                            >
                              {alert.title}
                            </Link>
                          </td>
                          <td
                            style={{
                              padding: '0.6rem 0.75rem',
                              color: 'var(--color-text-secondary)',
                              fontSize: '11.5px',
                            }}
                          >
                            {alert.rule?.name || 'Manual Alert'}
                          </td>
                          <td style={{ padding: '0.6rem 0.75rem' }}>
                            <span className={`badge ${getStatusBadgeClass(alert.status)}`}>
                              {alert.status}
                            </span>
                          </td>
                          <td
                            style={{
                              padding: '0.6rem 0.75rem',
                              textAlign: 'right',
                              color: 'var(--color-text-muted)',
                              fontSize: '11.5px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {formatLocalTime(alert.firedAt)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Recent Incidents Card */}
            <div className="card">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '1rem',
                  paddingBottom: '0.5rem',
                  borderBottom: '1px solid var(--color-border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <FolderOpen size={16} color="var(--color-accent)" />
                  <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Recent Incident Cases
                  </span>
                </div>
                <Link
                  to="/incidents"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    fontSize: '12px',
                    color: 'var(--color-accent)',
                    textDecoration: 'none',
                    fontWeight: 500,
                  }}
                >
                  View all incidents <ArrowRight size={12} />
                </Link>
              </div>

              {recentIncidents.length === 0 ? (
                <div
                  style={{
                    padding: '2rem 1rem',
                    textAlign: 'center',
                    color: 'var(--color-text-muted)',
                    fontSize: '12px',
                  }}
                >
                  No incidents recorded yet. Create an incident from the Incidents page.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12.5px' }}>
                    <thead>
                      <tr
                        style={{
                          textAlign: 'left',
                          color: 'var(--color-text-muted)',
                          fontSize: '11px',
                          borderBottom: '1px solid var(--color-border)',
                        }}
                      >
                        <th style={{ padding: '0.5rem 0.75rem' }}>ID</th>
                        <th style={{ padding: '0.5rem 0.75rem' }}>TITLE</th>
                        <th style={{ padding: '0.5rem 0.75rem' }}>SEVERITY</th>
                        <th style={{ padding: '0.5rem 0.75rem' }}>STATUS</th>
                        <th style={{ padding: '0.5rem 0.75rem' }}>ASSIGNEE</th>
                        <th style={{ padding: '0.5rem 0.75rem', textAlign: 'right' }}>CREATED</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentIncidents.map((inc) => (
                        <tr
                          key={inc.id}
                          style={{
                            borderBottom: '1px solid var(--color-border-subtle)',
                            transition: 'background 0.15s ease',
                          }}
                        >
                          <td style={{ padding: '0.6rem 0.75rem' }}>
                            <Link
                              to="/incidents"
                              style={{
                                fontFamily: 'var(--font-mono)',
                                color: 'var(--color-accent)',
                                fontWeight: 600,
                                textDecoration: 'none',
                              }}
                            >
                              {inc.readableId}
                            </Link>
                          </td>
                          <td
                            style={{
                              padding: '0.6rem 0.75rem',
                              fontWeight: 500,
                              color: 'var(--color-text-primary)',
                              maxWidth: 160,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                            title={inc.title}
                          >
                            <Link
                              to="/incidents"
                              style={{ color: 'inherit', textDecoration: 'none' }}
                              className="hover:underline"
                            >
                              {inc.title}
                            </Link>
                          </td>
                          <td style={{ padding: '0.6rem 0.75rem' }}>
                            <span className={`badge ${getSeverityBadgeClass(inc.severity)}`}>
                              {inc.severity}
                            </span>
                          </td>
                          <td style={{ padding: '0.6rem 0.75rem' }}>
                            <span className={`badge ${getStatusBadgeClass(inc.status)}`}>
                              {inc.status}
                            </span>
                          </td>
                          <td
                            style={{
                              padding: '0.6rem 0.75rem',
                              color: 'var(--color-text-secondary)',
                              fontSize: '11.5px',
                            }}
                          >
                            {inc.assignedTo?.name || inc.assignedTo?.email || 'Unassigned'}
                          </td>
                          <td
                            style={{
                              padding: '0.6rem 0.75rem',
                              textAlign: 'right',
                              color: 'var(--color-text-muted)',
                              fontSize: '11.5px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {formatLocalTime(inc.createdAt)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
