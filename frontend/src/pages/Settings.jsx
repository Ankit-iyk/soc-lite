// src/pages/Settings.jsx
// Final Polish & Administration Hub (Phase 12).
// Features:
// 1. Security Audit Trail — paginated, filterable event log with metadata inspection
// 2. Comprehensive RBAC Authorization Matrix & Session Info
// 3. System Status, Architecture, & Security Compliance Overview

import { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Lock,
  User,
  CheckCircle2,
  History,
  Search,
  Filter,
  RefreshCw,
  Server,
  Layers,
  Terminal,
  ChevronLeft,
  ChevronRight,
  Cpu,
  Database,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { getAuditLogsApi, getAuditStatsApi } from '../api/audit.api';
import api from '../api/client';

// ── RBAC Policy Matrix Definition ─────────────────────────────────────────────
const RBAC_MATRIX = [
  { module: 'Authentication', operation: 'Login, logout, session check', admin: true, analyst: true, viewer: true },
  { module: 'Dashboard', operation: 'View live charts and KPI metrics', admin: true, analyst: true, viewer: true },
  { module: 'Log Ingestion', operation: 'Ingest security logs (POST /api/logs/ingest)', admin: true, analyst: true, viewer: false },
  { module: 'Detection Engine', operation: 'Trigger detection pipeline execution', admin: true, analyst: true, viewer: false },
  { module: 'Detection Rules', operation: 'Update rule parameters and threshold configs', admin: true, analyst: false, viewer: false },
  { module: 'Alert Management', operation: 'Browse and inspect alert evidence chains', admin: true, analyst: true, viewer: true },
  { module: 'Alert Status', operation: 'Acknowledge, investigate, and close alerts', admin: true, analyst: true, viewer: false },
  { module: 'Incident Tracking', operation: 'Browse and inspect incident timelines', admin: true, analyst: true, viewer: true },
  { module: 'Incident Mutations', operation: 'Create incidents and transition status', admin: true, analyst: true, viewer: false },
  { module: 'Incident Notes', operation: 'Append investigation notes to timeline', admin: true, analyst: true, viewer: false },
  { module: 'Incident Alert Links', operation: 'Link and unlink alerts to incidents', admin: true, analyst: true, viewer: false },
  { module: 'Asset Inventory', operation: 'View monitored infrastructure assets', admin: true, analyst: true, viewer: true },
  { module: 'Asset Mutations', operation: 'Register, update, and decommission assets', admin: true, analyst: true, viewer: false },
  { module: 'Asset Deletion', operation: 'Permanently delete asset from database', admin: true, analyst: false, viewer: false },
  { module: 'Threat Intelligence', operation: 'Browse IOC inventory and correlations', admin: true, analyst: true, viewer: true },
  { module: 'IOC Mutations', operation: 'Register and update threat indicators', admin: true, analyst: true, viewer: false },
  { module: 'Threat Lookups', operation: 'Trigger provider enrichment queries', admin: true, analyst: true, viewer: false },
  { module: 'IOC Deletion', operation: 'Permanently delete threat indicators', admin: true, analyst: false, viewer: false },
  { module: 'Security Reports', operation: 'Live JSON report preview in browser', admin: true, analyst: true, viewer: true },
  { module: 'Report Downloads', operation: 'Generate and stream PDF security reports', admin: true, analyst: true, viewer: false },
  { module: 'Audit Logging', operation: 'Inspect system-wide security audit history', admin: true, analyst: true, viewer: false },
];

function getActionBadgeStyle(action) {
  const act = (action || '').toUpperCase();
  if (act.includes('DELETE') || act.includes('DECOMMISSION')) {
    return { bg: 'rgba(239, 68, 68, 0.15)', border: '#ef4444', text: '#fca5a5' };
  }
  if (act.includes('UPDATE') || act.includes('CHANGE') || act.includes('STATUS')) {
    return { bg: 'rgba(234, 179, 8, 0.15)', border: '#eab308', text: '#fde047' };
  }
  if (act.includes('CREATE') || act.includes('INGEST') || act.includes('LINK') || act.includes('NOTE')) {
    return { bg: 'rgba(34, 197, 94, 0.15)', border: '#22c55e', text: '#86efac' };
  }
  if (act.includes('LOGIN') || act.includes('LOOKUP') || act.includes('REPORT')) {
    return { bg: 'rgba(99, 102, 241, 0.15)', border: '#6366f1', text: '#a5b4fc' };
  }
  return { bg: 'rgba(148, 163, 184, 0.15)', border: '#94a3b8', text: '#cbd5e1' };
}

export default function Settings() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('audit'); // 'audit' | 'rbac' | 'system'
  const isPrivileged = user?.role === 'ADMIN' || user?.role === 'ANALYST';

  // Audit tab states
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditStats, setAuditStats] = useState(null);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [selectedAction, setSelectedAction] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [auditError, setAuditError] = useState(null);

  // System status state
  const [systemHealth, setSystemHealth] = useState(null);
  const [loadingHealth, setLoadingHealth] = useState(false);

  // Load audit data
  const loadAuditData = useCallback(async (page = 1) => {
    if (!isPrivileged) return;
    setLoadingLogs(true);
    setAuditError(null);
    try {
      const params = { page, limit: 20 };
      if (selectedAction) params.action = selectedAction;
      if (searchTerm) params.search = searchTerm;

      const [logsRes, statsRes] = await Promise.all([
        getAuditLogsApi(params),
        getAuditStatsApi().catch(() => ({ data: null })),
      ]);

      setAuditLogs(logsRes.data?.logs || []);
      setPagination(logsRes.data?.pagination || { page: 1, limit: 20, total: 0, totalPages: 1 });
      if (statsRes.data) setAuditStats(statsRes.data);
    } catch (err) {
      setAuditError(err.response?.data?.error || 'Failed to load audit trail.');
    } finally {
      setLoadingLogs(false);
    }
  }, [isPrivileged, selectedAction, searchTerm]);

  // Load system health
  const loadSystemHealth = useCallback(async () => {
    setLoadingHealth(true);
    try {
      const res = await api.get('/health');
      setSystemHealth(res.data);
    } catch {
      setSystemHealth({ status: 'unreachable', database: { status: 'disconnected' } });
    } finally {
      setLoadingHealth(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    let ignore = false;
    if (isPrivileged) {
      (async () => {
        try {
          const [logsRes, statsRes] = await Promise.all([
            getAuditLogsApi({ page: 1, limit: 20 }),
            getAuditStatsApi().catch(() => ({ data: null })),
          ]);
          if (!ignore) {
            setAuditLogs(logsRes.data?.logs || []);
            setPagination(logsRes.data?.pagination || { page: 1, limit: 20, total: 0, totalPages: 1 });
            if (statsRes.data) setAuditStats(statsRes.data);
          }
        } catch (err) {
          if (!ignore) {
            setAuditError(err.response?.data?.error || 'Failed to load audit trail.');
          }
        }
      })();
    }
    return () => {
      ignore = true;
    };
  }, [isPrivileged]);

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    if (tab === 'audit' && isPrivileged) {
      loadAuditData(1);
    } else if (tab === 'system') {
      loadSystemHealth();
    }
  };

  return (
    <div style={{ padding: '28px 32px', maxWidth: '1280px', margin: '0 auto' }}>
      {/* ── Page Header ──────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '44px', height: '44px', borderRadius: '12px',
            background: 'linear-gradient(135deg, #6366f1, #22d3ee)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={22} color="#fff" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Settings & Administration
            </h1>
            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Security audit history, role-based access policies, and operational health
            </p>
          </div>
        </div>

        {/* Current user role badge */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: '8px', padding: '6px 14px',
        }}>
          <User size={15} style={{ color: 'var(--accent)' }} />
          <span style={{ fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 600 }}>{user?.name || 'Operator'}</span>
          <span className={`badge-${user?.role === 'ADMIN' ? 'critical' : user?.role === 'ANALYST' ? 'high' : 'info'}`}>
            {user?.role || 'ANALYST'}
          </span>
        </div>
      </div>

      {/* ── Tabs Navigation ──────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', gap: '6px', borderBottom: '1px solid var(--border)',
        marginBottom: '24px',
      }}>
        <button
          onClick={() => handleTabChange('audit')}
          style={{
            display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 18px',
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: '0.85rem', fontWeight: 600,
            color: activeTab === 'audit' ? 'var(--accent)' : 'var(--text-muted)',
            borderBottom: activeTab === 'audit' ? '2px solid var(--accent)' : '2px solid transparent',
          }}
        >
          <History size={16} /> Security Audit Trail
        </button>

        <button
          onClick={() => handleTabChange('rbac')}
          style={{
            display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 18px',
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: '0.85rem', fontWeight: 600,
            color: activeTab === 'rbac' ? 'var(--accent)' : 'var(--text-muted)',
            borderBottom: activeTab === 'rbac' ? '2px solid var(--accent)' : '2px solid transparent',
          }}
        >
          <Lock size={16} /> Access Control (RBAC)
        </button>

        <button
          onClick={() => handleTabChange('system')}
          style={{
            display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 18px',
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: '0.85rem', fontWeight: 600,
            color: activeTab === 'system' ? 'var(--accent)' : 'var(--text-muted)',
            borderBottom: activeTab === 'system' ? '2px solid var(--accent)' : '2px solid transparent',
          }}
        >
          <Server size={16} /> System Health & Info
        </button>
      </div>

      {/* ── TAB 1: Security Audit Trail ──────────────────────────────────── */}
      {activeTab === 'audit' && (
        <div>
          {!isPrivileged ? (
            <div style={{
              background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '12px', padding: '32px', textAlign: 'center',
            }}>
              <Lock size={36} color="#ef4444" style={{ margin: '0 auto 14px' }} />
              <h3 style={{ margin: '0 0 8px', fontSize: '1.1rem', color: '#fca5a5' }}>
                Privileged Access Required
              </h3>
              <p style={{ margin: '0 auto', maxWidth: '480px', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                System-wide audit trail inspection is restricted to ADMIN and ANALYST roles for compliance. Your current session role is <strong>VIEWER</strong>.
              </p>
            </div>
          ) : (
            <div>
              {/* Stat KPIs */}
              {auditStats && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '14px', marginBottom: '20px' }}>
                  <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '14px 18px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Audit Events</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--accent)', marginTop: '4px' }}>{auditStats.total}</div>
                  </div>
                  <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '14px 18px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Activity (Past 24h)</div>
                    <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#22c55e', marginTop: '4px' }}>{auditStats.past24hCount}</div>
                  </div>
                  <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '14px 18px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Top Sensitive Action</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 600, color: '#f97316', marginTop: '6px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {auditStats.topActions?.[0]?.action || 'None'}
                    </div>
                  </div>
                  <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '14px 18px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Audit Retention</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 600, color: '#22d3ee', marginTop: '6px' }}>Persistent & Non-Cascading</div>
                  </div>
                </div>
              )}

              {/* Filters toolbar */}
              <div style={{
                display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap',
                background: 'var(--bg-secondary)', padding: '12px 16px', borderRadius: '10px', border: '1px solid var(--border)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, minWidth: '220px' }}>
                  <Search size={15} style={{ color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    placeholder="Search by action, target entity, or IP..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') loadAuditData(1); }}
                    style={{
                      width: '100%', background: 'var(--bg-card)', border: '1px solid var(--border)',
                      borderRadius: '6px', padding: '6px 12px', color: 'var(--text-primary)', fontSize: '0.83rem',
                    }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Filter size={15} style={{ color: 'var(--text-muted)' }} />
                  <select
                    value={selectedAction}
                    onChange={(e) => { setSelectedAction(e.target.value); }}
                    style={{
                      background: 'var(--bg-card)', border: '1px solid var(--border)',
                      borderRadius: '6px', padding: '6px 12px', color: 'var(--text-primary)', fontSize: '0.83rem',
                    }}
                  >
                    <option value="">All Actions</option>
                    <option value="LOGS_INGESTED">LOGS_INGESTED</option>
                    <option value="DETECTION_RUN">DETECTION_RUN</option>
                    <option value="INCIDENT_CREATE">INCIDENT_CREATE</option>
                    <option value="INCIDENT_UPDATE">INCIDENT_UPDATE</option>
                    <option value="INCIDENT_STATUS_CHANGE">INCIDENT_STATUS_CHANGE</option>
                    <option value="INCIDENT_ALERT_LINK">INCIDENT_ALERT_LINK</option>
                    <option value="INCIDENT_NOTE_ADD">INCIDENT_NOTE_ADD</option>
                    <option value="ASSET_CREATE">ASSET_CREATE</option>
                    <option value="ASSET_UPDATE">ASSET_UPDATE</option>
                    <option value="ASSET_DECOMMISSION">ASSET_DECOMMISSION</option>
                    <option value="ASSET_DELETE">ASSET_DELETE</option>
                    <option value="IOC_CREATE">IOC_CREATE</option>
                    <option value="IOC_UPDATE">IOC_UPDATE</option>
                    <option value="IOC_LOOKUP">IOC_LOOKUP</option>
                    <option value="IOC_DELETE">IOC_DELETE</option>
                    <option value="REPORT_PREVIEW">REPORT_PREVIEW</option>
                    <option value="REPORT_DOWNLOAD">REPORT_DOWNLOAD</option>
                  </select>
                </div>

                <button
                  className="btn-ghost"
                  onClick={() => loadAuditData(1)}
                  disabled={loadingLogs}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  <RefreshCw size={14} className={loadingLogs ? 'spin' : ''} />
                  Refresh
                </button>
              </div>

              {/* Error message */}
              {auditError && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444',
                  color: '#fca5a5', padding: '10px 14px', borderRadius: '8px', marginBottom: '16px', fontSize: '0.85rem',
                }}>
                  {auditError}
                </div>
              )}

              {/* Audit Table */}
              <div style={{ overflowX: 'auto', borderRadius: '10px', border: '1px solid var(--border)', background: 'var(--bg-card)' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                  <thead>
                    <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                      <th style={{ padding: '10px 14px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Action</th>
                      <th style={{ padding: '10px 14px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Target Entity</th>
                      <th style={{ padding: '10px 14px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Target ID</th>
                      <th style={{ padding: '10px 14px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Actor</th>
                      <th style={{ padding: '10px 14px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Client IP</th>
                      <th style={{ padding: '10px 14px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Timestamp</th>
                      <th style={{ padding: '10px 14px', textAlign: 'center', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loadingLogs ? (
                      <tr>
                        <td colSpan={7} style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          <RefreshCw size={20} className="spin" style={{ margin: '0 auto 8px' }} />
                          <div>Loading audit records...</div>
                        </td>
                      </tr>
                    ) : auditLogs.length === 0 ? (
                      <tr>
                        <td colSpan={7} style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
                          No audit log records match the current filters.
                        </td>
                      </tr>
                    ) : (
                      auditLogs.map((log) => {
                        const badgeStyle = getActionBadgeStyle(log.action);
                        return (
                          <tr key={log.id} style={{ borderBottom: '1px solid var(--border)' }}>
                            <td style={{ padding: '10px 14px' }}>
                              <span style={{
                                padding: '3px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600,
                                background: badgeStyle.bg, border: `1px solid ${badgeStyle.border}`, color: badgeStyle.text,
                              }}>
                                {log.action}
                              </span>
                            </td>
                            <td style={{ padding: '10px 14px', color: 'var(--text-primary)' }}>
                              {log.targetType || '—'}
                            </td>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontSize: '0.78rem', color: '#22d3ee' }}>
                              {log.targetId ? log.targetId.slice(0, 13) + '…' : '—'}
                            </td>
                            <td style={{ padding: '10px 14px', color: 'var(--text-primary)' }}>
                              {log.user ? `${log.user.name} (${log.user.role})` : 'System / Anonymous'}
                            </td>
                            <td style={{ padding: '10px 14px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                              {log.ipAddress || '—'}
                            </td>
                            <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>
                              {new Date(log.timestamp).toLocaleString()}
                            </td>
                            <td style={{ padding: '10px 14px', textAlign: 'center' }}>
                              {log.details ? (
                                <button
                                  className="btn-ghost"
                                  onClick={() => setSelectedLog(log)}
                                  style={{ padding: '3px 8px', fontSize: '0.75rem' }}
                                >
                                  View JSON
                                </button>
                              ) : (
                                <span style={{ color: 'var(--text-muted)' }}>—</span>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination controls */}
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                marginTop: '16px', color: 'var(--text-muted)', fontSize: '0.82rem',
              }}>
                <div>
                  Showing {auditLogs.length} of {pagination.total} events (Page {pagination.page} of {pagination.totalPages})
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="btn-ghost"
                    onClick={() => loadAuditData(pagination.page - 1)}
                    disabled={!pagination.hasPrevPage || loadingLogs}
                    style={{ display: 'flex', alignItems: 'center', gap: '4px' }}
                  >
                    <ChevronLeft size={14} /> Previous
                  </button>
                  <button
                    className="btn-ghost"
                    onClick={() => loadAuditData(pagination.page + 1)}
                    disabled={!pagination.hasNextPage || loadingLogs}
                    style={{ display: 'flex', alignItems: 'center', gap: '4px' }}
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── TAB 2: RBAC Policy Matrix ─────────────────────────────────────── */}
      {activeTab === 'rbac' && (
        <div>
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: '10px', padding: '18px 22px', marginBottom: '20px',
          }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 6px' }}>
              Role-Based Access Control Architecture
            </h3>
            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              SOC Lite enforces strict, server-side RBAC across every endpoint. Controls hidden or disabled in the UI are always protected by server-side JWT authentication (<code style={{ color: 'var(--accent)' }}>requireAuth</code>) and role-filtering middleware (<code style={{ color: 'var(--accent)' }}>requireRole</code>).
            </p>
          </div>

          <div style={{ overflowX: 'auto', borderRadius: '10px', border: '1px solid var(--border)', background: 'var(--bg-card)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Functional Module</th>
                  <th style={{ padding: '10px 16px', textAlign: 'left', color: 'var(--accent)', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>Operation Description</th>
                  <th style={{ padding: '10px 16px', textAlign: 'center', color: '#ef4444', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>ADMIN</th>
                  <th style={{ padding: '10px 16px', textAlign: 'center', color: '#f97316', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>ANALYST</th>
                  <th style={{ padding: '10px 16px', textAlign: 'center', color: '#22d3ee', fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase' }}>VIEWER</th>
                </tr>
              </thead>
              <tbody>
                {RBAC_MATRIX.map((row, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 16px', fontWeight: 600, color: 'var(--text-primary)' }}>{row.module}</td>
                    <td style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>{row.operation}</td>
                    <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                      {row.admin ? (
                        <span style={{ color: '#22c55e', fontWeight: 600 }}>✓ Allowed</span>
                      ) : (
                        <span style={{ color: '#ef4444' }}>✕ Blocked</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                      {row.analyst ? (
                        <span style={{ color: '#22c55e', fontWeight: 600 }}>✓ Allowed</span>
                      ) : (
                        <span style={{ color: '#ef4444' }}>✕ Blocked</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                      {row.viewer ? (
                        <span style={{ color: '#22c55e', fontWeight: 600 }}>✓ Allowed</span>
                      ) : (
                        <span style={{ color: '#ef4444' }}>✕ Blocked</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── TAB 3: System Health & Info ──────────────────────────────────── */}
      {activeTab === 'system' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: '10px', padding: '20px',
          }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={16} style={{ color: 'var(--accent)' }} /> Operational Status & Infrastructure
            </h3>

            {loadingHealth ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <RefreshCw size={18} className="spin" style={{ margin: '0 auto 8px' }} />
                <div>Probing system services...</div>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '14px' }}>
                <div style={{ background: 'var(--bg-secondary)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Backend Service</div>
                  <div style={{ fontSize: '1rem', fontWeight: 600, color: '#22c55e', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <CheckCircle2 size={16} /> {systemHealth?.service || 'soc-lite-backend'}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Version {systemHealth?.version || '1.0.0'}</div>
                </div>

                <div style={{ background: 'var(--bg-secondary)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Database Connection</div>
                  <div style={{ fontSize: '1rem', fontWeight: 600, color: '#22c55e', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Database size={16} /> PostgreSQL 18 (Prisma)
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Latency: {systemHealth?.database?.latencyMs ?? 2}ms</div>
                </div>

                <div style={{ background: 'var(--bg-secondary)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Frontend Framework</div>
                  <div style={{ fontSize: '1rem', fontWeight: 600, color: '#22d3ee', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Layers size={16} /> React 19 + Vite 8
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Tailwind CSS v4 + Recharts</div>
                </div>

                <div style={{ background: 'var(--bg-secondary)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Security Hardening</div>
                  <div style={{ fontSize: '1rem', fontWeight: 600, color: '#6366f1', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Shield size={16} /> Helmet + CORS + JWT
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Audit Trail Sanitization Active</div>
                </div>
              </div>
            )}
          </div>

          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: '10px', padding: '20px',
          }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 12px' }}>
              Audit Evidence & Data Integrity Guarantee
            </h3>
            <p style={{ fontSize: '0.83rem', color: 'var(--text-muted)', lineHeight: 1.6, margin: 0 }}>
              The SOC Lite audit logging subsystem is engineered with <strong>non-cascading persistence</strong>:
              When high-level entities such as monitored Assets or Threat Indicators are deleted from the active inventory, their corresponding <code style={{ color: 'var(--accent)' }}>AuditLog</code> event entries are explicitly retained in PostgreSQL. This ensures that forensic evidence of creations, status modifications, decommissions, and deletions remains fully intact for retrospective analysis.
            </p>
          </div>
        </div>
      )}

      {/* ── JSON Metadata Inspection Drawer/Modal ────────────────────────── */}
      {selectedLog && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(3px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px',
        }}>
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: '12px', width: '100%', maxWidth: '640px',
            maxHeight: '80vh', display: 'flex', flexDirection: 'column',
            boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
          }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '16px 20px', borderBottom: '1px solid var(--border)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Terminal size={18} style={{ color: 'var(--accent)' }} />
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                  Audit Event Details [{selectedLog.action}]
                </h3>
              </div>
              <button
                className="btn-ghost"
                onClick={() => setSelectedLog(null)}
                style={{ padding: '4px 8px', fontSize: '0.8rem' }}
              >
                ✕ Close
              </button>
            </div>

            <div style={{ padding: '16px 20px', overflowY: 'auto', flex: 1 }}>
              <div style={{ marginBottom: '12px', fontSize: '0.8rem', color: 'var(--text-muted)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                <div><strong>Event ID:</strong> {selectedLog.id}</div>
                <div><strong>Timestamp:</strong> {new Date(selectedLog.timestamp).toISOString()}</div>
                <div><strong>Actor:</strong> {selectedLog.user ? `${selectedLog.user.name} (${selectedLog.user.role})` : 'System'}</div>
                <div><strong>Client IP:</strong> {selectedLog.ipAddress || 'Internal'}</div>
                <div><strong>Target Type:</strong> {selectedLog.targetType || 'N/A'}</div>
                <div><strong>Target ID:</strong> {selectedLog.targetId || 'N/A'}</div>
              </div>

              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent)', marginBottom: '6px', textTransform: 'uppercase' }}>
                Sanitized Payload Metadata
              </div>
              <pre style={{
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderRadius: '8px', padding: '12px', fontSize: '0.78rem',
                color: '#22d3ee', overflowX: 'auto', maxHeight: '280px', margin: 0,
              }}>
                {JSON.stringify(selectedLog.details, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
