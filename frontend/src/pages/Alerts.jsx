// src/pages/Alerts.jsx
// Alert Management UI for SOC Lite (Phase 5 Step 3).
// Provides live alert statistics, multi-criteria filtering, paginated list,
// detailed evidence drawer, and RBAC-governed status lifecycle workflows.

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  BellDot,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Clock,
  Eye,
  Check,
  X,
  Lock,
  ChevronLeft,
  ChevronRight,
  Shield,
  FileCode,
  Copy,
  Terminal,
  RotateCcw,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import {
  getAlertsApi,
  getAlertStatsApi,
  getAlertByIdApi,
  updateAlertStatusApi,
} from '../api/alerts.api';
import { getRulesApi } from '../api/rules.api';

// ── Helpers ──────────────────────────────────────────────────────────────────

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
    case 'OPEN':
      return {
        background: 'rgba(255, 59, 59, 0.12)',
        color: 'var(--color-critical)',
        border: '1px solid rgba(255, 59, 59, 0.3)',
      };
    case 'ACKNOWLEDGED':
      return {
        background: 'rgba(91, 155, 213, 0.15)',
        color: 'var(--color-info)',
        border: '1px solid rgba(91, 155, 213, 0.3)',
      };
    case 'CLOSED':
      return {
        background: 'rgba(139, 175, 201, 0.12)',
        color: 'var(--color-text-secondary)',
        border: '1px solid var(--color-border)',
      };
    default:
      return {
        background: 'var(--color-bg-surface)',
        color: 'var(--color-text-muted)',
        border: '1px solid var(--color-border)',
      };
  }
}

function formatDateTime(dateStr) {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return dateStr;
  }
}

export default function Alerts() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'ADMIN';
  const isAnalyst = user?.role === 'ANALYST';
  const canModifyStatus = isAdmin || isAnalyst;
  const isViewer = user?.role === 'VIEWER';

  // ── Alerts & Stats State ───────────────────────────────────────────────────
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    byStatus: { OPEN: 0, ACKNOWLEDGED: 0, CLOSED: 0 },
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  });
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  const [availableRules, setAvailableRules] = useState([]);

  // Loading & error states
  const [tableLoading, setTableLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [pageError, setPageError] = useState('');
  const [successToast, setSuccessToast] = useState('');

  // ── Filters & Search ───────────────────────────────────────────────────────
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [ruleFilter, setRuleFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  // Debounce search input by 300ms
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchQuery.trim());
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Request counter to avoid stale responses overwriting newer ones
  const latestRequestRef = useRef(0);

  // ── Detail Drawer State ────────────────────────────────────────────────────
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [detailAlert, setDetailAlert] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [copiedLogId, setCopiedLogId] = useState(null);

  // ── Status Transition Modal State ──────────────────────────────────────────
  const [transitionModal, setTransitionModal] = useState({
    isOpen: false,
    alert: null,
    targetStatus: null, // 'ACKNOWLEDGED' | 'CLOSED'
  });
  const [transitionSubmitting, setTransitionSubmitting] = useState(false);
  const [transitionError, setTransitionError] = useState('');

  // Auto-dismiss success toast after 4s
  useEffect(() => {
    if (!successToast) return;
    const timer = setTimeout(() => setSuccessToast(''), 4000);
    return () => clearTimeout(timer);
  }, [successToast]);

  // ── 1. Fetch Stats ─────────────────────────────────────────────────────────
  const fetchStats = useCallback(async () => {
    await Promise.resolve();
    try {
      setStatsLoading(true);
      const res = await getAlertStatsApi();
      if (res?.success && res.data) {
        setStats(res.data);
      }
    } catch {
      // Non-fatal if stats fail to refresh
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // ── 2. Fetch Available Detection Rules (for filter dropdown) ───────────────
  const fetchRules = useCallback(async () => {
    await Promise.resolve();
    try {
      const res = await getRulesApi();
      if (res?.success && Array.isArray(res.data)) {
        setAvailableRules(res.data);
      }
    } catch {
      // Non-fatal
    }
  }, []);

  // ── 3. Fetch Alerts List ───────────────────────────────────────────────────
  const fetchAlerts = useCallback(async (page = 1) => {
    await Promise.resolve();
    const reqId = ++latestRequestRef.current;
    setTableLoading(true);
    setPageError('');

    try {
      const params = {
        page,
        limit: pagination.limit || 20,
        ...(statusFilter && { status: statusFilter }),
        ...(severityFilter && { severity: severityFilter }),
        ...(ruleFilter && { ruleId: ruleFilter }),
        ...(debouncedSearch && { search: debouncedSearch }),
        ...(startDate && { startDate: new Date(startDate).toISOString() }),
        ...(endDate && { endDate: new Date(endDate).toISOString() }),
      };

      const res = await getAlertsApi(params);

      // Guard against out-of-order responses
      if (reqId === latestRequestRef.current && res?.success) {
        setAlerts(res.data || []);
        if (res.pagination) {
          setPagination(res.pagination);
        }
      }
    } catch (err) {
      if (reqId === latestRequestRef.current) {
        setPageError(err.response?.data?.error || err.message || 'Failed to load security alerts.');
      }
    } finally {
      if (reqId === latestRequestRef.current) {
        setTableLoading(false);
      }
    }
  }, [statusFilter, severityFilter, ruleFilter, debouncedSearch, startDate, endDate, pagination.limit]);

  // Initial load
  useEffect(() => {
    let isMounted = true;
    async function loadInitial() {
      await Promise.resolve();
      if (isMounted) {
        fetchStats();
        fetchRules();
      }
    }
    loadInitial();
    return () => { isMounted = false; };
  }, [fetchStats, fetchRules]);

  // Refetch alerts whenever filters or search query change
  useEffect(() => {
    let isMounted = true;
    async function loadFiltered() {
      await Promise.resolve();
      if (isMounted) {
        fetchAlerts(1);
      }
    }
    loadFiltered();
    return () => { isMounted = false; };
  }, [fetchAlerts]);

  // ── 4. Fetch Single Alert Details (Drawer) ──────────────────────────────────
  const openDetailDrawer = useCallback(async (id) => {
    setSelectedAlertId(id);
    setDetailLoading(true);
    setDetailError('');
    setDetailAlert(null);

    try {
      const res = await getAlertByIdApi(id);
      if (res?.success && res.data) {
        setDetailAlert(res.data);
      } else {
        setDetailError('Unable to load alert details.');
      }
    } catch (err) {
      setDetailError(err.response?.data?.error || err.message || 'Failed to load alert details.');
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeDetailDrawer = () => {
    setSelectedAlertId(null);
    setDetailAlert(null);
    setDetailError('');
  };

  // ── 5. Status Transition Handler ───────────────────────────────────────────
  const openTransitionConfirm = (alert, targetStatus) => {
    if (!canModifyStatus) return;
    setTransitionModal({
      isOpen: true,
      alert,
      targetStatus,
    });
    setTransitionError('');
  };

  const closeTransitionConfirm = () => {
    setTransitionModal({ isOpen: false, alert: null, targetStatus: null });
    setTransitionError('');
    setTransitionSubmitting(false);
  };

  const handleExecuteStatusTransition = async () => {
    const { alert, targetStatus } = transitionModal;
    if (!alert || !targetStatus || !canModifyStatus) return;

    setTransitionSubmitting(true);
    setTransitionError('');

    try {
      const res = await updateAlertStatusApi(alert.id, targetStatus);
      if (res?.success) {
        const actionText = targetStatus === 'ACKNOWLEDGED' ? 'acknowledged' : 'closed';
        setSuccessToast(`Alert successfully ${actionText}.`);
        closeTransitionConfirm();

        // Refresh lists and stats
        fetchAlerts(pagination.page);
        fetchStats();

        // If drawer is currently open on this alert, refresh its detail
        if (selectedAlertId === alert.id) {
          openDetailDrawer(alert.id);
        }
      } else {
        setTransitionError(res?.error || 'Failed to update alert status.');
      }
    } catch (err) {
      setTransitionError(err.response?.data?.error || err.message || 'Status transition rejected.');
    } finally {
      setTransitionSubmitting(false);
    }
  };

  // ── 6. Copy Raw Log Content ────────────────────────────────────────────────
  const handleCopyRawLog = (logId, content) => {
    if (!content) return;
    navigator.clipboard.writeText(content);
    setCopiedLogId(logId);
    setTimeout(() => setCopiedLogId(null), 2000);
  };

  // Clear all filters helper
  const handleResetFilters = () => {
    setSearchQuery('');
    setDebouncedSearch('');
    setStatusFilter('');
    setSeverityFilter('');
    setRuleFilter('');
    setStartDate('');
    setEndDate('');
  };

  const hasActiveFilters = Boolean(
    debouncedSearch || statusFilter || severityFilter || ruleFilter || startDate || endDate
  );

  const highCriticalTotal = (stats.bySeverity.CRITICAL || 0) + (stats.bySeverity.HIGH || 0);

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* ── Success Toast Notification ─────────────────────────────────────── */}
      {successToast && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: 'fixed',
            top: '1.5rem',
            right: '1.5rem',
            zIndex: 9999,
            backgroundColor: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-accent)',
            borderRadius: 'var(--radius-card)',
            padding: '0.85rem 1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.65rem',
            boxShadow: 'var(--shadow-glow)',
            color: 'var(--color-text-primary)',
            fontSize: '13px',
          }}
          className="fade-in"
        >
          <CheckCircle2 size={16} color="var(--color-accent)" />
          <span>{successToast}</span>
          <button
            onClick={() => setSuccessToast('')}
            aria-label="Close notification"
            style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', marginLeft: '0.5rem' }}
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ── Header Bar ─────────────────────────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
              Security Alerts
            </h1>
            <span
              style={{
                fontSize: '11px',
                fontWeight: 600,
                textTransform: 'uppercase',
                padding: '0.2rem 0.55rem',
                borderRadius: '999px',
                backgroundColor: isViewer ? 'rgba(91, 155, 213, 0.12)' : 'rgba(0, 212, 170, 0.12)',
                color: isViewer ? 'var(--color-info)' : 'var(--color-accent)',
                border: isViewer ? '1px solid rgba(91, 155, 213, 0.25)' : '1px solid rgba(0, 212, 170, 0.25)',
              }}
            >
              {isViewer ? 'Read-Only (Viewer)' : 'Triage Enabled'}
            </span>
          </div>
          <p style={{ margin: '0.35rem 0 0', fontSize: '13px', color: 'var(--color-text-secondary)' }}>
            Monitor, triage, and investigate threat detection alerts generated across your environment.
          </p>
        </div>

        {/* Global Refresh Button */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            onClick={() => {
              fetchAlerts(pagination.page);
              fetchStats();
            }}
            disabled={tableLoading}
            className="btn btn-ghost"
            style={{ fontSize: '12.5px', padding: '0.45rem 0.85rem' }}
          >
            <RefreshCw size={14} className={tableLoading ? 'pulse' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* ── Live Metric Summary Cards ──────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '1rem',
        }}
      >
        {/* Total Alerts Card */}
        <div
          className="card"
          style={{
            padding: '1rem 1.15rem',
            cursor: 'pointer',
            borderColor: statusFilter === '' ? 'var(--color-accent)' : 'var(--color-border)',
            transition: 'border-color 0.2s',
          }}
          onClick={() => setStatusFilter('')}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
              Total Alerts
            </span>
            <BellDot size={16} color="var(--color-accent)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            {statsLoading ? '—' : stats.total}
          </div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            All recorded threats
          </div>
        </div>

        {/* Open Alerts Card */}
        <div
          className="card"
          style={{
            padding: '1rem 1.15rem',
            cursor: 'pointer',
            borderColor: statusFilter === 'OPEN' ? 'var(--color-critical)' : 'var(--color-border)',
            transition: 'border-color 0.2s',
          }}
          onClick={() => setStatusFilter(statusFilter === 'OPEN' ? '' : 'OPEN')}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-critical)', textTransform: 'uppercase' }}>
              Open / Untriaged
            </span>
            <AlertCircle size={16} color="var(--color-critical)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-critical)' }}>
            {statsLoading ? '—' : stats.byStatus.OPEN || 0}
          </div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Requires immediate review
          </div>
        </div>

        {/* Acknowledged Card */}
        <div
          className="card"
          style={{
            padding: '1rem 1.15rem',
            cursor: 'pointer',
            borderColor: statusFilter === 'ACKNOWLEDGED' ? 'var(--color-info)' : 'var(--color-border)',
            transition: 'border-color 0.2s',
          }}
          onClick={() => setStatusFilter(statusFilter === 'ACKNOWLEDGED' ? '' : 'ACKNOWLEDGED')}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-info)', textTransform: 'uppercase' }}>
              Acknowledged
            </span>
            <Clock size={16} color="var(--color-info)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-info)' }}>
            {statsLoading ? '—' : stats.byStatus.ACKNOWLEDGED || 0}
          </div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Under active investigation
          </div>
        </div>

        {/* Closed Card */}
        <div
          className="card"
          style={{
            padding: '1rem 1.15rem',
            cursor: 'pointer',
            borderColor: statusFilter === 'CLOSED' ? 'var(--color-text-secondary)' : 'var(--color-border)',
            transition: 'border-color 0.2s',
          }}
          onClick={() => setStatusFilter(statusFilter === 'CLOSED' ? '' : 'CLOSED')}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
              Closed
            </span>
            <CheckCircle2 size={16} color="var(--color-accent-dim)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-text-secondary)' }}>
            {statsLoading ? '—' : stats.byStatus.CLOSED || 0}
          </div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Resolved or dismissed
          </div>
        </div>

        {/* High / Critical Severity Card */}
        <div
          className="card"
          style={{
            padding: '1rem 1.15rem',
            cursor: 'pointer',
            borderColor: severityFilter === 'CRITICAL' ? 'var(--color-high)' : 'var(--color-border)',
            transition: 'border-color 0.2s',
          }}
          onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? '' : 'CRITICAL')}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-high)', textTransform: 'uppercase' }}>
              High & Critical
            </span>
            <AlertTriangle size={16} color="var(--color-high)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-high)' }}>
            {statsLoading ? '—' : highCriticalTotal}
          </div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Critical threats prioritized
          </div>
        </div>
      </div>

      {/* ── Search & Filter Controls Bar ───────────────────────────────────── */}
      <div
        className="card"
        style={{
          padding: '1rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.85rem',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          {/* Status Segmented Tabs */}
          <div
            style={{
              display: 'flex',
              backgroundColor: 'var(--color-bg-base)',
              padding: '0.25rem',
              borderRadius: '6px',
              border: '1px solid var(--color-border)',
              gap: '0.2rem',
            }}
          >
            {[
              { id: '', label: 'All' },
              { id: 'OPEN', label: 'Open' },
              { id: 'ACKNOWLEDGED', label: 'Acknowledged' },
              { id: 'CLOSED', label: 'Closed' },
            ].map((tab) => {
              const active = statusFilter === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setStatusFilter(tab.id)}
                  style={{
                    padding: '0.35rem 0.75rem',
                    fontSize: '12px',
                    fontWeight: active ? 600 : 500,
                    borderRadius: '4px',
                    border: 'none',
                    cursor: 'pointer',
                    background: active ? 'var(--color-bg-elevated)' : 'transparent',
                    color: active ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                    boxShadow: active ? '0 1px 4px rgba(0,0,0,0.3)' : 'none',
                    transition: 'all 0.15s ease',
                  }}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Quick Active Filters Reset */}
          {hasActiveFilters && (
            <button
              onClick={handleResetFilters}
              className="btn btn-ghost"
              style={{ fontSize: '11.5px', padding: '0.35rem 0.65rem', color: 'var(--color-text-muted)' }}
            >
              <RotateCcw size={12} />
              <span>Reset Filters</span>
            </button>
          )}
        </div>

        {/* Filter Inputs Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '0.75rem',
            alignItems: 'center',
          }}
        >
          {/* Search Input */}
          <div style={{ position: 'relative' }}>
            <Search
              size={14}
              style={{
                position: 'absolute',
                left: '0.75rem',
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--color-text-muted)',
              }}
            />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search alert title or description…"
              style={{
                width: '100%',
                padding: '0.45rem 2rem 0.45rem 2.2rem',
                backgroundColor: 'var(--color-bg-surface)',
                border: '1px solid var(--color-border)',
                borderRadius: '6px',
                color: 'var(--color-text-primary)',
                fontSize: '12.5px',
                outline: 'none',
              }}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                aria-label="Clear search"
                style={{
                  position: 'absolute',
                  right: '0.65rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: 'var(--color-text-muted)',
                  cursor: 'pointer',
                }}
              >
                <X size={13} />
              </button>
            )}
          </div>

          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              padding: '0.45rem 0.75rem',
              backgroundColor: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              color: 'var(--color-text-primary)',
              fontSize: '12.5px',
              outline: 'none',
            }}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Rule Dropdown */}
          <select
            value={ruleFilter}
            onChange={(e) => setRuleFilter(e.target.value)}
            style={{
              padding: '0.45rem 0.75rem',
              backgroundColor: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              color: 'var(--color-text-primary)',
              fontSize: '12.5px',
              outline: 'none',
            }}
          >
            <option value="">All Detection Rules</option>
            {availableRules.map((rule) => (
              <option key={rule.id} value={rule.id}>
                {rule.name}
              </option>
            ))}
          </select>

          {/* Start Date */}
          <input
            type="datetime-local"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            title="Filter alerts fired on or after"
            style={{
              padding: '0.45rem 0.65rem',
              backgroundColor: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              color: 'var(--color-text-primary)',
              fontSize: '12px',
              outline: 'none',
            }}
          />

          {/* End Date */}
          <input
            type="datetime-local"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            title="Filter alerts fired on or before"
            style={{
              padding: '0.45rem 0.65rem',
              backgroundColor: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              color: 'var(--color-text-primary)',
              fontSize: '12px',
              outline: 'none',
            }}
          />
        </div>
      </div>

      {/* ── Inline Error Alert (if fetch failed) ────────────────────────────── */}
      {pageError && (
        <div
          style={{
            padding: '0.85rem 1.15rem',
            backgroundColor: 'rgba(255, 59, 59, 0.1)',
            border: '1px solid rgba(255, 59, 59, 0.3)',
            borderRadius: 'var(--radius-card)',
            color: 'var(--color-critical)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '13px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <AlertCircle size={16} />
            <span>{pageError}</span>
          </div>
          <button
            onClick={() => fetchAlerts(pagination.page)}
            className="btn btn-ghost"
            style={{ fontSize: '12px', padding: '0.3rem 0.6rem' }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Alerts Table Card ──────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr
                style={{
                  backgroundColor: 'var(--color-bg-surface)',
                  borderBottom: '1px solid var(--color-border)',
                  color: 'var(--color-text-muted)',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                }}
              >
                <th style={{ padding: '0.85rem 1rem', width: '110px' }}>Severity</th>
                <th style={{ padding: '0.85rem 1rem' }}>Alert Title & Description</th>
                <th style={{ padding: '0.85rem 1rem', width: '200px' }}>Detection Rule</th>
                <th style={{ padding: '0.85rem 1rem', width: '130px' }}>Status</th>
                <th style={{ padding: '0.85rem 1rem', width: '160px' }}>Fired Time</th>
                <th style={{ padding: '0.85rem 1rem', width: '90px' }}>Evidence</th>
                <th style={{ padding: '0.85rem 1rem', width: '180px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tableLoading ? (
                /* Loading Skeleton Rows */
                Array.from({ length: 5 }).map((_, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
                    <td colSpan={7} style={{ padding: '1.25rem 1rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                      <span className="pulse" style={{ display: 'inline-block', width: '100%', height: '18px', backgroundColor: 'var(--color-bg-elevated)', borderRadius: '4px' }} />
                    </td>
                  </tr>
                ))
              ) : alerts.length === 0 ? (
                /* Empty State */
                <tr>
                  <td colSpan={7} style={{ padding: '3.5rem 1rem', textAlign: 'center' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem' }}>
                      <div
                        style={{
                          width: '48px',
                          height: '48px',
                          borderRadius: '50%',
                          backgroundColor: 'var(--color-bg-elevated)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: 'var(--color-text-muted)',
                        }}
                      >
                        <Shield size={22} />
                      </div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
                        No Security Alerts Found
                      </div>
                      <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--color-text-muted)', maxWidth: '380px' }}>
                        {hasActiveFilters
                          ? 'No alerts match your active filter criteria. Try adjusting your search query or resetting filters.'
                          : 'The detection engine has not recorded any security alerts yet.'}
                      </p>
                      {hasActiveFilters && (
                        <button
                          onClick={handleResetFilters}
                          className="btn btn-ghost"
                          style={{ marginTop: '0.5rem', fontSize: '12px' }}
                        >
                          Clear Active Filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                /* Real Alert Rows */
                alerts.map((alert) => {
                  const statusStyle = getStatusBadgeClass(alert.status);
                  const isAck = alert.status === 'ACKNOWLEDGED';
                  const isClosed = alert.status === 'CLOSED';

                  return (
                    <tr
                      key={alert.id}
                      style={{
                        borderBottom: '1px solid var(--color-border-subtle)',
                        backgroundColor: selectedAlertId === alert.id ? 'var(--color-bg-elevated)' : 'transparent',
                        transition: 'background-color 0.15s ease',
                      }}
                      onMouseEnter={(e) => {
                        if (selectedAlertId !== alert.id) e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.02)';
                      }}
                      onMouseLeave={(e) => {
                        if (selectedAlertId !== alert.id) e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      {/* Severity Badge */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>

                      {/* Title & Description */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <div
                          style={{
                            fontWeight: 600,
                            color: 'var(--color-text-primary)',
                            marginBottom: '0.15rem',
                            cursor: 'pointer',
                          }}
                          onClick={() => openDetailDrawer(alert.id)}
                        >
                          {alert.title}
                        </div>
                        {alert.description && (
                          <div
                            style={{
                              fontSize: '11.5px',
                              color: 'var(--color-text-muted)',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              maxWidth: '480px',
                            }}
                            title={alert.description}
                          >
                            {alert.description}
                          </div>
                        )}
                      </td>

                      {/* Detection Rule */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                            fontSize: '12px',
                            color: 'var(--color-text-secondary)',
                          }}
                        >
                          <Shield size={13} color="var(--color-accent-dim)" />
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '170px' }}>
                            {alert.rule?.name || 'Manual / Custom'}
                          </span>
                        </span>
                      </td>

                      {/* Status Badge */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                            padding: '0.2rem 0.55rem',
                            borderRadius: 'var(--radius-badge)',
                            fontSize: '11px',
                            fontWeight: 600,
                            ...statusStyle,
                          }}
                        >
                          <span
                            className={alert.status === 'OPEN' ? 'status-dot offline pulse' : 'status-dot'}
                            style={{
                              backgroundColor:
                                alert.status === 'OPEN'
                                  ? 'var(--color-critical)'
                                  : alert.status === 'ACKNOWLEDGED'
                                  ? 'var(--color-info)'
                                  : 'var(--color-text-muted)',
                            }}
                          />
                          {alert.status}
                        </span>
                      </td>

                      {/* Fired Time */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle', color: 'var(--color-text-secondary)', fontSize: '12px' }}>
                        {formatDateTime(alert.firedAt)}
                      </td>

                      {/* Evidence Count */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <span
                          style={{
                            fontSize: '11.5px',
                            padding: '0.15rem 0.45rem',
                            borderRadius: '4px',
                            backgroundColor: 'var(--color-bg-base)',
                            border: '1px solid var(--color-border)',
                            color: 'var(--color-text-secondary)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                          }}
                        >
                          <FileCode size={12} color="var(--color-text-muted)" />
                          {alert.evidenceCount ?? 0}
                        </span>
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                          {/* Inspect Detail Button */}
                          <button
                            onClick={() => openDetailDrawer(alert.id)}
                            className="btn btn-ghost"
                            title="Inspect Alert Details & Evidence"
                            style={{ padding: '0.35rem 0.6rem', fontSize: '12px' }}
                          >
                            <Eye size={13} />
                            <span>Inspect</span>
                          </button>

                          {/* Acknowledge Button */}
                          {!isClosed && !isAck && (
                            <button
                              onClick={() => openTransitionConfirm(alert, 'ACKNOWLEDGED')}
                              disabled={!canModifyStatus}
                              className="btn btn-ghost"
                              title={
                                canModifyStatus
                                  ? 'Mark as Acknowledged'
                                  : 'Viewer role cannot modify alert status'
                              }
                              style={{
                                padding: '0.35rem 0.6rem',
                                fontSize: '12px',
                                color: canModifyStatus ? 'var(--color-info)' : 'var(--color-text-muted)',
                                borderColor: canModifyStatus ? 'rgba(91, 155, 213, 0.4)' : 'var(--color-border)',
                                cursor: canModifyStatus ? 'pointer' : 'not-allowed',
                                opacity: canModifyStatus ? 1 : 0.6,
                              }}
                            >
                              {canModifyStatus ? <Check size={13} /> : <Lock size={12} />}
                              <span>Ack</span>
                            </button>
                          )}

                          {/* Close Button */}
                          {!isClosed && (
                            <button
                              onClick={() => openTransitionConfirm(alert, 'CLOSED')}
                              disabled={!canModifyStatus}
                              className="btn btn-ghost"
                              title={
                                canModifyStatus
                                  ? 'Close Alert'
                                  : 'Viewer role cannot modify alert status'
                              }
                              style={{
                                padding: '0.35rem 0.6rem',
                                fontSize: '12px',
                                color: canModifyStatus ? 'var(--color-text-secondary)' : 'var(--color-text-muted)',
                                cursor: canModifyStatus ? 'pointer' : 'not-allowed',
                                opacity: canModifyStatus ? 1 : 0.6,
                              }}
                            >
                              {canModifyStatus ? <X size={13} /> : <Lock size={12} />}
                              <span>Close</span>
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* ── Table Pagination Footer ────────────────────────────────────────── */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.85rem 1.25rem',
            borderTop: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-bg-surface)',
            fontSize: '12px',
            color: 'var(--color-text-secondary)',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}
        >
          <div>
            Showing{' '}
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
              {alerts.length > 0 ? (pagination.page - 1) * pagination.limit + 1 : 0}
            </span>{' '}
            to{' '}
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
              {Math.min(pagination.page * pagination.limit, pagination.total)}
            </span>{' '}
            of{' '}
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
              {pagination.total}
            </span>{' '}
            alerts
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              onClick={() => fetchAlerts(pagination.page - 1)}
              disabled={pagination.page <= 1 || tableLoading}
              className="btn btn-ghost"
              style={{ padding: '0.35rem 0.65rem', fontSize: '12px' }}
            >
              <ChevronLeft size={14} />
              <span>Previous</span>
            </button>
            <span style={{ padding: '0 0.4rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Page {pagination.page} of {pagination.totalPages || 1}
            </span>
            <button
              onClick={() => fetchAlerts(pagination.page + 1)}
              disabled={pagination.page >= pagination.totalPages || tableLoading}
              className="btn btn-ghost"
              style={{ padding: '0.35rem 0.65rem', fontSize: '12px' }}
            >
              <span>Next</span>
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* ── Slide-Over Detail Drawer ───────────────────────────────────────── */}
      {selectedAlertId && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1000,
            display: 'flex',
            justifyContent: 'flex-end',
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            backdropFilter: 'blur(3px)',
          }}
          onClick={closeDetailDrawer}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '680px',
              height: '100%',
              backgroundColor: 'var(--color-bg-surface)',
              borderLeft: '1px solid var(--color-border)',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: 'var(--shadow-card)',
            }}
            onClick={(e) => e.stopPropagation()}
            className="fade-in"
          >
            {/* Drawer Header */}
            <div
              style={{
                padding: '1.25rem 1.5rem',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: '1rem',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                  {detailAlert && (
                    <span className={`badge ${getSeverityBadgeClass(detailAlert.severity)}`}>
                      {detailAlert.severity}
                    </span>
                  )}
                  {detailAlert && (
                    <span
                      style={{
                        padding: '0.15rem 0.5rem',
                        borderRadius: 'var(--radius-badge)',
                        fontSize: '11px',
                        fontWeight: 600,
                        ...getStatusBadgeClass(detailAlert.status),
                      }}
                    >
                      {detailAlert.status}
                    </span>
                  )}
                  <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                    Fired: {formatDateTime(detailAlert?.firedAt)}
                  </span>
                </div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
                  {detailAlert?.title || 'Alert Details'}
                </h2>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {/* Transition Actions directly inside Drawer Header */}
                {detailAlert && detailAlert.status === 'OPEN' && canModifyStatus && (
                  <button
                    onClick={() => openTransitionConfirm(detailAlert, 'ACKNOWLEDGED')}
                    className="btn btn-ghost"
                    style={{ fontSize: '12px', padding: '0.35rem 0.75rem', color: 'var(--color-info)', borderColor: 'rgba(91, 155, 213, 0.4)' }}
                  >
                    <Check size={13} />
                    <span>Acknowledge</span>
                  </button>
                )}
                {detailAlert && detailAlert.status !== 'CLOSED' && canModifyStatus && (
                  <button
                    onClick={() => openTransitionConfirm(detailAlert, 'CLOSED')}
                    className="btn btn-ghost"
                    style={{ fontSize: '12px', padding: '0.35rem 0.75rem' }}
                  >
                    <X size={13} />
                    <span>Close Alert</span>
                  </button>
                )}
                <button
                  onClick={closeDetailDrawer}
                  className="btn btn-ghost"
                  aria-label="Close drawer"
                  style={{ padding: '0.4rem' }}
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Drawer Body Content */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {detailLoading ? (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                  <RefreshCw size={24} className="pulse" />
                  <p style={{ marginTop: '0.75rem', fontSize: '13px' }}>Loading full alert evidence chain…</p>
                </div>
              ) : detailError ? (
                <div style={{ padding: '1.25rem', backgroundColor: 'rgba(255, 59, 59, 0.1)', color: 'var(--color-critical)', borderRadius: '6px' }}>
                  {detailError}
                </div>
              ) : detailAlert ? (
                <>
                  {/* Alert Description */}
                  <div className="card" style={{ padding: '1rem' }}>
                    <div className="card-title">Alert Overview</div>
                    <p style={{ margin: 0, fontSize: '13px', color: 'var(--color-text-primary)', lineHeight: 1.5 }}>
                      {detailAlert.description}
                    </p>

                    {/* Acknowledgement Metadata if present */}
                    {detailAlert.acknowledgedAt && (
                      <div
                        style={{
                          marginTop: '0.85rem',
                          padding: '0.65rem 0.85rem',
                          backgroundColor: 'var(--color-bg-base)',
                          borderRadius: '6px',
                          border: '1px solid var(--color-border)',
                          fontSize: '12px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                        }}
                      >
                        <Clock size={14} color="var(--color-info)" />
                        <span>
                          Acknowledged by{' '}
                          <strong style={{ color: 'var(--color-text-primary)' }}>
                            {detailAlert.acknowledgedBy || 'Analyst'}
                          </strong>{' '}
                          on {formatDateTime(detailAlert.acknowledgedAt)}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Detection Rule Specification Card */}
                  <div className="card" style={{ padding: '1rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
                      <div className="card-title" style={{ margin: 0 }}>Triggering Detection Rule</div>
                      {detailAlert.rule && (
                        <span className={`badge ${getSeverityBadgeClass(detailAlert.rule.severity)}`}>
                          Rule Severity: {detailAlert.rule.severity}
                        </span>
                      )}
                    </div>

                    {detailAlert.rule ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '12.5px' }}>
                        <div>
                          <strong style={{ color: 'var(--color-text-primary)' }}>{detailAlert.rule.name}</strong>
                          <span style={{ color: 'var(--color-text-muted)', marginLeft: '0.5rem' }}>
                            ({detailAlert.rule.type})
                          </span>
                        </div>
                        {detailAlert.rule.description && (
                          <div style={{ color: 'var(--color-text-secondary)', fontSize: '12px' }}>
                            {detailAlert.rule.description}
                          </div>
                        )}
                        {detailAlert.rule.config && (
                          <div
                            style={{
                              marginTop: '0.4rem',
                              backgroundColor: 'var(--color-bg-base)',
                              padding: '0.5rem 0.75rem',
                              borderRadius: '4px',
                              border: '1px solid var(--color-border)',
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              color: 'var(--color-accent)',
                            }}
                          >
                            Config: {JSON.stringify(detailAlert.rule.config, null, 2)}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div style={{ color: 'var(--color-text-muted)', fontSize: '12px' }}>
                        Rule details unavailable (ad-hoc or custom alert).
                      </div>
                    )}
                  </div>

                  {/* Linked Evidence Section */}
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        Linked Evidence ({detailAlert.evidenceCount ?? detailAlert.evidence?.length ?? 0} Events)
                      </div>
                    </div>

                    {!detailAlert.evidence || detailAlert.evidence.length === 0 ? (
                      <div className="card" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '12.5px' }}>
                        No direct event records linked to this alert.
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                        {detailAlert.evidence.map((item, index) => {
                          const ev = item.event;
                          if (!ev) return null;

                          return (
                            <div
                              key={item.eventId || index}
                              className="card"
                              style={{ padding: '1rem', backgroundColor: 'var(--color-bg-elevated)' }}
                            >
                              {/* Event Header */}
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-accent)' }}>
                                    {ev.eventType}
                                  </span>
                                  <span className={`badge ${getSeverityBadgeClass(ev.severity)}`} style={{ fontSize: '10px' }}>
                                    {ev.severity}
                                  </span>
                                </div>
                                <span style={{ fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
                                  {formatDateTime(ev.timestamp)}
                                </span>
                              </div>

                              {/* Normalized Fields Grid */}
                              <div
                                style={{
                                  display: 'grid',
                                  gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                                  gap: '0.5rem',
                                  padding: '0.5rem 0',
                                  borderTop: '1px solid var(--color-border-subtle)',
                                  borderBottom: '1px solid var(--color-border-subtle)',
                                  fontSize: '11.5px',
                                }}
                              >
                                {ev.srcIp && (
                                  <div>
                                    <span style={{ color: 'var(--color-text-muted)' }}>Src IP: </span>
                                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>{ev.srcIp}</span>
                                    {ev.srcPort ? `:${ev.srcPort}` : ''}
                                  </div>
                                )}
                                {ev.dstIp && (
                                  <div>
                                    <span style={{ color: 'var(--color-text-muted)' }}>Dst IP: </span>
                                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>{ev.dstIp}</span>
                                    {ev.dstPort ? `:${ev.dstPort}` : ''}
                                  </div>
                                )}
                                {ev.username && (
                                  <div>
                                    <span style={{ color: 'var(--color-text-muted)' }}>User: </span>
                                    <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{ev.username}</span>
                                  </div>
                                )}
                                {ev.hostname && (
                                  <div>
                                    <span style={{ color: 'var(--color-text-muted)' }}>Host: </span>
                                    <span style={{ color: 'var(--color-text-primary)' }}>{ev.hostname}</span>
                                  </div>
                                )}
                              </div>

                              {ev.message && (
                                <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', marginTop: '0.4rem' }}>
                                  {ev.message}
                                </div>
                              )}

                              {/* Originating Raw Log Payload (if available) */}
                              {ev.rawLog && ev.rawLog.rawContent && (
                                <div style={{ marginTop: '0.65rem' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                                    <span style={{ fontSize: '10.5px', textTransform: 'uppercase', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                                      <Terminal size={11} /> Source: {ev.rawLog.source || 'raw'}
                                    </span>
                                    <button
                                      onClick={() => handleCopyRawLog(ev.rawLog.id, ev.rawLog.rawContent)}
                                      style={{
                                        background: 'none',
                                        border: 'none',
                                        color: copiedLogId === ev.rawLog.id ? 'var(--color-accent)' : 'var(--color-text-muted)',
                                        fontSize: '10.5px',
                                        cursor: 'pointer',
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        gap: '0.25rem',
                                      }}
                                    >
                                      {copiedLogId === ev.rawLog.id ? <Check size={11} /> : <Copy size={11} />}
                                      <span>{copiedLogId === ev.rawLog.id ? 'Copied' : 'Copy Payload'}</span>
                                    </button>
                                  </div>
                                  <pre
                                    style={{
                                      margin: 0,
                                      padding: '0.5rem 0.65rem',
                                      backgroundColor: 'var(--color-bg-base)',
                                      borderRadius: '4px',
                                      border: '1px solid var(--color-border)',
                                      fontFamily: 'var(--font-mono)',
                                      fontSize: '11px',
                                      color: 'var(--color-text-secondary)',
                                      overflowX: 'auto',
                                      whiteSpace: 'pre-wrap',
                                      wordBreak: 'break-all',
                                    }}
                                  >
                                    {ev.rawLog.rawContent}
                                  </pre>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* ── Status Transition Confirmation Modal ────────────────────────────── */}
      {transitionModal.isOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 2000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(3px)',
          }}
          onClick={closeTransitionConfirm}
        >
          <div
            className="card fade-in"
            style={{
              width: '100%',
              maxWidth: '460px',
              padding: '1.5rem',
              backgroundColor: 'var(--color-bg-surface)',
              border: '1px solid var(--color-border)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.85rem' }}>
              {transitionModal.targetStatus === 'ACKNOWLEDGED' ? (
                <div style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: 'rgba(91, 155, 213, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-info)' }}>
                  <Clock size={18} />
                </div>
              ) : (
                <div style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: 'rgba(255, 59, 59, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-critical)' }}>
                  <CheckCircle2 size={18} />
                </div>
              )}
              <div>
                <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                  {transitionModal.targetStatus === 'ACKNOWLEDGED' ? 'Acknowledge Security Alert' : 'Close Security Alert'}
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                  SOC Analyst Action Required
                </span>
              </div>
            </div>

            <p style={{ margin: '0 0 1rem', fontSize: '13px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              {transitionModal.targetStatus === 'ACKNOWLEDGED' ? (
                <>
                  Are you sure you want to mark alert{' '}
                  <strong style={{ color: 'var(--color-text-primary)' }}>"{transitionModal.alert?.title}"</strong>{' '}
                  as <strong style={{ color: 'var(--color-info)' }}>ACKNOWLEDGED</strong>? This will record your identity and begin active investigation.
                </>
              ) : (
                <>
                  Are you sure you want to transition alert{' '}
                  <strong style={{ color: 'var(--color-text-primary)' }}>"{transitionModal.alert?.title}"</strong>{' '}
                  to <strong style={{ color: 'var(--color-text-primary)' }}>CLOSED</strong>? This archives the alert and prevents duplicate alerts from re-triggering on this closed evidence.
                </>
              )}
            </p>

            {/* Error Message inside Dialog */}
            {transitionError && (
              <div
                style={{
                  marginBottom: '1rem',
                  padding: '0.65rem 0.85rem',
                  backgroundColor: 'rgba(255, 59, 59, 0.12)',
                  border: '1px solid rgba(255, 59, 59, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--color-critical)',
                  fontSize: '12px',
                }}
              >
                {transitionError}
              </div>
            )}

            {/* Modal Actions */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={closeTransitionConfirm}
                disabled={transitionSubmitting}
                className="btn btn-ghost"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteStatusTransition}
                disabled={transitionSubmitting}
                className="btn btn-primary"
                style={{
                  backgroundColor:
                    transitionModal.targetStatus === 'ACKNOWLEDGED'
                      ? 'var(--color-info)'
                      : 'var(--color-accent)',
                  color: '#000',
                }}
              >
                {transitionSubmitting ? 'Updating…' : `Confirm ${transitionModal.targetStatus === 'ACKNOWLEDGED' ? 'Acknowledge' : 'Close'}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
