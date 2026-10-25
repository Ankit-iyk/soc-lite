// src/pages/Incidents.jsx
// Incident Tracking UI for SOC Lite (Phase 6 Step 5).
// Full incident management: stats, filtering, CRUD, detail drawer,
// alert linking, investigation notes, and status lifecycle.

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  FolderOpen,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Clock,
  Eye,
  Plus,
  X,
  Lock,
  ChevronLeft,
  ChevronRight,
  Shield,
  Link2,
  Link2Off,
  MessageSquarePlus,
  RotateCcw,
  User,
  CalendarCheck,
  Activity,
  StickyNote,
  Pencil,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import {
  getIncidentsApi,
  getIncidentStatsApi,
  getIncidentByIdApi,
  createIncidentApi,
  updateIncidentApi,
  linkAlertsApi,
  unlinkAlertApi,
  addIncidentNoteApi,
} from '../api/incidents.api';
import { getAlertsApi } from '../api/alerts.api';

// ── Design helpers ─────────────────────────────────────────────────────────

function getSeverityBadgeClass(sev) {
  switch (sev) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH':     return 'badge-high';
    case 'MEDIUM':   return 'badge-medium';
    case 'LOW':      return 'badge-low';
    default:         return 'badge-info';
  }
}

function getStatusStyle(status) {
  switch (status) {
    case 'OPEN':
      return { background: 'rgba(255,59,59,0.12)', color: 'var(--color-critical)', border: '1px solid rgba(255,59,59,0.3)' };
    case 'INVESTIGATING':
      return { background: 'rgba(91,155,213,0.15)', color: 'var(--color-info)', border: '1px solid rgba(91,155,213,0.3)' };
    case 'RESOLVED':
      return { background: 'rgba(0,212,170,0.12)', color: 'var(--color-accent)', border: '1px solid rgba(0,212,170,0.3)' };
    case 'CLOSED':
      return { background: 'rgba(139,175,201,0.12)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border)' };
    default:
      return { background: 'var(--color-bg-surface)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' };
  }
}

function getStatusDotColor(status) {
  switch (status) {
    case 'OPEN':         return 'var(--color-critical)';
    case 'INVESTIGATING':return 'var(--color-info)';
    case 'RESOLVED':     return 'var(--color-accent)';
    case 'CLOSED':       return 'var(--color-text-muted)';
    default:             return 'var(--color-text-muted)';
  }
}

function getActionLabel(action) {
  const map = {
    INCIDENT_CREATE:       'Incident Created',
    INCIDENT_UPDATE:       'Incident Updated',
    INCIDENT_STATUS_CHANGE:'Status Changed',
    INCIDENT_ALERT_LINK:   'Alert(s) Linked',
    INCIDENT_ALERT_UNLINK: 'Alert Unlinked',
    INCIDENT_NOTE_ADD:     'Note Added',
  };
  return map[action] || action;
}

function getActionIcon(action) {
  if (action === 'INCIDENT_NOTE_ADD') return <StickyNote size={13} color="var(--color-accent-dim)" />;
  if (action === 'INCIDENT_STATUS_CHANGE') return <Activity size={13} color="var(--color-info)" />;
  if (action === 'INCIDENT_ALERT_LINK') return <Link2 size={13} color="var(--color-accent)" />;
  if (action === 'INCIDENT_ALERT_UNLINK') return <Link2Off size={13} color="var(--color-critical)" />;
  if (action === 'INCIDENT_CREATE') return <Plus size={13} color="var(--color-accent)" />;
  return <Pencil size={13} color="var(--color-text-muted)" />;
}

function formatDateTime(dateStr) {
  if (!dateStr) return '—';
  try {
    const d = new Date(dateStr);
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
      hour12: false,
    });
  } catch { return dateStr; }
}

function formatRelative(dateStr) {
  if (!dateStr) return '—';
  try {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1)  return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24)  return `${hrs}h ago`;
    return formatDateTime(dateStr);
  } catch { return dateStr; }
}

// Reusable inline error box
function ErrorBox({ message, onRetry, style }) {
  return (
    <div style={{
      padding: '0.75rem 1rem',
      backgroundColor: 'rgba(255,59,59,0.1)',
      border: '1px solid rgba(255,59,59,0.3)',
      borderRadius: 'var(--radius-card)',
      color: 'var(--color-critical)',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      fontSize: '13px', ...style,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <AlertCircle size={15} /> <span>{message}</span>
      </div>
      {onRetry && (
        <button onClick={onRetry} className="btn btn-ghost" style={{ fontSize: '12px', padding: '0.25rem 0.55rem' }}>
          Retry
        </button>
      )}
    </div>
  );
}

// Success toast (auto-dismiss controlled by parent)
function SuccessToast({ message, onClose }) {
  return (
    <div role="status" aria-live="polite" className="fade-in" style={{
      position: 'fixed', top: '1.5rem', right: '1.5rem', zIndex: 9999,
      backgroundColor: 'var(--color-bg-elevated)',
      border: '1px solid var(--color-accent)',
      borderRadius: 'var(--radius-card)',
      padding: '0.85rem 1.25rem',
      display: 'flex', alignItems: 'center', gap: '0.65rem',
      boxShadow: 'var(--shadow-glow)', color: 'var(--color-text-primary)', fontSize: '13px',
    }}>
      <CheckCircle2 size={16} color="var(--color-accent)" />
      <span>{message}</span>
      <button onClick={onClose} aria-label="Dismiss" style={{
        background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', marginLeft: '0.5rem',
      }}><X size={14} /></button>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function Incidents() {
  const { user } = useAuth();
  const canMutate = user?.role === 'ADMIN' || user?.role === 'ANALYST';
  const isViewer = user?.role === 'VIEWER';

  // ── State ──────────────────────────────────────────────────────────────
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    byStatus: { OPEN: 0, INVESTIGATING: 0, RESOLVED: 0, CLOSED: 0 },
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  });
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });

  const [tableLoading, setTableLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [pageError, setPageError] = useState('');
  const [successToast, setSuccessToast] = useState('');

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  // Stale-response guard
  const latestRequestRef = useRef(0);

  // Detail drawer
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [detailIncident, setDetailIncident] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [drawerTab, setDrawerTab] = useState('details'); // 'details' | 'alerts' | 'timeline'

  // Create modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createForm, setCreateForm] = useState({
    title: '', description: '', severity: 'MEDIUM', status: 'OPEN', assignedToId: '',
  });
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState('');

  // Status update
  const [statusModal, setStatusModal] = useState({ isOpen: false, incident: null, targetStatus: '' });
  const [statusSubmitting, setStatusSubmitting] = useState(false);
  const [statusError, setStatusError] = useState('');

  // Note form inside drawer
  const [noteText, setNoteText] = useState('');
  const [noteSubmitting, setNoteSubmitting] = useState(false);
  const [noteError, setNoteError] = useState('');

  // Alert link panel
  const [showLinkPanel, setShowLinkPanel] = useState(false);
  const [availableAlerts, setAvailableAlerts] = useState([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [linkSubmitting, setLinkSubmitting] = useState(false);
  const [linkError, setLinkError] = useState('');
  const [unlinkingId, setUnlinkingId] = useState(null);

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchQuery.trim()), 300);
    return () => clearTimeout(t);
  }, [searchQuery]);

  // Auto-dismiss toast
  useEffect(() => {
    if (!successToast) return;
    const t = setTimeout(() => setSuccessToast(''), 4000);
    return () => clearTimeout(t);
  }, [successToast]);

  // ── Fetch stats ──────────────────────────────────────────────────────────
  const fetchStats = useCallback(async () => {
    try {
      setStatsLoading(true);
      const res = await getIncidentStatsApi();
      if (res?.success && res.data) setStats(res.data);
    } catch { /* non-fatal */ } finally {
      setStatsLoading(false);
    }
  }, []);

  // ── Fetch incident list ─────────────────────────────────────────────────
  const fetchIncidents = useCallback(async (page = 1) => {
    const reqId = ++latestRequestRef.current;
    setTableLoading(true);
    setPageError('');
    try {
      const params = {
        page, limit: pagination.limit || 20,
        ...(statusFilter   && { status: statusFilter }),
        ...(severityFilter && { severity: severityFilter }),
        ...(debouncedSearch && { search: debouncedSearch }),
        ...(startDate && { startDate: new Date(startDate).toISOString() }),
        ...(endDate   && { endDate:   new Date(endDate).toISOString() }),
      };
      const res = await getIncidentsApi(params);
      if (reqId === latestRequestRef.current && res?.success) {
        setIncidents(res.data || []);
        if (res.pagination) setPagination(res.pagination);
      }
    } catch (err) {
      if (reqId === latestRequestRef.current)
        setPageError(err.response?.data?.error || err.message || 'Failed to load incidents.');
    } finally {
      if (reqId === latestRequestRef.current) setTableLoading(false);
    }
  }, [statusFilter, severityFilter, debouncedSearch, startDate, endDate, pagination.limit]);

  // ── Initial load ─────────────────────────────────────────────────────────
  useEffect(() => {
    let mounted = true;
    async function init() {
      if (mounted) { fetchStats(); }
    }
    init();
    return () => { mounted = false; };
  }, [fetchStats]);

  useEffect(() => {
    let mounted = true;
    async function load() { if (mounted) fetchIncidents(1); }
    load();
    return () => { mounted = false; };
  }, [fetchIncidents]);

  // ── Open detail drawer ─────────────────────────────────────────────────
  const openDrawer = useCallback(async (id) => {
    setSelectedIncidentId(id);
    setDetailLoading(true);
    setDetailError('');
    setDetailIncident(null);
    setDrawerTab('details');
    setNoteText('');
    setNoteError('');
    setShowLinkPanel(false);
    setLinkError('');
    try {
      const res = await getIncidentByIdApi(id);
      if (res?.success && res.data) setDetailIncident(res.data);
      else setDetailError('Unable to load incident details.');
    } catch (err) {
      setDetailError(err.response?.data?.error || err.message || 'Failed to load incident.');
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const refreshDrawer = useCallback(async () => {
    if (!selectedIncidentId) return;
    try {
      const res = await getIncidentByIdApi(selectedIncidentId);
      if (res?.success && res.data) setDetailIncident(res.data);
    } catch { /* silently refresh */ }
  }, [selectedIncidentId]);

  const closeDrawer = () => {
    setSelectedIncidentId(null);
    setDetailIncident(null);
    setDetailError('');
    setShowLinkPanel(false);
    setNoteText('');
  };

  // ── Create incident ────────────────────────────────────────────────────
  const openCreateModal = () => {
    setCreateForm({ title: '', description: '', severity: 'MEDIUM', status: 'OPEN', assignedToId: '' });
    setCreateError('');
    setShowCreateModal(true);
  };
  const closeCreateModal = () => { setShowCreateModal(false); setCreateError(''); };

  const handleCreate = async (e) => {
    e.preventDefault();
    if (createSubmitting) return;
    const payload = {
      title: createForm.title.trim(),
      ...(createForm.description.trim() && { description: createForm.description.trim() }),
      severity: createForm.severity,
      status: createForm.status,
      ...(createForm.assignedToId.trim() && { assignedToId: createForm.assignedToId.trim() }),
    };
    if (!payload.title) { setCreateError('Title is required.'); return; }

    setCreateSubmitting(true);
    setCreateError('');
    try {
      const res = await createIncidentApi(payload);
      if (res?.success) {
        setSuccessToast(`Incident "${res.data.readableId}" created.`);
        closeCreateModal();
        fetchIncidents(1);
        fetchStats();
      } else {
        setCreateError(res?.error || 'Failed to create incident.');
      }
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Failed to create incident.';
      setCreateError(msg);
    } finally {
      setCreateSubmitting(false);
    }
  };

  // ── Status transition ──────────────────────────────────────────────────
  const openStatusModal = (incident, targetStatus) => {
    if (!canMutate) return;
    setStatusModal({ isOpen: true, incident, targetStatus });
    setStatusError('');
  };
  const closeStatusModal = () => {
    setStatusModal({ isOpen: false, incident: null, targetStatus: '' });
    setStatusError('');
    setStatusSubmitting(false);
  };

  const handleStatusTransition = async () => {
    const { incident, targetStatus } = statusModal;
    if (!incident || !targetStatus) return;
    setStatusSubmitting(true);
    setStatusError('');
    try {
      const res = await updateIncidentApi(incident.id, { status: targetStatus });
      if (res?.success) {
        setSuccessToast(`Incident status updated to ${targetStatus}.`);
        closeStatusModal();
        fetchIncidents(pagination.page);
        fetchStats();
        if (selectedIncidentId === incident.id) await refreshDrawer();
      } else {
        setStatusError(res?.error || 'Failed to update status.');
      }
    } catch (err) {
      const status = err.response?.status;
      if (status === 409) {
        setStatusError('Conflict: this incident was updated elsewhere. Please refresh and try again.');
      } else {
        setStatusError(err.response?.data?.error || err.message || 'Status update failed.');
      }
    } finally {
      setStatusSubmitting(false);
    }
  };

  // ── Add investigation note ─────────────────────────────────────────────
  const handleAddNote = async (e) => {
    e.preventDefault();
    if (noteSubmitting || !detailIncident) return;
    const trimmed = noteText.trim();
    if (!trimmed) { setNoteError('Note cannot be empty.'); return; }
    if (trimmed.length > 2000) { setNoteError('Note must be 2000 characters or fewer.'); return; }

    setNoteSubmitting(true);
    setNoteError('');
    try {
      const res = await addIncidentNoteApi(detailIncident.id, { note: trimmed });
      if (res?.success) {
        setNoteText('');
        setSuccessToast('Investigation note added.');
        await refreshDrawer();
      } else {
        setNoteError(res?.error || 'Failed to add note.');
      }
    } catch (err) {
      setNoteError(err.response?.data?.error || err.message || 'Failed to add note.');
    } finally {
      setNoteSubmitting(false);
    }
  };

  // ── Alert linking ──────────────────────────────────────────────────────
  const fetchAvailableAlerts = async () => {
    setAlertsLoading(true);
    try {
      const res = await getAlertsApi({ limit: 100, status: 'OPEN' });
      if (res?.success) setAvailableAlerts(res.data || []);
    } catch { setAvailableAlerts([]); } finally {
      setAlertsLoading(false);
    }
  };

  const openLinkPanel = () => {
    setShowLinkPanel(true);
    setLinkError('');
    fetchAvailableAlerts();
  };

  const handleLinkAlert = async (alertId) => {
    if (!detailIncident || linkSubmitting) return;
    // Skip if already linked
    const alreadyLinked = detailIncident.alerts.some((a) => a.id === alertId);
    if (alreadyLinked) return;
    setLinkSubmitting(true);
    setLinkError('');
    try {
      const res = await linkAlertsApi(detailIncident.id, { alertIds: [alertId] });
      if (res?.success || res?.message?.includes('already linked')) {
        setSuccessToast('Alert linked to incident.');
        await refreshDrawer();
      } else {
        setLinkError(res?.error || 'Failed to link alert.');
      }
    } catch (err) {
      setLinkError(err.response?.data?.error || err.message || 'Failed to link alert.');
    } finally {
      setLinkSubmitting(false);
    }
  };

  const handleUnlinkAlert = async (alertId) => {
    if (!detailIncident || unlinkingId) return;
    setUnlinkingId(alertId);
    setLinkError('');
    try {
      const res = await unlinkAlertApi(detailIncident.id, alertId);
      if (res?.success) {
        setSuccessToast('Alert unlinked from incident.');
        await refreshDrawer();
      } else {
        setLinkError(res?.error || 'Failed to unlink alert.');
      }
    } catch (err) {
      setLinkError(err.response?.data?.error || err.message || 'Failed to unlink alert.');
    } finally {
      setUnlinkingId(null);
    }
  };

  // ── Helpers ───────────────────────────────────────────────────────────
  const handleResetFilters = () => {
    setSearchQuery(''); setDebouncedSearch('');
    setStatusFilter(''); setSeverityFilter('');
    setStartDate(''); setEndDate('');
  };
  const hasActiveFilters = Boolean(debouncedSearch || statusFilter || severityFilter || startDate || endDate);
  const highCritTotal = (stats.bySeverity.CRITICAL || 0) + (stats.bySeverity.HIGH || 0);

  // Status transitions available for a given current status
  function availableTransitions(status) {
    switch (status) {
      case 'OPEN':         return ['INVESTIGATING', 'RESOLVED', 'CLOSED'];
      case 'INVESTIGATING':return ['RESOLVED', 'CLOSED', 'OPEN'];
      case 'RESOLVED':     return ['CLOSED', 'OPEN', 'INVESTIGATING'];
      case 'CLOSED':       return [];
      default:             return [];
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

      {/* ── Toast ──────────────────────────────────────────────────────── */}
      {successToast && <SuccessToast message={successToast} onClose={() => setSuccessToast('')} />}

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
              Incident Tracking
            </h1>
            <span style={{
              fontSize: '11px', fontWeight: 600, textTransform: 'uppercase',
              padding: '0.2rem 0.55rem', borderRadius: '999px',
              backgroundColor: isViewer ? 'rgba(91,155,213,0.12)' : 'rgba(0,212,170,0.12)',
              color: isViewer ? 'var(--color-info)' : 'var(--color-accent)',
              border: isViewer ? '1px solid rgba(91,155,213,0.25)' : '1px solid rgba(0,212,170,0.25)',
            }}>
              {isViewer ? 'Read-Only (Viewer)' : 'Analyst Mode'}
            </span>
          </div>
          <p style={{ margin: '0.35rem 0 0', fontSize: '13px', color: 'var(--color-text-secondary)' }}>
            Create, investigate, and manage security incidents across your environment.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            onClick={() => { fetchIncidents(pagination.page); fetchStats(); }}
            disabled={tableLoading}
            className="btn btn-ghost"
            style={{ fontSize: '12.5px', padding: '0.45rem 0.85rem' }}
          >
            <RefreshCw size={14} className={tableLoading ? 'pulse' : ''} />
            <span>Refresh</span>
          </button>
          {canMutate && (
            <button
              id="btn-create-incident"
              onClick={openCreateModal}
              className="btn btn-primary"
              style={{ fontSize: '12.5px', padding: '0.45rem 0.9rem' }}
            >
              <Plus size={14} />
              <span>New Incident</span>
            </button>
          )}
        </div>
      </div>

      {/* ── Stats Cards ─────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '1rem' }}>
        {/* Total */}
        <div className="card" style={{ padding: '1rem 1.15rem', cursor: 'pointer', borderColor: !statusFilter ? 'var(--color-accent)' : 'var(--color-border)', transition: 'border-color 0.2s' }}
          onClick={() => setStatusFilter('')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>Total</span>
            <FolderOpen size={16} color="var(--color-accent)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>{statsLoading ? '—' : stats.total}</div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>All incidents</div>
        </div>

        {/* Open */}
        <div className="card" style={{ padding: '1rem 1.15rem', cursor: 'pointer', borderColor: statusFilter === 'OPEN' ? 'var(--color-critical)' : 'var(--color-border)', transition: 'border-color 0.2s' }}
          onClick={() => setStatusFilter(statusFilter === 'OPEN' ? '' : 'OPEN')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-critical)', textTransform: 'uppercase' }}>Open</span>
            <AlertCircle size={16} color="var(--color-critical)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-critical)' }}>{statsLoading ? '—' : stats.byStatus.OPEN || 0}</div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>Requires triage</div>
        </div>

        {/* Investigating */}
        <div className="card" style={{ padding: '1rem 1.15rem', cursor: 'pointer', borderColor: statusFilter === 'INVESTIGATING' ? 'var(--color-info)' : 'var(--color-border)', transition: 'border-color 0.2s' }}
          onClick={() => setStatusFilter(statusFilter === 'INVESTIGATING' ? '' : 'INVESTIGATING')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-info)', textTransform: 'uppercase' }}>Investigating</span>
            <Clock size={16} color="var(--color-info)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-info)' }}>{statsLoading ? '—' : stats.byStatus.INVESTIGATING || 0}</div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>Active investigation</div>
        </div>

        {/* Resolved */}
        <div className="card" style={{ padding: '1rem 1.15rem', cursor: 'pointer', borderColor: statusFilter === 'RESOLVED' ? 'var(--color-accent)' : 'var(--color-border)', transition: 'border-color 0.2s' }}
          onClick={() => setStatusFilter(statusFilter === 'RESOLVED' ? '' : 'RESOLVED')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-accent)', textTransform: 'uppercase' }}>Resolved</span>
            <CheckCircle2 size={16} color="var(--color-accent)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-accent)' }}>{statsLoading ? '—' : stats.byStatus.RESOLVED || 0}</div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>Remediated</div>
        </div>

        {/* Closed */}
        <div className="card" style={{ padding: '1rem 1.15rem', cursor: 'pointer', borderColor: statusFilter === 'CLOSED' ? 'var(--color-text-secondary)' : 'var(--color-border)', transition: 'border-color 0.2s' }}
          onClick={() => setStatusFilter(statusFilter === 'CLOSED' ? '' : 'CLOSED')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>Closed</span>
            <Shield size={16} color="var(--color-text-muted)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-text-secondary)' }}>{statsLoading ? '—' : stats.byStatus.CLOSED || 0}</div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>Archived</div>
        </div>

        {/* High/Critical */}
        <div className="card" style={{ padding: '1rem 1.15rem', cursor: 'pointer', borderColor: severityFilter === 'CRITICAL' ? 'var(--color-high)' : 'var(--color-border)', transition: 'border-color 0.2s' }}
          onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? '' : 'CRITICAL')}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-high)', textTransform: 'uppercase' }}>High &amp; Critical</span>
            <AlertTriangle size={16} color="var(--color-high)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-high)' }}>{statsLoading ? '—' : highCritTotal}</div>
          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>Priority threats</div>
        </div>
      </div>

      {/* ── Filter Bar ──────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          {/* Status tabs */}
          <div style={{
            display: 'flex', backgroundColor: 'var(--color-bg-base)',
            padding: '0.25rem', borderRadius: '6px',
            border: '1px solid var(--color-border)', gap: '0.2rem',
          }}>
            {[
              { id: '', label: 'All' },
              { id: 'OPEN', label: 'Open' },
              { id: 'INVESTIGATING', label: 'Investigating' },
              { id: 'RESOLVED', label: 'Resolved' },
              { id: 'CLOSED', label: 'Closed' },
            ].map((tab) => {
              const active = statusFilter === tab.id;
              return (
                <button key={tab.id} onClick={() => setStatusFilter(tab.id)} style={{
                  padding: '0.35rem 0.75rem', fontSize: '12px',
                  fontWeight: active ? 600 : 500, borderRadius: '4px', border: 'none', cursor: 'pointer',
                  background: active ? 'var(--color-bg-elevated)' : 'transparent',
                  color: active ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                  boxShadow: active ? '0 1px 4px rgba(0,0,0,0.3)' : 'none',
                  transition: 'all 0.15s ease',
                }}>
                  {tab.label}
                </button>
              );
            })}
          </div>

          {hasActiveFilters && (
            <button onClick={handleResetFilters} className="btn btn-ghost" style={{ fontSize: '11.5px', padding: '0.35rem 0.65rem', color: 'var(--color-text-muted)' }}>
              <RotateCcw size={12} /><span>Reset Filters</span>
            </button>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', alignItems: 'center' }}>
          {/* Search */}
          <div style={{ position: 'relative', gridColumn: 'span 2' }}>
            <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
            <input
              id="incidents-search"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search incident title or description…"
              style={{
                width: '100%', padding: '0.45rem 2rem 0.45rem 2.2rem',
                backgroundColor: 'var(--color-bg-surface)', border: '1px solid var(--color-border)',
                borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '12.5px', outline: 'none',
              }}
            />
            {searchQuery && (
              <button onClick={() => setSearchQuery('')} aria-label="Clear search" style={{
                position: 'absolute', right: '0.65rem', top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer',
              }}><X size={13} /></button>
            )}
          </div>

          {/* Severity */}
          <select id="filter-severity" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}
            style={{ padding: '0.45rem 0.75rem', backgroundColor: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '12.5px', outline: 'none' }}>
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Start date */}
          <input type="datetime-local" value={startDate} onChange={(e) => setStartDate(e.target.value)} title="Created on or after"
            style={{ padding: '0.45rem 0.65rem', backgroundColor: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '12px', outline: 'none' }} />

          {/* End date */}
          <input type="datetime-local" value={endDate} onChange={(e) => setEndDate(e.target.value)} title="Created on or before"
            style={{ padding: '0.45rem 0.65rem', backgroundColor: 'var(--color-bg-surface)', border: '1px solid var(--color-border)', borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '12px', outline: 'none' }} />
        </div>
      </div>

      {/* ── Page Error ──────────────────────────────────────────────────── */}
      {pageError && <ErrorBox message={pageError} onRetry={() => fetchIncidents(pagination.page)} />}

      {/* ── Incidents Table ─────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{
                backgroundColor: 'var(--color-bg-surface)', borderBottom: '1px solid var(--color-border)',
                color: 'var(--color-text-muted)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em',
              }}>
                <th style={{ padding: '0.85rem 1rem', width: '100px' }}>ID</th>
                <th style={{ padding: '0.85rem 1rem', width: '100px' }}>Severity</th>
                <th style={{ padding: '0.85rem 1rem' }}>Title &amp; Description</th>
                <th style={{ padding: '0.85rem 1rem', width: '130px' }}>Status</th>
                <th style={{ padding: '0.85rem 1rem', width: '150px' }}>Assigned To</th>
                <th style={{ padding: '0.85rem 1rem', width: '80px', textAlign: 'center' }}>Alerts</th>
                <th style={{ padding: '0.85rem 1rem', width: '130px' }}>Updated</th>
                <th style={{ padding: '0.85rem 1rem', width: '140px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tableLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
                    <td colSpan={8} style={{ padding: '1.25rem 1rem' }}>
                      <span className="pulse" style={{ display: 'block', height: '16px', backgroundColor: 'var(--color-bg-elevated)', borderRadius: '4px' }} />
                    </td>
                  </tr>
                ))
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '3.5rem 1rem', textAlign: 'center' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem' }}>
                      <div style={{ width: '48px', height: '48px', borderRadius: '50%', backgroundColor: 'var(--color-bg-elevated)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-text-muted)' }}>
                        <FolderOpen size={22} />
                      </div>
                      <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
                        No Incidents Found
                      </div>
                      <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--color-text-muted)', maxWidth: '380px' }}>
                        {hasActiveFilters
                          ? 'No incidents match your current filters. Try adjusting or resetting them.'
                          : 'No incidents have been created yet.'}
                      </p>
                      {hasActiveFilters && (
                        <button onClick={handleResetFilters} className="btn btn-ghost" style={{ marginTop: '0.5rem', fontSize: '12px' }}>
                          Clear Filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => {
                  const statusStyle = getStatusStyle(inc.status);
                  const transitions = availableTransitions(inc.status);
                  return (
                    <tr
                      key={inc.id}
                      style={{
                        borderBottom: '1px solid var(--color-border-subtle)',
                        backgroundColor: selectedIncidentId === inc.id ? 'var(--color-bg-elevated)' : 'transparent',
                        transition: 'background-color 0.15s ease',
                      }}
                      onMouseEnter={(e) => { if (selectedIncidentId !== inc.id) e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)'; }}
                      onMouseLeave={(e) => { if (selectedIncidentId !== inc.id) e.currentTarget.style.backgroundColor = 'transparent'; }}
                    >
                      {/* Readable ID */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: 'var(--color-accent-dim)', fontWeight: 600 }}>
                          {inc.readableId}
                        </span>
                      </td>

                      {/* Severity */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <span className={`badge ${getSeverityBadgeClass(inc.severity)}`}>{inc.severity}</span>
                      </td>

                      {/* Title & desc */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <div
                          style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.15rem', cursor: 'pointer' }}
                          onClick={() => openDrawer(inc.id)}
                        >
                          {inc.title}
                        </div>
                        {inc.description && (
                          <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '420px' }} title={inc.description}>
                            {inc.description}
                          </div>
                        )}
                      </td>

                      {/* Status */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle' }}>
                        <span style={{
                          display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                          padding: '0.2rem 0.55rem', borderRadius: 'var(--radius-badge)',
                          fontSize: '11px', fontWeight: 600, ...statusStyle,
                        }}>
                          <span style={{
                            width: '6px', height: '6px', borderRadius: '50%', display: 'inline-block',
                            backgroundColor: getStatusDotColor(inc.status),
                            ...(inc.status === 'OPEN' ? { animation: 'pulse 2s infinite' } : {}),
                          }} />
                          {inc.status}
                        </span>
                      </td>

                      {/* Assigned */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle', fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                        {inc.assignedTo ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                            <User size={12} color="var(--color-text-muted)" />
                            {inc.assignedTo.name || inc.assignedTo.email}
                          </span>
                        ) : '—'}
                      </td>

                      {/* Alert count */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle', textAlign: 'center' }}>
                        <span style={{
                          fontSize: '11.5px', padding: '0.15rem 0.45rem', borderRadius: '4px',
                          backgroundColor: inc.alertCount > 0 ? 'rgba(0,212,170,0.08)' : 'var(--color-bg-base)',
                          border: '1px solid var(--color-border)',
                          color: inc.alertCount > 0 ? 'var(--color-accent)' : 'var(--color-text-muted)',
                          fontWeight: 600,
                        }}>
                          {inc.alertCount}
                        </span>
                      </td>

                      {/* Updated */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle', fontSize: '12px', color: 'var(--color-text-muted)' }}>
                        {formatRelative(inc.updatedAt)}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '0.9rem 1rem', verticalAlign: 'middle', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                          <button onClick={() => openDrawer(inc.id)} className="btn btn-ghost" title="View details" style={{ padding: '0.35rem 0.55rem', fontSize: '12px' }}>
                            <Eye size={13} /><span>View</span>
                          </button>
                          {canMutate && transitions.length > 0 && (
                            <button
                              onClick={() => openStatusModal(inc, transitions[0])}
                              className="btn btn-ghost"
                              title={`Transition to ${transitions[0]}`}
                              style={{ padding: '0.35rem 0.55rem', fontSize: '12px', color: 'var(--color-info)', borderColor: 'rgba(91,155,213,0.35)' }}
                            >
                              <Activity size={13} /><span>{transitions[0]}</span>
                            </button>
                          )}
                          {!canMutate && (
                            <span title="Read-only" style={{ color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: '0.2rem', fontSize: '11.5px', padding: '0.35rem 0.5rem' }}>
                              <Lock size={12} />
                            </span>
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

        {/* Pagination footer */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0.85rem 1.25rem', borderTop: '1px solid var(--color-border)',
          backgroundColor: 'var(--color-bg-surface)', fontSize: '12px',
          color: 'var(--color-text-secondary)', flexWrap: 'wrap', gap: '0.75rem',
        }}>
          <div>
            Showing{' '}
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
              {incidents.length > 0 ? (pagination.page - 1) * pagination.limit + 1 : 0}
            </span>{' '}–{' '}
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
              {Math.min(pagination.page * pagination.limit, pagination.total)}
            </span>{' '}
            of{' '}
            <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{pagination.total}</span>{' '}
            incidents
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button onClick={() => fetchIncidents(pagination.page - 1)} disabled={pagination.page <= 1 || tableLoading} className="btn btn-ghost" style={{ padding: '0.35rem 0.65rem', fontSize: '12px' }}>
              <ChevronLeft size={14} /><span>Previous</span>
            </button>
            <span style={{ padding: '0 0.4rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Page {pagination.page} of {pagination.totalPages || 1}
            </span>
            <button onClick={() => fetchIncidents(pagination.page + 1)} disabled={pagination.page >= pagination.totalPages || tableLoading} className="btn btn-ghost" style={{ padding: '0.35rem 0.65rem', fontSize: '12px' }}>
              <span>Next</span><ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* ── Detail Drawer ───────────────────────────────────────────────── */}
      {selectedIncidentId && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            display: 'flex', justifyContent: 'flex-end',
            backgroundColor: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(3px)',
          }}
          onClick={closeDrawer}
        >
          <div
            style={{
              width: '100%', maxWidth: '720px', height: '100%',
              backgroundColor: 'var(--color-bg-surface)',
              borderLeft: '1px solid var(--color-border)',
              display: 'flex', flexDirection: 'column',
              boxShadow: 'var(--shadow-card)',
            }}
            onClick={(e) => e.stopPropagation()}
            className="fade-in"
          >
            {/* Drawer header */}
            <div style={{
              padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--color-border)',
              display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem',
            }}>
              <div>
                {detailIncident && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--color-accent-dim)', fontWeight: 700 }}>
                      {detailIncident.readableId}
                    </span>
                    <span className={`badge ${getSeverityBadgeClass(detailIncident.severity)}`}>{detailIncident.severity}</span>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', padding: '0.2rem 0.55rem', borderRadius: 'var(--radius-badge)', fontSize: '11px', fontWeight: 600, ...getStatusStyle(detailIncident.status) }}>
                      {detailIncident.status}
                    </span>
                  </div>
                )}
                <h2 style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
                  {detailIncident?.title || 'Incident Details'}
                </h2>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexShrink: 0 }}>
                {detailIncident && canMutate && availableTransitions(detailIncident.status).slice(0, 2).map((ts) => (
                  <button key={ts} onClick={() => openStatusModal(detailIncident, ts)} className="btn btn-ghost"
                    style={{ fontSize: '11.5px', padding: '0.3rem 0.65rem', color: 'var(--color-info)', borderColor: 'rgba(91,155,213,0.35)' }}>
                    <Activity size={12} /><span>{ts}</span>
                  </button>
                ))}
                <button onClick={closeDrawer} className="btn btn-ghost" aria-label="Close drawer" style={{ padding: '0.4rem' }}>
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Tab bar */}
            <div style={{
              display: 'flex', padding: '0.5rem 1.5rem 0', gap: '0',
              borderBottom: '1px solid var(--color-border)',
              backgroundColor: 'var(--color-bg-surface)',
            }}>
              {['details', 'alerts', 'timeline'].map((tab) => (
                <button key={tab} onClick={() => setDrawerTab(tab)} style={{
                  padding: '0.5rem 1rem', fontSize: '12.5px', fontWeight: drawerTab === tab ? 600 : 400,
                  borderRadius: 0, border: 'none', cursor: 'pointer', background: 'transparent',
                  color: drawerTab === tab ? 'var(--color-accent)' : 'var(--color-text-muted)',
                  borderBottom: drawerTab === tab ? '2px solid var(--color-accent)' : '2px solid transparent',
                  marginBottom: '-1px', transition: 'all 0.15s',
                  textTransform: 'capitalize',
                }}>
                  {tab}{tab === 'alerts' && detailIncident ? ` (${detailIncident.alertCount})` : ''}
                  {tab === 'timeline' && detailIncident ? ` (${detailIncident.timeline?.length || 0})` : ''}
                </button>
              ))}
            </div>

            {/* Drawer body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '1.25rem 1.5rem', display: 'flex', flexDirection: 'column', gap: '1.15rem' }}>
              {detailLoading ? (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                  <RefreshCw size={24} className="pulse" />
                  <p style={{ marginTop: '0.75rem', fontSize: '13px' }}>Loading incident…</p>
                </div>
              ) : detailError ? (
                <ErrorBox message={detailError} onRetry={() => openDrawer(selectedIncidentId)} />
              ) : detailIncident ? (
                <>
                  {/* ── DETAILS TAB ────────────────────────────────────── */}
                  {drawerTab === 'details' && (
                    <>
                      {/* Overview card */}
                      <div className="card" style={{ padding: '1rem' }}>
                        <div className="card-title">Overview</div>
                        <p style={{ margin: '0 0 0.85rem', fontSize: '13px', color: 'var(--color-text-primary)', lineHeight: 1.6 }}>
                          {detailIncident.description || <span style={{ color: 'var(--color-text-muted)', fontStyle: 'italic' }}>No description provided.</span>}
                        </p>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '12px' }}>
                          <div>
                            <span style={{ color: 'var(--color-text-muted)' }}>Created: </span>
                            <span style={{ color: 'var(--color-text-secondary)' }}>{formatDateTime(detailIncident.createdAt)}</span>
                          </div>
                          <div>
                            <span style={{ color: 'var(--color-text-muted)' }}>Updated: </span>
                            <span style={{ color: 'var(--color-text-secondary)' }}>{formatDateTime(detailIncident.updatedAt)}</span>
                          </div>
                          {detailIncident.resolvedAt && (
                            <div>
                              <span style={{ color: 'var(--color-text-muted)' }}>Resolved: </span>
                              <span style={{ color: 'var(--color-accent)' }}>{formatDateTime(detailIncident.resolvedAt)}</span>
                            </div>
                          )}
                          <div>
                            <span style={{ color: 'var(--color-text-muted)' }}>Assigned To: </span>
                            <span style={{ color: 'var(--color-text-secondary)' }}>
                              {detailIncident.assignedTo ? `${detailIncident.assignedTo.name} (${detailIncident.assignedTo.role})` : '—'}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Status transitions */}
                      {canMutate && availableTransitions(detailIncident.status).length > 0 && (
                        <div className="card" style={{ padding: '1rem' }}>
                          <div className="card-title" style={{ marginBottom: '0.65rem' }}>Status Transitions</div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                            {availableTransitions(detailIncident.status).map((ts) => (
                              <button key={ts} onClick={() => openStatusModal(detailIncident, ts)} className="btn btn-ghost"
                                style={{ fontSize: '12px', padding: '0.4rem 0.85rem', color: 'var(--color-info)', borderColor: 'rgba(91,155,213,0.35)' }}>
                                <Activity size={13} /><span>→ {ts}</span>
                              </button>
                            ))}
                          </div>
                          <p style={{ margin: '0.6rem 0 0', fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
                            Transitions create an audit entry and update timestamps automatically.
                          </p>
                        </div>
                      )}
                    </>
                  )}

                  {/* ── ALERTS TAB ─────────────────────────────────────── */}
                  {drawerTab === 'alerts' && (
                    <>
                      {linkError && <ErrorBox message={linkError} />}

                      {canMutate && (
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                          <button onClick={openLinkPanel} className="btn btn-ghost" style={{ fontSize: '12px', padding: '0.4rem 0.8rem' }}>
                            <Link2 size={13} /><span>Link Alert</span>
                          </button>
                          <span style={{ fontSize: '11.5px', color: 'var(--color-text-muted)' }}>
                            Link open alerts to this incident for investigation.
                          </span>
                        </div>
                      )}

                      {/* Link panel */}
                      {showLinkPanel && canMutate && (
                        <div className="card" style={{ padding: '1rem', backgroundColor: 'var(--color-bg-elevated)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
                            <div className="card-title" style={{ margin: 0 }}>Select Alert to Link</div>
                            <button onClick={() => setShowLinkPanel(false)} className="btn btn-ghost" style={{ padding: '0.25rem', fontSize: '12px' }}>
                              <X size={14} />
                            </button>
                          </div>
                          {alertsLoading ? (
                            <div style={{ color: 'var(--color-text-muted)', fontSize: '12.5px', padding: '0.5rem 0' }}>
                              <RefreshCw size={13} className="pulse" /> Loading alerts…
                            </div>
                          ) : availableAlerts.length === 0 ? (
                            <div style={{ color: 'var(--color-text-muted)', fontSize: '12.5px' }}>No open alerts available to link.</div>
                          ) : (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '220px', overflowY: 'auto' }}>
                              {availableAlerts.map((alert) => {
                                const alreadyLinked = detailIncident.alerts.some((a) => a.id === alert.id);
                                return (
                                  <div key={alert.id} style={{
                                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                    padding: '0.5rem 0.75rem', borderRadius: '6px',
                                    border: '1px solid var(--color-border)',
                                    backgroundColor: alreadyLinked ? 'rgba(0,212,170,0.05)' : 'var(--color-bg-base)',
                                    fontSize: '12px',
                                  }}>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.1rem' }}>
                                      <span style={{ color: 'var(--color-text-primary)', fontWeight: 500 }}>{alert.title}</span>
                                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                                        <span className={`badge ${getSeverityBadgeClass(alert.severity)}`} style={{ fontSize: '10px' }}>{alert.severity}</span>
                                      </div>
                                    </div>
                                    <button
                                      onClick={() => handleLinkAlert(alert.id)}
                                      disabled={alreadyLinked || linkSubmitting}
                                      className="btn btn-ghost"
                                      style={{ fontSize: '11.5px', padding: '0.25rem 0.6rem', opacity: alreadyLinked ? 0.5 : 1 }}
                                    >
                                      {alreadyLinked ? 'Linked' : 'Link'}
                                    </button>
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Linked alerts list */}
                      {detailIncident.alerts.length === 0 ? (
                        <div className="card" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '12.5px' }}>
                          No alerts are linked to this incident yet.
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                          {detailIncident.alerts.map((alert) => (
                            <div key={alert.id} className="card" style={{ padding: '0.85rem 1rem', backgroundColor: 'var(--color-bg-elevated)' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem' }}>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.3rem', flexWrap: 'wrap' }}>
                                    <span className={`badge ${getSeverityBadgeClass(alert.severity)}`}>{alert.severity}</span>
                                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', padding: '0.15rem 0.45rem', borderRadius: '4px', fontSize: '10.5px', fontWeight: 600, ...getStatusStyle(alert.status) }}>
                                      {alert.status}
                                    </span>
                                  </div>
                                  <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--color-text-primary)', marginBottom: '0.15rem' }}>
                                    {alert.title}
                                  </div>
                                  {alert.rule && (
                                    <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                                      <Shield size={11} color="var(--color-accent-dim)" />
                                      {alert.rule.name} ({alert.rule.type})
                                    </div>
                                  )}
                                  <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                                    Fired: {formatDateTime(alert.firedAt)}
                                  </div>
                                </div>
                                {canMutate && (
                                  <button
                                    onClick={() => handleUnlinkAlert(alert.id)}
                                    disabled={unlinkingId === alert.id}
                                    className="btn btn-ghost"
                                    title="Unlink this alert"
                                    style={{ fontSize: '11.5px', padding: '0.3rem 0.55rem', color: 'var(--color-critical)', flexShrink: 0 }}
                                  >
                                    <Link2Off size={13} />
                                    <span>{unlinkingId === alert.id ? '…' : 'Unlink'}</span>
                                  </button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}

                  {/* ── TIMELINE TAB ───────────────────────────────────── */}
                  {drawerTab === 'timeline' && (
                    <>
                      {/* Add note form */}
                      {canMutate && (
                        <form onSubmit={handleAddNote} style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                          <textarea
                            id="incident-note-input"
                            value={noteText}
                            onChange={(e) => { setNoteText(e.target.value); setNoteError(''); }}
                            placeholder="Add an investigation note… (up to 2000 characters)"
                            rows={3}
                            maxLength={2000}
                            style={{
                              width: '100%', padding: '0.65rem 0.85rem',
                              backgroundColor: 'var(--color-bg-elevated)',
                              border: noteError ? '1px solid rgba(255,59,59,0.5)' : '1px solid var(--color-border)',
                              borderRadius: '6px', color: 'var(--color-text-primary)',
                              fontSize: '12.5px', resize: 'vertical', fontFamily: 'var(--font-sans)',
                              outline: 'none',
                            }}
                          />
                          {noteError && <div style={{ fontSize: '12px', color: 'var(--color-critical)' }}>{noteError}</div>}
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>{noteText.length}/2000</span>
                            <button type="submit" disabled={noteSubmitting || !noteText.trim()} className="btn btn-primary" style={{ fontSize: '12px', padding: '0.4rem 0.9rem' }}>
                              <MessageSquarePlus size={13} />
                              <span>{noteSubmitting ? 'Saving…' : 'Add Note'}</span>
                            </button>
                          </div>
                        </form>
                      )}

                      {/* Timeline entries — API returns newest first; show in that order */}
                      {detailIncident.timeline.length === 0 ? (
                        <div className="card" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '12.5px' }}>
                          No activity recorded for this incident yet.
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                          {detailIncident.timeline.map((entry) => (
                            <div key={entry.id} className="card" style={{ padding: '0.75rem 1rem', backgroundColor: 'var(--color-bg-elevated)' }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: entry.action === 'INCIDENT_NOTE_ADD' ? '0.4rem' : 0 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                                  {getActionIcon(entry.action)}
                                  <span style={{ fontWeight: 600 }}>{getActionLabel(entry.action)}</span>
                                  {entry.actor && (
                                    <span style={{ color: 'var(--color-text-muted)' }}>
                                      by {entry.actor.name || entry.actor.email}
                                    </span>
                                  )}
                                </div>
                                <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', flexShrink: 0 }}>
                                  {formatDateTime(entry.timestamp)}
                                </span>
                              </div>
                              {entry.action === 'INCIDENT_NOTE_ADD' && entry.details?.note && (
                                <div style={{
                                  marginTop: '0.3rem', padding: '0.55rem 0.75rem',
                                  backgroundColor: 'var(--color-bg-base)', borderRadius: '5px',
                                  borderLeft: '3px solid var(--color-accent)',
                                  fontSize: '12.5px', color: 'var(--color-text-primary)', lineHeight: 1.55,
                                }}>
                                  {entry.details.note}
                                </div>
                              )}
                              {entry.action === 'INCIDENT_STATUS_CHANGE' && entry.details && (
                                <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.25rem', display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                                  <span style={{ ...getStatusStyle(entry.details.previous?.status), padding: '0.1rem 0.4rem', borderRadius: '4px', fontSize: '10.5px', fontWeight: 600 }}>
                                    {entry.details.previous?.status}
                                  </span>
                                  <span>→</span>
                                  <span style={{ ...getStatusStyle(entry.details.updated?.status), padding: '0.1rem 0.4rem', borderRadius: '4px', fontSize: '10.5px', fontWeight: 600 }}>
                                    {entry.details.updated?.status}
                                  </span>
                                </div>
                              )}
                              {entry.action === 'INCIDENT_ALERT_LINK' && entry.details?.newlyLinkedAlertIds?.length > 0 && (
                                <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
                                  Linked {entry.details.newlyLinkedAlertIds.length} alert(s).
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* ── Create Incident Modal ─────────────────────────────────────────── */}
      {showCreateModal && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 2000,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            backgroundColor: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(3px)',
          }}
          onClick={closeCreateModal}
        >
          <div
            className="card fade-in"
            style={{ width: '100%', maxWidth: '520px', padding: '1.5rem', backgroundColor: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1.15rem' }}>
              <div style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: 'rgba(0,212,170,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-accent)' }}>
                <FolderOpen size={18} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--color-text-primary)' }}>Create New Incident</h3>
                <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>Opens an investigation case</span>
              </div>
            </div>

            <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {/* Title */}
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                  Title <span style={{ color: 'var(--color-critical)' }}>*</span>
                </label>
                <input
                  id="create-incident-title"
                  type="text"
                  value={createForm.title}
                  onChange={(e) => { setCreateForm({ ...createForm, title: e.target.value }); setCreateError(''); }}
                  placeholder="Brief, descriptive incident title"
                  required
                  maxLength={200}
                  style={{ width: '100%', padding: '0.5rem 0.75rem', backgroundColor: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '13px', outline: 'none' }}
                />
              </div>

              {/* Description */}
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                  Description
                </label>
                <textarea
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  placeholder="Optional – detailed context or initial findings"
                  rows={3}
                  maxLength={2000}
                  style={{ width: '100%', padding: '0.5rem 0.75rem', backgroundColor: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '13px', resize: 'vertical', fontFamily: 'var(--font-sans)', outline: 'none' }}
                />
              </div>

              {/* Severity + Status row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>Severity</label>
                  <select
                    id="create-severity"
                    value={createForm.severity}
                    onChange={(e) => setCreateForm({ ...createForm, severity: e.target.value })}
                    style={{ width: '100%', padding: '0.5rem 0.75rem', backgroundColor: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '13px', outline: 'none' }}>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>Initial Status</label>
                  <select
                    id="create-status"
                    value={createForm.status}
                    onChange={(e) => setCreateForm({ ...createForm, status: e.target.value })}
                    style={{ width: '100%', padding: '0.5rem 0.75rem', backgroundColor: 'var(--color-bg-elevated)', border: '1px solid var(--color-border)', borderRadius: '6px', color: 'var(--color-text-primary)', fontSize: '13px', outline: 'none' }}>
                    <option value="OPEN">Open</option>
                    <option value="INVESTIGATING">Investigating</option>
                  </select>
                </div>
              </div>

              {createError && (
                <div style={{ padding: '0.65rem 0.85rem', backgroundColor: 'rgba(255,59,59,0.12)', border: '1px solid rgba(255,59,59,0.3)', borderRadius: '6px', color: 'var(--color-critical)', fontSize: '12.5px' }}>
                  {createError}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.25rem' }}>
                <button type="button" onClick={closeCreateModal} disabled={createSubmitting} className="btn btn-ghost">Cancel</button>
                <button type="submit" disabled={createSubmitting || !createForm.title.trim()} className="btn btn-primary">
                  <Plus size={14} />
                  <span>{createSubmitting ? 'Creating…' : 'Create Incident'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Status Transition Modal ─────────────────────────────────────── */}
      {statusModal.isOpen && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 2000,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            backgroundColor: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(3px)',
          }}
          onClick={closeStatusModal}
        >
          <div
            className="card fade-in"
            style={{ width: '100%', maxWidth: '460px', padding: '1.5rem', backgroundColor: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.85rem' }}>
              <div style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: 'rgba(91,155,213,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-info)' }}>
                <CalendarCheck size={18} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--color-text-primary)' }}>Update Incident Status</h3>
                <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>This action will be recorded in the audit timeline.</span>
              </div>
            </div>

            <p style={{ margin: '0 0 1rem', fontSize: '13px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              Transition <strong style={{ color: 'var(--color-text-primary)' }}>"{statusModal.incident?.title}"</strong> from{' '}
              <span style={{ fontWeight: 600, color: 'var(--color-info)' }}>{statusModal.incident?.status}</span> to{' '}
              <span style={{ fontWeight: 600, color: 'var(--color-accent)' }}>{statusModal.targetStatus}</span>?
              {statusModal.targetStatus === 'RESOLVED' && ' This will automatically record a resolution timestamp.'}
              {(['OPEN', 'INVESTIGATING'].includes(statusModal.targetStatus) && statusModal.incident?.status === 'RESOLVED') && ' This will clear the resolution timestamp.'}
            </p>

            {statusError && (
              <div style={{ marginBottom: '1rem', padding: '0.65rem 0.85rem', backgroundColor: 'rgba(255,59,59,0.12)', border: '1px solid rgba(255,59,59,0.3)', borderRadius: '6px', color: 'var(--color-critical)', fontSize: '12.5px' }}>
                {statusError}
                {statusError.includes('Conflict') && (
                  <button onClick={() => { closeStatusModal(); fetchIncidents(pagination.page); if (selectedIncidentId) openDrawer(selectedIncidentId); }}
                    className="btn btn-ghost" style={{ fontSize: '12px', padding: '0.25rem 0.5rem', marginLeft: '0.5rem' }}>
                    Refresh
                  </button>
                )}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button type="button" onClick={closeStatusModal} disabled={statusSubmitting} className="btn btn-ghost">Cancel</button>
              <button type="button" onClick={handleStatusTransition} disabled={statusSubmitting} className="btn btn-primary"
                style={{ backgroundColor: 'var(--color-info)', color: '#000' }}>
                {statusSubmitting ? 'Updating…' : `Confirm → ${statusModal.targetStatus}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
