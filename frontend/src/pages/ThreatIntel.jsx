// src/pages/ThreatIntel.jsx
// Threat Intelligence & IOC Integration UI for SOC Lite (Phase 9).
// Comprehensive IOC inventory, multi-provider enrichment, threat verdicts,
// fleet correlation, and RBAC enforcement.

import { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  ShieldAlert,
  Search,
  Plus,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Pencil,
  Trash2,
  X,
  ChevronLeft,
  ChevronRight,
  Lock,
  Info,
  History,
  Globe,
  Hash,
  Link as LinkIcon,
  Server,
  Copy,
  Check,
  Zap,
  Database,
  Activity,
  Layers,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import {
  getIocsApi,
  getIocStatsApi,
  getIocByIdApi,
  createIocApi,
  updateIocApi,
  deleteIocApi,
  lookupIocApi,
} from '../api/threatIntel.api';

// ── Badge and Visual Styling Helpers ───────────────────────────────────────

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
    case 'ACTIVE':   return 'badge-low';
    case 'INACTIVE': return 'badge-medium';
    case 'EXPIRED':  return 'badge-critical';
    case 'REVOKED':  return 'badge-critical';
    default:         return 'badge-info';
  }
}

function getVerdictBadgeClass(verdict) {
  switch (verdict) {
    case 'MALICIOUS':  return 'badge-critical';
    case 'SUSPICIOUS': return 'badge-high';
    case 'BENIGN':     return 'badge-low';
    case 'UNKNOWN':    return 'badge-info';
    default:           return 'badge-info';
  }
}

function getTypeIcon(type) {
  switch (type) {
    case 'IP':     return <Server size={14} className="text-cyan-400" />;
    case 'DOMAIN': return <Globe size={14} className="text-purple-400" />;
    case 'HASH':   return <Hash size={14} className="text-emerald-400" />;
    case 'URL':    return <LinkIcon size={14} className="text-amber-400" />;
    default:       return <Database size={14} className="text-slate-400" />;
  }
}

function getTypeBadgeStyle(type) {
  switch (type) {
    case 'IP':     return 'bg-cyan-950/60 text-cyan-300 border-cyan-800/60';
    case 'DOMAIN': return 'bg-purple-950/60 text-purple-300 border-purple-800/60';
    case 'HASH':   return 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60';
    case 'URL':    return 'bg-amber-950/60 text-amber-300 border-amber-800/60';
    default:       return 'bg-slate-900 text-slate-300 border-slate-700';
  }
}

function formatLocalDate(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function ThreatIntel() {
  const { user } = useAuth();
  const isViewer = user?.role === 'VIEWER';
  const isAdmin = user?.role === 'ADMIN';

  // ── State Management ──────────────────────────────────────────────────────
  const [iocs, setIocs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Pagination
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);

  // Detail Drawer State
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedIocId, setSelectedIocId] = useState(null);
  const [detailIoc, setDetailIoc] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailTab, setDetailTab] = useState('overview'); // 'overview' | 'enrichment' | 'correlations' | 'audit'

  // Modals
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState(null);
  const [createForm, setCreateForm] = useState({
    type: 'IP',
    value: '',
    severity: 'MEDIUM',
    confidence: 80,
    source: 'ThreatHunt',
    description: '',
    expiresAt: '',
  });

  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editSubmitting, setEditSubmitting] = useState(false);
  const [editError, setEditError] = useState(null);
  const [editIoc, setEditIoc] = useState(null);
  const [editForm, setEditForm] = useState({
    severity: 'MEDIUM',
    confidence: 80,
    status: 'ACTIVE',
    description: '',
    expiresAt: '',
  });

  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [deleteSubmitting, setDeleteSubmitting] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);

  // Provider Lookup State
  const [lookupInProgress, setLookupInProgress] = useState({});
  const [lookupResultNotice, setLookupResultNotice] = useState(null);
  const [copiedValue, setCopiedValue] = useState(null);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  // Fetch Inventory and Statistics
  const fetchIocs = useCallback(async () => {
    try {
      const res = await getIocsApi({
        page,
        limit: 10,
        search: debouncedSearch || undefined,
        type: typeFilter || undefined,
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        sortBy: 'createdAt',
        sortOrder: 'desc',
      });
      if (res.success) {
        setIocs(res.data);
        setTotalPages(res.pagination.totalPages);
        setTotalCount(res.pagination.total);
      }
    } catch (err) {
      setError(err?.response?.data?.error || err.message || 'Failed to fetch IOCs');
    } finally {
      setLoading(false);
    }
  }, [page, debouncedSearch, typeFilter, statusFilter, severityFilter]);

  const fetchStats = useCallback(async () => {
    try {
      const res = await getIocStatsApi();
      if (res.success) {
        setStats(res.data);
      }
    } catch {
      // Non-blocking stats failure
    } finally {
      setStatsLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    async function loadData() {
      if (!active) return;
      await fetchIocs();
      await fetchStats();
    }
    loadData();
    return () => {
      active = false;
    };
  }, [fetchIocs, fetchStats]);

  // Fetch Details for Drawer
  const openDetailDrawer = async (id) => {
    setSelectedIocId(id);
    setDrawerOpen(true);
    setDetailLoading(true);
    setDetailTab('overview');
    try {
      const res = await getIocByIdApi(id);
      if (res.success) {
        setDetailIoc(res.data);
      }
    } catch (err) {
      setError(err?.response?.data?.error || 'Failed to load indicator details');
    } finally {
      setDetailLoading(false);
    }
  };

  const closeDrawer = () => {
    setDrawerOpen(false);
    setSelectedIocId(null);
    setDetailIoc(null);
  };

  // Copy to clipboard
  const handleCopy = (val) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  // Perform On-Demand Provider Lookup
  const handleLookup = async (iocId, providerName = null, forceRefresh = true) => {
    if (isViewer) return;
    setLookupInProgress((prev) => ({ ...prev, [iocId]: true }));
    setLookupResultNotice(null);

    try {
      const res = await lookupIocApi(iocId, {
        provider: providerName || undefined,
        forceRefresh,
      });

      if (res.success) {
        const obs = res.data;
        const msg = obs.status === 'NOT_CONFIGURED'
          ? `Provider "${res.provider}" is not configured in environment.`
          : `Enrichment completed via ${res.provider}. Verdict: ${obs.verdict || 'UNKNOWN'} (Score: ${obs.score ?? '—'})`;

        setLookupResultNotice({
          type: obs.verdict === 'MALICIOUS' ? 'error' : obs.status === 'SUCCESS' ? 'success' : 'info',
          message: msg,
        });

        // Refresh lists and details
        fetchIocs();
        fetchStats();
        if (selectedIocId === iocId) {
          const detailRes = await getIocByIdApi(iocId);
          if (detailRes.success) setDetailIoc(detailRes.data);
        }
      }
    } catch (err) {
      setLookupResultNotice({
        type: 'error',
        message: err?.response?.data?.error || 'Provider lookup failed',
      });
    } finally {
      setLookupInProgress((prev) => ({ ...prev, [iocId]: false }));
    }
  };

  // Handle Create IOC Submit
  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setCreateSubmitting(true);
    setCreateError(null);

    try {
      const res = await createIocApi({
        type: createForm.type,
        value: createForm.value,
        severity: createForm.severity,
        confidence: Number(createForm.confidence),
        source: createForm.source || 'MANUAL',
        description: createForm.description || undefined,
        expiresAt: createForm.expiresAt || undefined,
      });

      if (res.success) {
        setCreateModalOpen(false);
        setCreateForm({
          type: 'IP',
          value: '',
          severity: 'MEDIUM',
          confidence: 80,
          source: 'ThreatHunt',
          description: '',
          expiresAt: '',
        });
        fetchIocs();
        fetchStats();
      }
    } catch (err) {
      setCreateError(err?.response?.data?.error || err.message || 'Failed to register indicator');
    } finally {
      setCreateSubmitting(false);
    }
  };

  // Handle Edit IOC
  const handleOpenEdit = (ioc) => {
    setEditIoc(ioc);
    setEditForm({
      severity: ioc.severity || 'MEDIUM',
      confidence: ioc.confidence ?? 80,
      status: ioc.status || 'ACTIVE',
      description: ioc.description || '',
      expiresAt: ioc.expiresAt ? ioc.expiresAt.split('T')[0] : '',
    });
    setEditError(null);
    setEditModalOpen(true);
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    if (!editIoc) return;
    setEditSubmitting(true);
    setEditError(null);

    try {
      const res = await updateIocApi(editIoc.id, {
        severity: editForm.severity,
        confidence: Number(editForm.confidence),
        status: editForm.status,
        description: editForm.description,
        expiresAt: editForm.expiresAt || null,
      });

      if (res.success) {
        setEditModalOpen(false);
        setEditIoc(null);
        fetchIocs();
        fetchStats();
        if (selectedIocId === editIoc.id) {
          const detailRes = await getIocByIdApi(editIoc.id);
          if (detailRes.success) setDetailIoc(detailRes.data);
        }
      }
    } catch (err) {
      setEditError(err?.response?.data?.error || err.message || 'Failed to update indicator');
    } finally {
      setEditSubmitting(false);
    }
  };

  // Handle Delete IOC
  const handleOpenDelete = (ioc) => {
    setDeleteTarget(ioc);
    setDeleteModalOpen(true);
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    setDeleteSubmitting(true);
    try {
      const res = await deleteIocApi(deleteTarget.id);
      if (res.success) {
        setDeleteModalOpen(false);
        setDeleteTarget(null);
        if (selectedIocId === deleteTarget.id) closeDrawer();
        fetchIocs();
        fetchStats();
      }
    } catch (err) {
      setError(err?.response?.data?.error || 'Failed to delete indicator');
    } finally {
      setDeleteSubmitting(false);
    }
  };

  const handleResetFilters = () => {
    setSearch('');
    setTypeFilter('');
    setStatusFilter('');
    setSeverityFilter('');
    setPage(1);
  };

  return (
    <div className="space-y-6">
      {/* ── Page Header ──────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-7 w-7 text-cyan-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">Threat Intelligence</h1>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Indicators of Compromise (IOC) inventory, multi-provider enrichment, threat verdicts, and fleet correlation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              fetchIocs();
              fetchStats();
            }}
            className="btn btn-secondary inline-flex items-center gap-1.5"
            title="Refresh IOC List"
          >
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>

          {!isViewer && (
            <button
              onClick={() => {
                setCreateError(null);
                setCreateModalOpen(true);
              }}
              className="btn btn-primary inline-flex items-center gap-1.5 shadow-lg shadow-cyan-950/40"
            >
              <Plus size={16} />
              <span>Register IOC</span>
            </button>
          )}
        </div>
      </div>

      {/* ── Lookup / Global Notice Banner ─────────────────────────────────────── */}
      {lookupResultNotice && (
        <div
          className={`flex items-start justify-between rounded-lg border p-4 text-sm ${
            lookupResultNotice.type === 'error'
              ? 'border-red-800/80 bg-red-950/40 text-red-300'
              : lookupResultNotice.type === 'success'
              ? 'border-emerald-800/80 bg-emerald-950/40 text-emerald-300'
              : 'border-cyan-800/80 bg-cyan-950/40 text-cyan-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {lookupResultNotice.type === 'error' ? (
              <AlertCircle size={18} />
            ) : lookupResultNotice.type === 'success' ? (
              <CheckCircle2 size={18} />
            ) : (
              <Info size={18} />
            )}
            <span>{lookupResultNotice.message}</span>
          </div>
          <button
            onClick={() => setLookupResultNotice(null)}
            className="text-slate-400 hover:text-white"
          >
            <X size={15} />
          </button>
        </div>
      )}

      {/* ── KPI Stat Cards ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Card 1: Total Indicators */}
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total IOCs</span>
            <div className="rounded-md bg-cyan-950/60 p-2 text-cyan-400 border border-cyan-800/50">
              <Database size={18} />
            </div>
          </div>
          <div className="mt-2 text-3xl font-extrabold text-white">
            {statsLoading ? '—' : (stats?.total ?? 0)}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            {statsLoading ? '' : `${stats?.byType?.IP || 0} IPs · ${stats?.byType?.DOMAIN || 0} Domains · ${stats?.byType?.HASH || 0} Hashes · ${stats?.byType?.URL || 0} URLs`}
          </div>
        </div>

        {/* Card 2: Active Indicators */}
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Active Indicators</span>
            <div className="rounded-md bg-emerald-950/60 p-2 text-emerald-400 border border-emerald-800/50">
              <Activity size={18} />
            </div>
          </div>
          <div className="mt-2 text-3xl font-extrabold text-emerald-400">
            {statsLoading ? '—' : (stats?.active ?? 0)}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            {statsLoading ? '' : `${stats?.inactive || 0} inactive or expired`}
          </div>
        </div>

        {/* Card 3: Threat Breakdown by Type */}
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Fleet Indicators</span>
            <div className="rounded-md bg-purple-950/60 p-2 text-purple-400 border border-purple-800/50">
              <Layers size={18} />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-3 text-white">
            <span className="text-2xl font-bold">{stats?.byType?.IP || 0} <span className="text-xs font-normal text-slate-400">IPs</span></span>
            <span className="text-2xl font-bold">{stats?.byType?.DOMAIN || 0} <span className="text-xs font-normal text-slate-400">Dom</span></span>
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Active threat intelligence indicators
          </div>
        </div>

        {/* Card 4: Confirmed Malicious */}
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Elevated Threats</span>
            <div className="rounded-md bg-red-950/60 p-2 text-red-400 border border-red-800/50">
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="mt-2 text-3xl font-extrabold text-red-400">
            {statsLoading ? '—' : (stats?.confirmedMaliciousCount ?? 0)}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Confirmed malicious by provider feeds
          </div>
        </div>
      </div>

      {/* ── Search & Filter Bar ──────────────────────────────────────────────── */}
      <div className="card p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search by indicator value, description, or source..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-9"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Type Filter */}
            <select
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setPage(1);
              }}
              className="select"
            >
              <option value="">All Types</option>
              <option value="IP">IP Address</option>
              <option value="DOMAIN">Domain</option>
              <option value="HASH">File Hash</option>
              <option value="URL">URL</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="select"
            >
              <option value="">All Statuses</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="INACTIVE">INACTIVE</option>
              <option value="EXPIRED">EXPIRED</option>
              <option value="REVOKED">REVOKED</option>
            </select>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="select"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>

            {(search || typeFilter || statusFilter || severityFilter) && (
              <button
                onClick={handleResetFilters}
                className="btn btn-secondary text-xs"
              >
                Reset
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Main IOC Inventory Table ────────────────────────────────────────── */}
      <div className="card overflow-hidden">
        {error && (
          <div className="border-b border-red-800/80 bg-red-950/40 p-4 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="border-b border-slate-800 bg-slate-900/80 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-4 py-3">Indicator Value</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Threat Verdict</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Last Checked</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw size={18} className="animate-spin text-cyan-400" />
                      <span>Loading threat indicators...</span>
                    </div>
                  </td>
                </tr>
              ) : iocs.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    <Shield size={32} className="mx-auto mb-2 text-slate-600" />
                    <p className="text-base font-semibold text-slate-300">No threat indicators found</p>
                    <p className="text-xs text-slate-500">
                      {search || typeFilter || statusFilter || severityFilter
                        ? 'Try adjusting your search query or filters'
                        : 'Register an indicator using the button above'}
                    </p>
                  </td>
                </tr>
              ) : (
                iocs.map((ioc) => {
                  const latest = ioc.latestEnrichment;
                  const isLookingUp = !!lookupInProgress[ioc.id];

                  return (
                    <tr
                      key={ioc.id}
                      onClick={() => openDetailDrawer(ioc.id)}
                      className="cursor-pointer transition-colors hover:bg-slate-800/40"
                    >
                      {/* Value + Copy */}
                      <td className="px-4 py-3 font-mono text-xs text-white">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-cyan-300 hover:underline">{ioc.value}</span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopy(ioc.value);
                            }}
                            className="text-slate-500 hover:text-cyan-400"
                            title="Copy to clipboard"
                          >
                            {copiedValue === ioc.value ? (
                              <Check size={13} className="text-emerald-400" />
                            ) : (
                              <Copy size={13} />
                            )}
                          </button>
                        </div>
                      </td>

                      {/* Type */}
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium ${getTypeBadgeStyle(ioc.type)}`}>
                          {getTypeIcon(ioc.type)}
                          <span>{ioc.type}</span>
                        </span>
                      </td>

                      {/* Severity */}
                      <td className="px-4 py-3">
                        <span className={`badge ${getSeverityBadgeClass(ioc.severity)}`}>
                          {ioc.severity}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3">
                        <span className={`badge ${getStatusBadgeClass(ioc.status)}`}>
                          {ioc.status}
                        </span>
                      </td>

                      {/* Threat Verdict */}
                      <td className="px-4 py-3">
                        {latest ? (
                          <div className="flex flex-col">
                            <span className={`badge ${getVerdictBadgeClass(latest.verdict)}`}>
                              {latest.verdict || latest.status}
                            </span>
                            <span className="text-[10px] text-slate-500 mt-0.5">
                              via {latest.provider}
                            </span>
                          </div>
                        ) : (
                          <span className="text-xs text-slate-500">Not checked</span>
                        )}
                      </td>

                      {/* Confidence */}
                      <td className="px-4 py-3">
                        <div className="w-20">
                          <div className="flex justify-between text-[11px] text-slate-300">
                            <span>{ioc.confidence}%</span>
                          </div>
                          <div className="h-1.5 w-full rounded-full bg-slate-800 mt-1 overflow-hidden">
                            <div
                              className={`h-full ${
                                ioc.confidence >= 80
                                  ? 'bg-red-500'
                                  : ioc.confidence >= 50
                                  ? 'bg-amber-500'
                                  : 'bg-cyan-500'
                              }`}
                              style={{ width: `${ioc.confidence}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Source */}
                      <td className="px-4 py-3 text-xs text-slate-400 truncate max-w-[120px]">
                        {ioc.source || 'MANUAL'}
                      </td>

                      {/* Last Checked */}
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {latest ? formatLocalDate(latest.queriedAt) : formatLocalDate(ioc.createdAt)}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                          {!isViewer && (
                            <button
                              type="button"
                              onClick={() => handleLookup(ioc.id, null, true)}
                              disabled={isLookingUp}
                              className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-cyan-400 disabled:opacity-40"
                              title="Trigger Threat Intelligence Lookup"
                            >
                              <Zap size={15} className={isLookingUp ? 'animate-pulse text-amber-400' : ''} />
                            </button>
                          )}

                          {!isViewer && (
                            <button
                              type="button"
                              onClick={() => handleOpenEdit(ioc)}
                              className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
                              title="Edit Indicator"
                            >
                              <Pencil size={15} />
                            </button>
                          )}

                          {isAdmin && (
                            <button
                              type="button"
                              onClick={() => handleOpenDelete(ioc)}
                              className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-red-400"
                              title="Permanently Delete Indicator"
                            >
                              <Trash2 size={15} />
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

        {/* Pagination Bar */}
        <div className="flex items-center justify-between border-t border-slate-800 px-4 py-3 text-xs text-slate-400">
          <div>
            Showing {iocs.length > 0 ? (page - 1) * 10 + 1 : 0} to{' '}
            {Math.min(page * 10, totalCount)} of {totalCount} indicators
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="btn btn-secondary p-1 disabled:opacity-40"
              title="Previous page"
            >
              <ChevronLeft size={16} />
            </button>
            <span className="text-white">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || loading}
              className="btn btn-secondary p-1 disabled:opacity-40"
              title="Next page"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* ── Slide-Out Detail Drawer ─────────────────────────────────────────── */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
          <div className="flex h-full w-full max-w-2xl flex-col bg-slate-900 border-l border-slate-800 shadow-2xl overflow-y-auto">
            {/* Drawer Header */}
            <div className="flex items-center justify-between border-b border-slate-800 p-5">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-cyan-950/80 p-2.5 text-cyan-400 border border-cyan-800/60">
                  <Shield size={20} />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white font-mono break-all">
                    {detailIoc?.value || 'Indicator Details'}
                  </h2>
                  <div className="flex items-center gap-2 mt-1">
                    {detailIoc && (
                      <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ${getTypeBadgeStyle(detailIoc.type)}`}>
                        {detailIoc.type}
                      </span>
                    )}
                    {detailIoc && (
                      <span className={`badge ${getSeverityBadgeClass(detailIoc.severity)}`}>
                        {detailIoc.severity}
                      </span>
                    )}
                    {detailIoc && (
                      <span className={`badge ${getStatusBadgeClass(detailIoc.status)}`}>
                        {detailIoc.status}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <button
                onClick={closeDrawer}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X size={20} />
              </button>
            </div>

            {/* Read-only banner for viewers */}
            {isViewer && (
              <div className="flex items-center gap-2 border-b border-amber-800/60 bg-amber-950/40 px-5 py-2.5 text-xs text-amber-300">
                <Lock size={13} />
                <span>Read-only mode (VIEWER role). Indicator mutations and external lookups are restricted.</span>
              </div>
            )}

            {/* Drawer Tabs */}
            <div className="flex border-b border-slate-800 px-5">
              <button
                onClick={() => setDetailTab('overview')}
                className={`flex items-center gap-1.5 border-b-2 py-3 px-3 text-xs font-semibold ${
                  detailTab === 'overview'
                    ? 'border-cyan-400 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <Info size={14} /> Overview
              </button>
              <button
                onClick={() => setDetailTab('enrichment')}
                className={`flex items-center gap-1.5 border-b-2 py-3 px-3 text-xs font-semibold ${
                  detailTab === 'enrichment'
                    ? 'border-cyan-400 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <Zap size={14} /> Threat Enrichment ({detailIoc?.enrichments?.length || 0})
              </button>
              <button
                onClick={() => setDetailTab('correlations')}
                className={`flex items-center gap-1.5 border-b-2 py-3 px-3 text-xs font-semibold ${
                  detailTab === 'correlations'
                    ? 'border-cyan-400 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <Server size={14} /> Fleet Correlation (
                {(detailIoc?.correlations?.assets?.length || 0) +
                  (detailIoc?.correlations?.events?.length || 0) +
                  (detailIoc?.correlations?.alerts?.length || 0)}
                )
              </button>
              <button
                onClick={() => setDetailTab('audit')}
                className={`flex items-center gap-1.5 border-b-2 py-3 px-3 text-xs font-semibold ${
                  detailTab === 'audit'
                    ? 'border-cyan-400 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-white'
                }`}
              >
                <History size={14} /> Audit Trail ({detailIoc?.auditLogs?.length || 0})
              </button>
            </div>

            {/* Drawer Content */}
            <div className="flex-1 p-5 space-y-6">
              {detailLoading ? (
                <div className="flex items-center justify-center py-20 text-slate-400">
                  <RefreshCw size={24} className="animate-spin text-cyan-400 mr-2" />
                  <span>Loading indicator intelligence...</span>
                </div>
              ) : !detailIoc ? (
                <div className="py-12 text-center text-slate-400">Indicator details unavailable</div>
              ) : (
                <>
                  {/* TAB 1: OVERVIEW */}
                  {detailTab === 'overview' && (
                    <div className="space-y-6">
                      {/* Lookup action banner */}
                      {!isViewer && (
                        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <h3 className="text-sm font-semibold text-white">External Provider Lookup</h3>
                              <p className="text-xs text-slate-400 mt-0.5">
                                Query AbuseIPDB, VirusTotal, or AlienVault OTX on demand.
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleLookup(detailIoc.id, null, true)}
                                disabled={lookupInProgress[detailIoc.id]}
                                className="btn btn-primary inline-flex items-center gap-1.5 text-xs py-1.5"
                              >
                                <Zap size={14} className={lookupInProgress[detailIoc.id] ? 'animate-pulse' : ''} />
                                <span>{lookupInProgress[detailIoc.id] ? 'Scanning...' : 'Run Lookup'}</span>
                              </button>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Properties Grid */}
                      <div className="grid grid-cols-2 gap-4 text-xs">
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                          <span className="text-slate-500 uppercase font-semibold">Indicator Value</span>
                          <p className="mt-1 font-mono text-sm font-bold text-cyan-300 break-all">{detailIoc.value}</p>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                          <span className="text-slate-500 uppercase font-semibold">Indicator Type</span>
                          <p className="mt-1 font-semibold text-white">{detailIoc.type}</p>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                          <span className="text-slate-500 uppercase font-semibold">Confidence Rating</span>
                          <p className="mt-1 font-semibold text-white">{detailIoc.confidence}%</p>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                          <span className="text-slate-500 uppercase font-semibold">Source Feeder</span>
                          <p className="mt-1 font-semibold text-white">{detailIoc.source || 'MANUAL'}</p>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                          <span className="text-slate-500 uppercase font-semibold">Registered Timestamp</span>
                          <p className="mt-1 text-slate-300">{formatLocalDate(detailIoc.createdAt)}</p>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                          <span className="text-slate-500 uppercase font-semibold">Expiration Date</span>
                          <p className="mt-1 text-slate-300">{detailIoc.expiresAt ? formatLocalDate(detailIoc.expiresAt) : 'Never (Permanent)'}</p>
                        </div>
                      </div>

                      {/* Description */}
                      <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-4 text-xs">
                        <span className="text-slate-500 uppercase font-semibold">Analyst Investigation Notes</span>
                        <p className="mt-1.5 text-slate-300 whitespace-pre-wrap leading-relaxed">
                          {detailIoc.description || 'No analyst notes recorded for this indicator.'}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* TAB 2: THREAT ENRICHMENT */}
                  {detailTab === 'enrichment' && (
                    <div className="space-y-4">
                      {detailIoc.enrichments?.length === 0 ? (
                        <div className="py-12 text-center text-slate-400">
                          <Zap size={32} className="mx-auto mb-2 text-slate-600" />
                          <p className="text-base font-semibold text-slate-300">No threat provider lookups yet</p>
                          <p className="text-xs text-slate-500">
                            Use the &quot;Run Lookup&quot; button in the overview tab to query configured threat intelligence providers.
                          </p>
                        </div>
                      ) : (
                        detailIoc.enrichments.map((enr) => (
                          <div
                            key={enr.id}
                            className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-3"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-white text-sm">{enr.provider}</span>
                                <span className={`badge ${getVerdictBadgeClass(enr.verdict)}`}>
                                  {enr.verdict || enr.status}
                                </span>
                              </div>
                              <span className="text-xs text-slate-500">{formatLocalDate(enr.queriedAt)}</span>
                            </div>

                            {/* Score / Metrics */}
                            <div className="grid grid-cols-3 gap-2 text-xs">
                              <div className="rounded bg-slate-900 p-2 text-center">
                                <span className="text-slate-500 block">Status</span>
                                <span className="font-semibold text-white">{enr.status}</span>
                              </div>
                              <div className="rounded bg-slate-900 p-2 text-center">
                                <span className="text-slate-500 block">Confidence / Score</span>
                                <span className="font-semibold text-white">{enr.score !== null ? `${enr.score}%` : '—'}</span>
                              </div>
                              <div className="rounded bg-slate-900 p-2 text-center">
                                <span className="text-slate-500 block">Detections</span>
                                <span className="font-semibold text-white">
                                  {enr.detectionCount !== null ? enr.detectionCount : '0'}
                                  {enr.totalEngines ? ` / ${enr.totalEngines}` : ''}
                                </span>
                              </div>
                            </div>

                            {/* Error or Summary */}
                            {enr.errorMessage && (
                              <p className="text-xs text-red-400 bg-red-950/40 p-2 rounded border border-red-800/50">
                                {enr.errorMessage}
                              </p>
                            )}

                            {enr.rawSummary && (
                              <div className="rounded bg-slate-900/80 p-2.5 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-40">
                                <pre>{JSON.stringify(enr.rawSummary, null, 2)}</pre>
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* TAB 3: FLEET CORRELATIONS */}
                  {detailTab === 'correlations' && (
                    <div className="space-y-5">
                      {/* Correlated Monitored Assets */}
                      <div>
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                          Correlated Monitored Assets ({detailIoc.correlations?.assets?.length || 0})
                        </h3>
                        {detailIoc.correlations?.assets?.length === 0 ? (
                          <div className="rounded-lg border border-slate-800/60 p-3 text-xs text-slate-500">
                            No internal inventory assets match this indicator IP or domain.
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {detailIoc.correlations.assets.map((ast) => (
                              <div
                                key={ast.id}
                                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs"
                              >
                                <div>
                                  <span className="font-bold text-white text-sm">{ast.name}</span>
                                  <span className="ml-2 font-mono text-cyan-400">{ast.ipAddress || ast.hostname}</span>
                                  <p className="text-slate-500 mt-0.5">{ast.matchReason}</p>
                                </div>
                                <span className={`badge ${getSeverityBadgeClass(ast.criticality)}`}>
                                  {ast.criticality}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Correlated Security Events */}
                      <div>
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                          Correlated Security Events ({detailIoc.correlations?.events?.length || 0})
                        </h3>
                        {detailIoc.correlations?.events?.length === 0 ? (
                          <div className="rounded-lg border border-slate-800/60 p-3 text-xs text-slate-500">
                            No security events reference this indicator.
                          </div>
                        ) : (
                          <div className="space-y-2 max-h-60 overflow-y-auto">
                            {detailIoc.correlations.events.map((evt) => (
                              <div
                                key={evt.id}
                                className="rounded-lg border border-slate-800 bg-slate-950/50 p-2.5 text-xs"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="font-mono font-semibold text-white">{evt.eventType}</span>
                                  <span className="text-slate-500">{formatLocalDate(evt.timestamp)}</span>
                                </div>
                                <p className="text-slate-400 mt-0.5">
                                  Src: {evt.srcIp || '—'} → Dst: {evt.dstIp || '—'} {evt.username ? `(${evt.username})` : ''}
                                </p>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Correlated Alerts */}
                      <div>
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                          Correlated Security Alerts ({detailIoc.correlations?.alerts?.length || 0})
                        </h3>
                        {detailIoc.correlations?.alerts?.length === 0 ? (
                          <div className="rounded-lg border border-slate-800/60 p-3 text-xs text-slate-500">
                            No security alerts correlate with this indicator.
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {detailIoc.correlations.alerts.map((alt) => (
                              <div
                                key={alt.id}
                                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs"
                              >
                                <div>
                                  <span className="font-bold text-white">{alt.title}</span>
                                  <p className="text-slate-500 mt-0.5">{formatLocalDate(alt.firedAt)}</p>
                                </div>
                                <span className={`badge ${getSeverityBadgeClass(alt.severity)}`}>
                                  {alt.severity}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* TAB 4: AUDIT TRAIL */}
                  {detailTab === 'audit' && (
                    <div className="space-y-3">
                      {detailIoc.auditLogs?.length === 0 ? (
                        <div className="py-8 text-center text-xs text-slate-500">
                          No audit entries recorded for this indicator.
                        </div>
                      ) : (
                        detailIoc.auditLogs.map((log) => (
                          <div
                            key={log.id}
                            className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-cyan-400">{log.action}</span>
                              <span className="text-slate-500">{formatLocalDate(log.timestamp)}</span>
                            </div>
                            <div className="mt-1 text-slate-400">
                              By: <span className="text-white font-medium">{log.user?.name || 'System / Service'}</span>{' '}
                              ({log.user?.role || 'N/A'})
                            </div>
                            {log.details && (
                              <div className="mt-2 rounded bg-slate-900 p-2 font-mono text-[11px] text-slate-300 overflow-x-auto">
                                <pre>{JSON.stringify(log.details, null, 2)}</pre>
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Register IOC Modal ──────────────────────────────────────────────── */}
      {createModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-cyan-400" />
                <h3 className="text-lg font-bold text-white">Register Threat Indicator</h3>
              </div>
              <button
                onClick={() => setCreateModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            {createError && (
              <div className="rounded-lg border border-red-800/80 bg-red-950/40 p-3 text-xs text-red-300">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-4">
                {/* Type */}
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Indicator Type</label>
                  <select
                    value={createForm.type}
                    onChange={(e) => setCreateForm({ ...createForm, type: e.target.value })}
                    className="select w-full"
                    required
                  >
                    <option value="IP">IP Address</option>
                    <option value="DOMAIN">Domain Name</option>
                    <option value="HASH">File Hash (MD5/SHA)</option>
                    <option value="URL">URL</option>
                  </select>
                </div>

                {/* Severity */}
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Severity</label>
                  <select
                    value={createForm.severity}
                    onChange={(e) => setCreateForm({ ...createForm, severity: e.target.value })}
                    className="select w-full"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              {/* Value */}
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Indicator Observable Value</label>
                <input
                  type="text"
                  placeholder={
                    createForm.type === 'IP'
                      ? 'e.g. 198.51.100.25'
                      : createForm.type === 'DOMAIN'
                      ? 'e.g. c2.malicious-domain.com'
                      : createForm.type === 'HASH'
                      ? 'e.g. 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
                      : 'e.g. https://evil.com/payload.exe'
                  }
                  value={createForm.value}
                  onChange={(e) => setCreateForm({ ...createForm, value: e.target.value })}
                  className="input w-full font-mono text-xs"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                {/* Confidence */}
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">
                    Confidence ({createForm.confidence}%)
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={createForm.confidence}
                    onChange={(e) => setCreateForm({ ...createForm, confidence: Number(e.target.value) })}
                    className="w-full accent-cyan-400 mt-2"
                  />
                </div>

                {/* Source */}
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Source Feeder</label>
                  <input
                    type="text"
                    value={createForm.source}
                    onChange={(e) => setCreateForm({ ...createForm, source: e.target.value })}
                    className="input w-full"
                    placeholder="e.g. AlienVault OTX, Internal Hunt"
                  />
                </div>
              </div>

              {/* Expiration */}
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Expiration Date (Optional)</label>
                <input
                  type="date"
                  value={createForm.expiresAt}
                  onChange={(e) => setCreateForm({ ...createForm, expiresAt: e.target.value })}
                  className="input w-full"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Analyst Description & Context</label>
                <textarea
                  rows={3}
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  className="textarea w-full"
                  placeholder="Record observed malicious tactics, campaign attribution, or malware families..."
                />
              </div>

              {/* Modal Actions */}
              <div className="flex items-center justify-end gap-2 border-t border-slate-800 pt-3">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="btn btn-secondary"
                  disabled={createSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createSubmitting}
                  className="btn btn-primary inline-flex items-center gap-1.5"
                >
                  {createSubmitting ? (
                    <>
                      <RefreshCw size={14} className="animate-spin" />
                      <span>Saving...</span>
                    </>
                  ) : (
                    <span>Register Indicator</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Edit IOC Modal ─────────────────────────────────────────────────── */}
      {editModalOpen && editIoc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Pencil className="h-5 w-5 text-cyan-400" />
                <h3 className="text-lg font-bold text-white">Edit Threat Indicator</h3>
              </div>
              <button
                onClick={() => setEditModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            {editError && (
              <div className="rounded-lg border border-red-800/80 bg-red-950/40 p-3 text-xs text-red-300">
                {editError}
              </div>
            )}

            <form onSubmit={handleEditSubmit} className="space-y-4 text-xs">
              <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800">
                <span className="text-slate-500 block uppercase font-semibold">Immutable Indicator</span>
                <span className="font-mono text-sm text-cyan-300 font-bold break-all">{editIoc.value}</span>
                <span className="ml-2 text-xs text-slate-400">({editIoc.type})</span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                {/* Severity */}
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Severity</label>
                  <select
                    value={editForm.severity}
                    onChange={(e) => setEditForm({ ...editForm, severity: e.target.value })}
                    className="select w-full"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                {/* Status */}
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Status</label>
                  <select
                    value={editForm.status}
                    onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
                    className="select w-full"
                  >
                    <option value="ACTIVE">ACTIVE</option>
                    <option value="INACTIVE">INACTIVE</option>
                    <option value="EXPIRED">EXPIRED</option>
                    <option value="REVOKED">REVOKED</option>
                  </select>
                </div>
              </div>

              {/* Confidence */}
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">
                  Confidence ({editForm.confidence}%)
                </label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={editForm.confidence}
                  onChange={(e) => setEditForm({ ...editForm, confidence: Number(e.target.value) })}
                  className="w-full accent-cyan-400 mt-2"
                />
              </div>

              {/* Expiration */}
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Expiration Date</label>
                <input
                  type="date"
                  value={editForm.expiresAt}
                  onChange={(e) => setEditForm({ ...editForm, expiresAt: e.target.value })}
                  className="input w-full"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Analyst Notes</label>
                <textarea
                  rows={3}
                  value={editForm.description}
                  onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                  className="textarea w-full"
                />
              </div>

              {/* Modal Actions */}
              <div className="flex items-center justify-end gap-2 border-t border-slate-800 pt-3">
                <button
                  type="button"
                  onClick={() => setEditModalOpen(false)}
                  className="btn btn-secondary"
                  disabled={editSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editSubmitting}
                  className="btn btn-primary inline-flex items-center gap-1.5"
                >
                  {editSubmitting ? (
                    <>
                      <RefreshCw size={14} className="animate-spin" />
                      <span>Updating...</span>
                    </>
                  ) : (
                    <span>Save Changes</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Permanent Delete Modal ─────────────────────────────────────────── */}
      {deleteModalOpen && deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-red-800/80 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-red-400">
              <AlertCircle size={24} />
              <h3 className="text-lg font-bold text-white">Permanently Delete Indicator</h3>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to permanently delete indicator{' '}
              <strong className="font-mono text-cyan-300">{deleteTarget.value}</strong>?
              This will remove the indicator and its historical enrichment observations.
              This action cannot be undone.
            </p>

            <div className="flex items-center justify-end gap-2 border-t border-slate-800 pt-3">
              <button
                type="button"
                onClick={() => setDeleteModalOpen(false)}
                className="btn btn-secondary"
                disabled={deleteSubmitting}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteConfirm}
                disabled={deleteSubmitting}
                className="btn bg-red-600 hover:bg-red-500 text-white text-xs font-semibold px-4 py-2 rounded-lg"
              >
                {deleteSubmitting ? 'Deleting...' : 'Permanently Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
