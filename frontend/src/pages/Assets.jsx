// src/pages/Assets.jsx
// Asset Management UI for SOC Lite (Phase 8).
// Comprehensive host inventory, registration, detail drawer, editing,
// decommissioning, audit timeline, and RBAC enforcement.

import { useState, useEffect, useCallback } from 'react';
import {
  Server,
  Plus,
  Search,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  PowerOff,
  ShieldAlert,
  Pencil,
  Trash2,
  X,
  ChevronLeft,
  ChevronRight,
  Lock,
  Info,
  History,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import {
  getAssetsApi,
  getAssetStatsApi,
  getAssetByIdApi,
  createAssetApi,
  updateAssetApi,
  decommissionAssetApi,
  deleteAssetApi,
} from '../api/assets.api';

// ── Design helpers ─────────────────────────────────────────────────────────

function getCriticalityBadgeClass(crit) {
  switch (crit) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH':     return 'badge-high';
    case 'MEDIUM':   return 'badge-medium';
    case 'LOW':      return 'badge-low';
    default:         return 'badge-info';
  }
}

function getStatusBadgeClass(status) {
  switch (status) {
    case 'ACTIVE':         return 'badge-low';
    case 'INACTIVE':       return 'badge-medium';
    case 'DECOMMISSIONED': return 'badge-critical';
    default:               return 'badge-info';
  }
}

function formatLocalDate(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function formatLocalDateTime(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const ASSET_TYPES = [
  'SERVER',
  'WORKSTATION',
  'LAPTOP',
  'FIREWALL',
  'ROUTER',
  'SWITCH',
  'CLOUD_INSTANCE',
  'OTHER',
];

const ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'LAB', 'OTHER'];
const CRITICALITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES = ['ACTIVE', 'INACTIVE', 'DECOMMISSIONED'];

export default function Assets() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'ADMIN';
  const canMutate = ['ADMIN', 'ANALYST'].includes(user?.role);

  // ── Inventory & Stats State ──────────────────────────────────────────────
  const [assets, setAssets] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    active: 0,
    inactive: 0,
    decommissioned: 0,
    critical: 0,
  });
  const [pagination, setPagination] = useState({ page: 1, limit: 10, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [successToast, setSuccessToast] = useState('');

  // ── Filters & Search ─────────────────────────────────────────────────────
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [criticalityFilter, setCriticalityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [envFilter, setEnvFilter] = useState('');

  // ── Modals & Drawer State ────────────────────────────────────────────────
  const [selectedAssetId, setSelectedAssetId] = useState(null);
  const [detailAsset, setDetailAsset] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [drawerTab, setDrawerTab] = useState('overview'); // 'overview' | 'audit'

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState('');
  const [createForm, setCreateForm] = useState({
    name: '',
    hostname: '',
    ipAddress: '',
    type: 'SERVER',
    status: 'ACTIVE',
    criticality: 'MEDIUM',
    environment: 'PRODUCTION',
    operatingSystem: '',
    owner: '',
    description: '',
    tagsString: '',
  });

  const [editAsset, setEditAsset] = useState(null);
  const [editSubmitting, setEditSubmitting] = useState(false);
  const [editError, setEditError] = useState('');
  const [editForm, setEditForm] = useState({
    name: '',
    hostname: '',
    ipAddress: '',
    type: 'SERVER',
    status: 'ACTIVE',
    criticality: 'MEDIUM',
    environment: 'PRODUCTION',
    operatingSystem: '',
    owner: '',
    description: '',
    tagsString: '',
  });

  const [confirmModal, setConfirmModal] = useState({
    isOpen: false,
    title: '',
    message: '',
    actionType: '', // 'decommission' | 'delete'
    asset: null,
    submitting: false,
  });

  // ── Debounce Search ──────────────────────────────────────────────────────
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPagination((prev) => ({ ...prev, page: 1 }));
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  // ── Toast dismiss timer ──────────────────────────────────────────────────
  useEffect(() => {
    if (!successToast) return;
    const t = setTimeout(() => setSuccessToast(''), 4000);
    return () => clearTimeout(t);
  }, [successToast]);

  // ── Fetch Inventory ──────────────────────────────────────────────────────
  const fetchAssets = useCallback(
    async (pageToLoad = 1) => {
      setError('');
      try {
        const params = {
          page: pageToLoad,
          limit: pagination.limit,
          ...(debouncedSearch.trim() && { search: debouncedSearch.trim() }),
          ...(statusFilter && { status: statusFilter }),
          ...(criticalityFilter && { criticality: criticalityFilter }),
          ...(typeFilter && { type: typeFilter }),
          ...(envFilter && { environment: envFilter }),
        };

        const res = await getAssetsApi(params);
        if (res?.success) {
          setAssets(res.data || []);
          if (res.pagination) {
            setPagination((p) => ({
              ...p,
              page: res.pagination.page,
              total: res.pagination.total,
              totalPages: res.pagination.totalPages,
            }));
          }
        } else {
          setError(res?.error || 'Failed to load asset inventory.');
        }
      } catch (err) {
        setError(err.response?.data?.error || err.message || 'Error loading assets.');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [pagination.limit, debouncedSearch, statusFilter, criticalityFilter, typeFilter, envFilter]
  );

  // ── Fetch Stats ──────────────────────────────────────────────────────────
  const fetchStats = useCallback(async () => {
    try {
      const res = await getAssetStatsApi();
      if (res?.success && res.data) {
        setStats(res.data);
      }
    } catch {
      // Keep existing stats silently
    }
  }, []);

  // Initial load and filter change trigger
  useEffect(() => {
    let active = true;
    async function load() {
      if (active) {
        await fetchAssets(pagination.page);
        await fetchStats();
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [fetchAssets, fetchStats, pagination.page]);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchAssets(pagination.page);
    fetchStats();
  };

  const handleResetFilters = () => {
    setSearch('');
    setDebouncedSearch('');
    setStatusFilter('');
    setCriticalityFilter('');
    setTypeFilter('');
    setEnvFilter('');
    setPagination((p) => ({ ...p, page: 1 }));
  };

  // ── Open Detail Drawer ───────────────────────────────────────────────────
  const openDrawer = useCallback(async (id) => {
    setSelectedAssetId(id);
    setDetailLoading(true);
    setDetailError('');
    setDetailAsset(null);
    setDrawerTab('overview');

    try {
      const res = await getAssetByIdApi(id);
      if (res?.success && res.data) {
        setDetailAsset(res.data);
      } else {
        setDetailError(res?.error || 'Unable to load asset details.');
      }
    } catch (err) {
      setDetailError(err.response?.data?.error || err.message || 'Failed to load asset.');
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeDrawer = () => {
    setSelectedAssetId(null);
    setDetailAsset(null);
    setDetailError('');
  };

  // ── Create Asset Modal ───────────────────────────────────────────────────
  const openCreateModal = () => {
    setCreateForm({
      name: '',
      hostname: '',
      ipAddress: '',
      type: 'SERVER',
      status: 'ACTIVE',
      criticality: 'MEDIUM',
      environment: 'PRODUCTION',
      operatingSystem: '',
      owner: '',
      description: '',
      tagsString: '',
    });
    setCreateError('');
    setShowCreateModal(true);
  };

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    if (createSubmitting) return;

    if (!createForm.name.trim()) {
      setCreateError('Asset Name is required.');
      return;
    }

    setCreateSubmitting(true);
    setCreateError('');

    try {
      const tags = createForm.tagsString
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter((t) => t.length > 0);

      const payload = {
        name: createForm.name.trim(),
        ...(createForm.hostname.trim() && { hostname: createForm.hostname.trim() }),
        ...(createForm.ipAddress.trim() && { ipAddress: createForm.ipAddress.trim() }),
        type: createForm.type,
        status: createForm.status,
        criticality: createForm.criticality,
        ...(createForm.environment && { environment: createForm.environment }),
        ...(createForm.operatingSystem.trim() && { operatingSystem: createForm.operatingSystem.trim() }),
        ...(createForm.owner.trim() && { owner: createForm.owner.trim() }),
        ...(createForm.description.trim() && { description: createForm.description.trim() }),
        ...(tags.length > 0 && { tags }),
      };

      const res = await createAssetApi(payload);
      if (res?.success) {
        setSuccessToast(`Asset "${res.data.name}" registered successfully.`);
        setShowCreateModal(false);
        fetchAssets(1);
        fetchStats();
      } else {
        setCreateError(res?.error || 'Failed to create asset.');
      }
    } catch (err) {
      setCreateError(err.response?.data?.error || err.message || 'Registration failed.');
    } finally {
      setCreateSubmitting(false);
    }
  };

  // ── Edit Asset Modal ─────────────────────────────────────────────────────
  const openEditModal = (asset) => {
    setEditAsset(asset);
    setEditForm({
      name: asset.name || '',
      hostname: asset.hostname || '',
      ipAddress: asset.ipAddress || '',
      type: asset.type || 'SERVER',
      status: asset.status || 'ACTIVE',
      criticality: asset.criticality || 'MEDIUM',
      environment: asset.environment || 'PRODUCTION',
      operatingSystem: asset.operatingSystem || '',
      owner: asset.owner || '',
      description: asset.description || '',
      tagsString: Array.isArray(asset.tags) ? asset.tags.join(', ') : '',
    });
    setEditError('');
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    if (editSubmitting || !editAsset) return;

    if (!editForm.name.trim()) {
      setEditError('Asset Name is required.');
      return;
    }

    setEditSubmitting(true);
    setEditError('');

    try {
      const tags = editForm.tagsString
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter((t) => t.length > 0);

      const payload = {
        name: editForm.name.trim(),
        hostname: editForm.hostname.trim() || null,
        ipAddress: editForm.ipAddress.trim() || null,
        type: editForm.type,
        status: editForm.status,
        criticality: editForm.criticality,
        environment: editForm.environment || null,
        operatingSystem: editForm.operatingSystem.trim() || null,
        owner: editForm.owner.trim() || null,
        description: editForm.description.trim() || null,
        tags,
      };

      const res = await updateAssetApi(editAsset.id, payload);
      if (res?.success) {
        setSuccessToast(`Asset "${res.data.name}" updated successfully.`);
        setEditAsset(null);
        fetchAssets(pagination.page);
        fetchStats();
        if (selectedAssetId === editAsset.id) {
          openDrawer(editAsset.id);
        }
      } else {
        setEditError(res?.error || 'Failed to update asset.');
      }
    } catch (err) {
      setEditError(err.response?.data?.error || err.message || 'Update failed.');
    } finally {
      setEditSubmitting(false);
    }
  };

  // ── Confirmation Modal (Decommission / Delete) ───────────────────────────
  const openConfirmModal = (actionType, asset) => {
    if (actionType === 'decommission') {
      setConfirmModal({
        isOpen: true,
        actionType: 'decommission',
        asset,
        title: `Decommission Asset: ${asset.name}`,
        message:
          'Are you sure you want to decommission this asset? Its status will be updated to DECOMMISSIONED while preserving all historical audit records.',
        submitting: false,
      });
    } else if (actionType === 'delete') {
      setConfirmModal({
        isOpen: true,
        actionType: 'delete',
        asset,
        title: `Permanently Delete Asset: ${asset.name}`,
        message:
          'Warning: This action will permanently remove the asset record from the inventory. An audit log entry will record the deletion. This action cannot be undone.',
        submitting: false,
      });
    }
  };

  const handleConfirmAction = async () => {
    const { actionType, asset } = confirmModal;
    if (!asset) return;

    setConfirmModal((prev) => ({ ...prev, submitting: true }));

    try {
      if (actionType === 'decommission') {
        const res = await decommissionAssetApi(asset.id);
        if (res?.success) {
          setSuccessToast(`Asset "${asset.name}" has been decommissioned.`);
          setConfirmModal({ isOpen: false, asset: null, actionType: '', title: '', message: '', submitting: false });
          fetchAssets(pagination.page);
          fetchStats();
          if (selectedAssetId === asset.id) openDrawer(asset.id);
        }
      } else if (actionType === 'delete') {
        const res = await deleteAssetApi(asset.id);
        if (res?.success) {
          setSuccessToast(`Asset "${asset.name}" was permanently deleted.`);
          setConfirmModal({ isOpen: false, asset: null, actionType: '', title: '', message: '', submitting: false });
          if (selectedAssetId === asset.id) closeDrawer();
          fetchAssets(pagination.page);
          fetchStats();
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Action failed.');
      setConfirmModal((prev) => ({ ...prev, submitting: false }));
    }
  };

  return (
    <div className="fade-in">
      {/* ── Success Toast ─────────────────────────────────────────────────── */}
      {successToast && (
        <div
          style={{
            position: 'fixed',
            top: 70,
            right: 24,
            zIndex: 9999,
            background: 'var(--color-bg-elevated)',
            border: '1px solid var(--color-accent)',
            borderRadius: 'var(--radius-card)',
            padding: '0.75rem 1.25rem',
            color: 'var(--color-accent)',
            boxShadow: 'var(--shadow-glow)',
            fontSize: '13px',
            fontWeight: 500,
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
          }}
        >
          <CheckCircle2 size={16} color="var(--color-accent)" />
          {successToast}
        </div>
      )}

      {/* ── Header ────────────────────────────────────────────────────────── */}
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
            <Server size={24} color="var(--color-accent)" />
            Asset Management
          </h1>
          <p className="page-subtitle">
            Monitored endpoints, servers, network hardware, and security infrastructure.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={handleManualRefresh}
            disabled={refreshing}
            style={{ fontSize: '13px' }}
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>

          {canMutate && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={openCreateModal}
              style={{ fontSize: '13px' }}
            >
              <Plus size={15} />
              Register Asset
            </button>
          )}
        </div>
      </div>

      {/* ── KPI Metric Cards ──────────────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          marginBottom: '1.5rem',
        }}
      >
        {/* Total Assets */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              TOTAL ASSETS
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
              <Server size={16} color="var(--color-accent)" />
            </div>
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            {stats.total.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
            Registered infrastructure devices
          </div>
        </div>

        {/* Active Assets */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              ACTIVE ASSETS
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
              <CheckCircle2 size={16} color="var(--color-accent)" />
            </div>
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-accent)' }}>
            {stats.active.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
            Actively monitored in production
          </div>
        </div>

        {/* Inactive & Decommissioned */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              INACTIVE / DECOMMISSIONED
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
              <PowerOff size={16} color="var(--color-medium)" />
            </div>
          </div>
          <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--color-medium)' }}>
            {(stats.inactive + stats.decommissioned).toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
            {stats.inactive} inactive, {stats.decommissioned} decommissioned
          </div>
        </div>

        {/* Critical Assets */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              CRITICAL INFRASTRUCTURE
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
            {stats.critical.toLocaleString()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
            High-value business impact assets
          </div>
        </div>
      </div>

      {/* ── Error Banner ──────────────────────────────────────────────────── */}
      {error && (
        <div
          style={{
            background: 'rgba(255, 59, 59, 0.1)',
            border: '1px solid rgba(255, 59, 59, 0.3)',
            borderRadius: 'var(--radius-card)',
            padding: '1rem',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <AlertCircle size={20} color="var(--color-critical)" />
            <span style={{ color: 'var(--color-critical)', fontSize: '13px' }}>{error}</span>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => fetchAssets(pagination.page)}
            style={{ fontSize: '12px', padding: '0.35rem 0.8rem' }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Search & Filter Controls ──────────────────────────────────────── */}
      <div
        className="card"
        style={{
          padding: '1rem 1.25rem',
          marginBottom: '1.25rem',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: '0.75rem',
        }}
      >
        {/* Search Bar */}
        <div style={{ flex: '1 1 240px', position: 'relative' }}>
          <Search
            size={15}
            color="var(--color-text-muted)"
            style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }}
          />
          <input
            type="text"
            placeholder="Search name, hostname, IP, owner…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              background: 'var(--color-bg-base)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              padding: '0.45rem 0.75rem 0.45rem 2rem',
              color: 'var(--color-text-primary)',
              fontSize: '13px',
              outline: 'none',
            }}
          />
        </div>

        {/* Status Dropdown */}
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPagination((p) => ({ ...p, page: 1 }));
          }}
          style={{
            background: 'var(--color-bg-base)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            padding: '0.45rem 0.75rem',
            color: 'var(--color-text-primary)',
            fontSize: '12.5px',
            outline: 'none',
            cursor: 'pointer',
          }}
        >
          <option value="">All Statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        {/* Criticality Dropdown */}
        <select
          value={criticalityFilter}
          onChange={(e) => {
            setCriticalityFilter(e.target.value);
            setPagination((p) => ({ ...p, page: 1 }));
          }}
          style={{
            background: 'var(--color-bg-base)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            padding: '0.45rem 0.75rem',
            color: 'var(--color-text-primary)',
            fontSize: '12.5px',
            outline: 'none',
            cursor: 'pointer',
          }}
        >
          <option value="">All Criticalities</option>
          {CRITICALITIES.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>

        {/* Asset Type Dropdown */}
        <select
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value);
            setPagination((p) => ({ ...p, page: 1 }));
          }}
          style={{
            background: 'var(--color-bg-base)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            padding: '0.45rem 0.75rem',
            color: 'var(--color-text-primary)',
            fontSize: '12.5px',
            outline: 'none',
            cursor: 'pointer',
          }}
        >
          <option value="">All Types</option>
          {ASSET_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        {/* Environment Dropdown */}
        <select
          value={envFilter}
          onChange={(e) => {
            setEnvFilter(e.target.value);
            setPagination((p) => ({ ...p, page: 1 }));
          }}
          style={{
            background: 'var(--color-bg-base)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            padding: '0.45rem 0.75rem',
            color: 'var(--color-text-primary)',
            fontSize: '12.5px',
            outline: 'none',
            cursor: 'pointer',
          }}
        >
          <option value="">All Environments</option>
          {ENVIRONMENTS.map((env) => (
            <option key={env} value={env}>{env}</option>
          ))}
        </select>

        {/* Reset Button */}
        {(search || statusFilter || criticalityFilter || typeFilter || envFilter) && (
          <button
            type="button"
            className="btn btn-ghost"
            onClick={handleResetFilters}
            style={{ fontSize: '12px', padding: '0.45rem 0.75rem' }}
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* ── Asset Inventory Table ─────────────────────────────────────────── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr
                style={{
                  background: 'var(--color-bg-surface)',
                  borderBottom: '1px solid var(--color-border)',
                  color: 'var(--color-text-muted)',
                  fontSize: '11px',
                  textAlign: 'left',
                }}
              >
                <th style={{ padding: '0.75rem 1rem' }}>ASSET NAME</th>
                <th style={{ padding: '0.75rem 1rem' }}>IP ADDRESS</th>
                <th style={{ padding: '0.75rem 1rem' }}>HOSTNAME</th>
                <th style={{ padding: '0.75rem 1rem' }}>TYPE</th>
                <th style={{ padding: '0.75rem 1rem' }}>STATUS</th>
                <th style={{ padding: '0.75rem 1rem' }}>CRITICALITY</th>
                <th style={{ padding: '0.75rem 1rem' }}>ENVIRONMENT</th>
                <th style={{ padding: '0.75rem 1rem' }}>OWNER</th>
                <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>UPDATED</th>
                <th style={{ padding: '0.75rem 1rem', textAlign: 'center' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={10} style={{ padding: '3rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                    <RefreshCw size={22} className="animate-spin" style={{ margin: '0 auto 0.5rem' }} />
                    Loading asset inventory…
                  </td>
                </tr>
              ) : assets.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{ padding: '3.5rem 1rem', textAlign: 'center' }}>
                    <Server size={32} color="var(--color-border)" style={{ margin: '0 auto 0.75rem' }} />
                    <p style={{ margin: '0 0 0.5rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      No assets found
                    </p>
                    <p style={{ margin: 0, fontSize: '12px', color: 'var(--color-text-muted)' }}>
                      {search || statusFilter || criticalityFilter || typeFilter || envFilter
                        ? 'Try clearing or modifying your filter criteria.'
                        : 'Register an asset to start tracking monitored infrastructure.'}
                    </p>
                  </td>
                </tr>
              ) : (
                assets.map((asset) => (
                  <tr
                    key={asset.id}
                    onClick={() => openDrawer(asset.id)}
                    style={{
                      borderBottom: '1px solid var(--color-border-subtle)',
                      cursor: 'pointer',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--color-bg-elevated)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                  >
                    {/* Name */}
                    <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ color: 'var(--color-accent)' }}>{asset.name}</span>
                      </div>
                    </td>

                    {/* IP Address */}
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      {asset.ipAddress ? (
                        <span style={{ color: 'var(--color-text-secondary)' }}>{asset.ipAddress}</span>
                      ) : (
                        <span style={{ color: 'var(--color-text-muted)' }}>—</span>
                      )}
                    </td>

                    {/* Hostname */}
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--color-text-secondary)', fontSize: '12px' }}>
                      {asset.hostname || '—'}
                    </td>

                    {/* Type */}
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span
                        style={{
                          background: 'var(--color-bg-surface)',
                          border: '1px solid var(--color-border)',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 500,
                          color: 'var(--color-text-secondary)',
                        }}
                      >
                        {asset.type}
                      </span>
                    </td>

                    {/* Status */}
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span className={`badge ${getStatusBadgeClass(asset.status)}`}>
                        {asset.status}
                      </span>
                    </td>

                    {/* Criticality */}
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span className={`badge ${getCriticalityBadgeClass(asset.criticality)}`}>
                        {asset.criticality}
                      </span>
                    </td>

                    {/* Environment */}
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--color-text-secondary)', fontSize: '12px' }}>
                      {asset.environment || '—'}
                    </td>

                    {/* Owner */}
                    <td style={{ padding: '0.75rem 1rem', color: 'var(--color-text-secondary)', fontSize: '12px' }}>
                      {asset.owner || '—'}
                    </td>

                    {/* Updated At */}
                    <td style={{ padding: '0.75rem 1rem', textAlign: 'right', color: 'var(--color-text-muted)', fontSize: '11.5px', whiteSpace: 'nowrap' }}>
                      {formatLocalDate(asset.updatedAt)}
                    </td>

                    {/* Actions */}
                    <td
                      style={{ padding: '0.75rem 1rem', textAlign: 'center' }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                        {canMutate && (
                          <button
                            type="button"
                            title="Edit Asset"
                            onClick={() => openEditModal(asset)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: 'var(--color-text-secondary)',
                              cursor: 'pointer',
                              padding: '4px',
                              borderRadius: '4px',
                            }}
                          >
                            <Pencil size={14} />
                          </button>
                        )}

                        {canMutate && asset.status !== 'DECOMMISSIONED' && (
                          <button
                            type="button"
                            title="Decommission Asset"
                            onClick={() => openConfirmModal('decommission', asset)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: 'var(--color-medium)',
                              cursor: 'pointer',
                              padding: '4px',
                              borderRadius: '4px',
                            }}
                          >
                            <PowerOff size={14} />
                          </button>
                        )}

                        {isAdmin && (
                          <button
                            type="button"
                            title="Delete Asset"
                            onClick={() => openConfirmModal('delete', asset)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: 'var(--color-critical)',
                              cursor: 'pointer',
                              padding: '4px',
                              borderRadius: '4px',
                            }}
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* ── Table Pagination ──────────────────────────────────────────────── */}
        <div
          style={{
            padding: '0.75rem 1.25rem',
            borderTop: '1px solid var(--color-border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            color: 'var(--color-text-muted)',
          }}
        >
          <div>
            Showing {assets.length > 0 ? (pagination.page - 1) * pagination.limit + 1 : 0} to{' '}
            {Math.min(pagination.page * pagination.limit, pagination.total)} of {pagination.total} assets
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={pagination.page <= 1}
              onClick={() => setPagination((p) => ({ ...p, page: p.page - 1 }))}
              style={{ padding: '0.3rem 0.6rem', fontSize: '11px' }}
            >
              <ChevronLeft size={13} /> Previous
            </button>
            <span style={{ color: 'var(--color-text-secondary)', fontWeight: 500 }}>
              Page {pagination.page} of {pagination.totalPages}
            </span>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={pagination.page >= pagination.totalPages}
              onClick={() => setPagination((p) => ({ ...p, page: p.page + 1 }))}
              style={{ padding: '0.3rem 0.6rem', fontSize: '11px' }}
            >
              Next <ChevronRight size={13} />
            </button>
          </div>
        </div>
      </div>

      {/* ── Register Asset Modal ──────────────────────────────────────────── */}
      {showCreateModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1000,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
        >
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: 580,
              maxHeight: '90vh',
              overflowY: 'auto',
              background: 'var(--color-bg-card)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-card)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '1rem',
                borderBottom: '1px solid var(--color-border-subtle)',
                paddingBottom: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Server size={18} color="var(--color-accent)" />
                <span style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Register New Asset
                </span>
              </div>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            {createError && (
              <div
                style={{
                  background: 'rgba(255, 59, 59, 0.1)',
                  border: '1px solid rgba(255, 59, 59, 0.3)',
                  borderRadius: '6px',
                  padding: '0.6rem 0.8rem',
                  color: 'var(--color-critical)',
                  fontSize: '12px',
                  marginBottom: '1rem',
                }}
              >
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                {/* Asset Name */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    ASSET NAME *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. DC-01, WEB-PROD-01"
                    value={createForm.name}
                    onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  />
                </div>

                {/* Hostname */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    HOSTNAME (OPTIONAL)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. dc01.internal.corp"
                    value={createForm.hostname}
                    onChange={(e) => setCreateForm({ ...createForm, hostname: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                {/* IP Address */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    IP ADDRESS (IPV4/IPV6)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. 10.0.0.1"
                    value={createForm.ipAddress}
                    onChange={(e) => setCreateForm({ ...createForm, ipAddress: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                      fontFamily: 'var(--font-mono)',
                    }}
                  />
                </div>

                {/* Asset Type */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    ASSET TYPE
                  </label>
                  <select
                    value={createForm.type}
                    onChange={(e) => setCreateForm({ ...createForm, type: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {ASSET_TYPES.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                {/* Criticality */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    CRITICALITY
                  </label>
                  <select
                    value={createForm.criticality}
                    onChange={(e) => setCreateForm({ ...createForm, criticality: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {CRITICALITIES.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>

                {/* Status */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    STATUS
                  </label>
                  <select
                    value={createForm.status}
                    onChange={(e) => setCreateForm({ ...createForm, status: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                {/* Environment */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    ENVIRONMENT
                  </label>
                  <select
                    value={createForm.environment}
                    onChange={(e) => setCreateForm({ ...createForm, environment: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {ENVIRONMENTS.map((env) => (
                      <option key={env} value={env}>{env}</option>
                    ))}
                  </select>
                </div>

                {/* Operating System */}
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    OPERATING SYSTEM
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Ubuntu 24.04, Windows Server 2022"
                    value={createForm.operatingSystem}
                    onChange={(e) => setCreateForm({ ...createForm, operatingSystem: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  />
                </div>
              </div>

              {/* Owner / Team */}
              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                  OWNER / RESPONSIBLE TEAM
                </label>
                <input
                  type="text"
                  placeholder="e.g. IT Infrastructure, CloudSec, DevOps"
                  value={createForm.owner}
                  onChange={(e) => setCreateForm({ ...createForm, owner: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.6rem',
                    color: 'var(--color-text-primary)',
                    fontSize: '12.5px',
                  }}
                />
              </div>

              {/* Tags */}
              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                  TAGS (COMMA SEPARATED)
                </label>
                <input
                  type="text"
                  placeholder="e.g. dmz, production, pci-dss, nginx"
                  value={createForm.tagsString}
                  onChange={(e) => setCreateForm({ ...createForm, tagsString: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.6rem',
                    color: 'var(--color-text-primary)',
                    fontSize: '12.5px',
                  }}
                />
              </div>

              {/* Description */}
              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                  DESCRIPTION
                </label>
                <textarea
                  rows={2}
                  placeholder="Purpose, location, notes…"
                  value={createForm.description}
                  onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.6rem',
                    color: 'var(--color-text-primary)',
                    fontSize: '12.5px',
                    resize: 'vertical',
                  }}
                />
              </div>

              <div
                style={{
                  display: 'flex',
                  justifyContent: 'flex-end',
                  gap: '0.75rem',
                  marginTop: '0.5rem',
                  borderTop: '1px solid var(--color-border-subtle)',
                  paddingTop: '0.75rem',
                }}
              >
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setShowCreateModal(false)}
                  disabled={createSubmitting}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={createSubmitting}>
                  {createSubmitting ? 'Registering…' : 'Register Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Edit Asset Modal ────────────────────────────────────────────── */}
      {editAsset && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1000,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
        >
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: 580,
              maxHeight: '90vh',
              overflowY: 'auto',
              background: 'var(--color-bg-card)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-card)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '1rem',
                borderBottom: '1px solid var(--color-border-subtle)',
                paddingBottom: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Pencil size={18} color="var(--color-accent)" />
                <span style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Edit Asset: {editAsset.name}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setEditAsset(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            {editError && (
              <div
                style={{
                  background: 'rgba(255, 59, 59, 0.1)',
                  border: '1px solid rgba(255, 59, 59, 0.3)',
                  borderRadius: '6px',
                  padding: '0.6rem 0.8rem',
                  color: 'var(--color-critical)',
                  fontSize: '12px',
                  marginBottom: '1rem',
                }}
              >
                {editError}
              </div>
            )}

            <form onSubmit={handleEditSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    ASSET NAME *
                  </label>
                  <input
                    type="text"
                    required
                    value={editForm.name}
                    onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    HOSTNAME
                  </label>
                  <input
                    type="text"
                    value={editForm.hostname}
                    onChange={(e) => setEditForm({ ...editForm, hostname: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    IP ADDRESS
                  </label>
                  <input
                    type="text"
                    value={editForm.ipAddress}
                    onChange={(e) => setEditForm({ ...editForm, ipAddress: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                      fontFamily: 'var(--font-mono)',
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    ASSET TYPE
                  </label>
                  <select
                    value={editForm.type}
                    onChange={(e) => setEditForm({ ...editForm, type: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {ASSET_TYPES.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    CRITICALITY
                  </label>
                  <select
                    value={editForm.criticality}
                    onChange={(e) => setEditForm({ ...editForm, criticality: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {CRITICALITIES.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    STATUS
                  </label>
                  <select
                    value={editForm.status}
                    onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    ENVIRONMENT
                  </label>
                  <select
                    value={editForm.environment}
                    onChange={(e) => setEditForm({ ...editForm, environment: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    {ENVIRONMENTS.map((env) => (
                      <option key={env} value={env}>{env}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                    OPERATING SYSTEM
                  </label>
                  <input
                    type="text"
                    value={editForm.operatingSystem}
                    onChange={(e) => setEditForm({ ...editForm, operatingSystem: e.target.value })}
                    style={{
                      width: '100%',
                      background: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.6rem',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                  OWNER / TEAM
                </label>
                <input
                  type="text"
                  value={editForm.owner}
                  onChange={(e) => setEditForm({ ...editForm, owner: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.6rem',
                    color: 'var(--color-text-primary)',
                    fontSize: '12.5px',
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                  TAGS (COMMA SEPARATED)
                </label>
                <input
                  type="text"
                  value={editForm.tagsString}
                  onChange={(e) => setEditForm({ ...editForm, tagsString: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.6rem',
                    color: 'var(--color-text-primary)',
                    fontSize: '12.5px',
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, color: 'var(--color-text-muted)', marginBottom: 4 }}>
                  DESCRIPTION
                </label>
                <textarea
                  rows={2}
                  value={editForm.description}
                  onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                  style={{
                    width: '100%',
                    background: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.6rem',
                    color: 'var(--color-text-primary)',
                    fontSize: '12.5px',
                    resize: 'vertical',
                  }}
                />
              </div>

              <div
                style={{
                  display: 'flex',
                  justifyContent: 'flex-end',
                  gap: '0.75rem',
                  marginTop: '0.5rem',
                  borderTop: '1px solid var(--color-border-subtle)',
                  paddingTop: '0.75rem',
                }}
              >
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setEditAsset(null)}
                  disabled={editSubmitting}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={editSubmitting}>
                  {editSubmitting ? 'Saving…' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Asset Detail Drawer ─────────────────────────────────────────── */}
      {selectedAssetId && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 900,
            background: 'rgba(0,0,0,0.5)',
            display: 'flex',
            justifyContent: 'flex-end',
          }}
          onClick={closeDrawer}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: 520,
              height: '100%',
              background: 'var(--color-bg-surface)',
              borderLeft: '1px solid var(--color-border)',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: 'var(--shadow-card)',
            }}
          >
            {/* Drawer Header */}
            <div
              style={{
                padding: '1.25rem',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                background: 'var(--color-bg-card)',
              }}
            >
              <div>
                <div style={{ fontSize: '11px', color: 'var(--color-accent)', fontWeight: 600, textTransform: 'uppercase' }}>
                  ASSET RECORD
                </div>
                <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                  {detailAsset?.name || 'Loading Asset…'}
                </h2>
              </div>
              <button
                type="button"
                onClick={closeDrawer}
                style={{ background: 'transparent', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Read-only notification for VIEWERS */}
            {!canMutate && (
              <div
                style={{
                  background: 'rgba(91, 155, 213, 0.1)',
                  borderBottom: '1px solid rgba(91, 155, 213, 0.25)',
                  padding: '0.6rem 1.25rem',
                  fontSize: '12px',
                  color: 'var(--color-info)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <Lock size={13} />
                <span>Read-only mode (VIEWER role). Asset modifications are restricted.</span>
              </div>
            )}

            {/* Drawer Tabs */}
            <div
              style={{
                display: 'flex',
                borderBottom: '1px solid var(--color-border)',
                background: 'var(--color-bg-base)',
              }}
            >
              <button
                type="button"
                onClick={() => setDrawerTab('overview')}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  background: 'transparent',
                  border: 'none',
                  borderBottom: drawerTab === 'overview' ? '2px solid var(--color-accent)' : 'none',
                  color: drawerTab === 'overview' ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.4rem',
                }}
              >
                <Info size={14} /> Overview
              </button>
              <button
                type="button"
                onClick={() => setDrawerTab('audit')}
                style={{
                  flex: 1,
                  padding: '0.75rem',
                  background: 'transparent',
                  border: 'none',
                  borderBottom: drawerTab === 'audit' ? '2px solid var(--color-accent)' : 'none',
                  color: drawerTab === 'audit' ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                  fontWeight: 600,
                  fontSize: '13px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.4rem',
                }}
              >
                <History size={14} /> Audit Timeline ({detailAsset?.timeline?.length || 0})
              </button>
            </div>

            {/* Drawer Content */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '1.25rem' }}>
              {detailLoading ? (
                <div style={{ padding: '3rem 1rem', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                  <RefreshCw size={22} className="animate-spin" style={{ margin: '0 auto 0.5rem' }} />
                  Loading details…
                </div>
              ) : detailError ? (
                <div style={{ color: 'var(--color-critical)', fontSize: '13px' }}>{detailError}</div>
              ) : detailAsset ? (
                drawerTab === 'overview' ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                    {/* Status & Criticality Badges */}
                    <div style={{ display: 'flex', gap: '0.6rem' }}>
                      <span className={`badge ${getStatusBadgeClass(detailAsset.status)}`}>
                        {detailAsset.status}
                      </span>
                      <span className={`badge ${getCriticalityBadgeClass(detailAsset.criticality)}`}>
                        {detailAsset.criticality} Criticality
                      </span>
                    </div>

                    {/* Metadata Grid */}
                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                        gap: '0.75rem',
                        background: 'var(--color-bg-card)',
                        padding: '1rem',
                        borderRadius: 'var(--radius-card)',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>IP ADDRESS</div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                          {detailAsset.ipAddress || '—'}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>HOSTNAME</div>
                        <div style={{ fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                          {detailAsset.hostname || '—'}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>TYPE</div>
                        <div style={{ fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                          {detailAsset.type}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>ENVIRONMENT</div>
                        <div style={{ fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                          {detailAsset.environment || '—'}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>OPERATING SYSTEM</div>
                        <div style={{ fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                          {detailAsset.operatingSystem || '—'}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>OWNER</div>
                        <div style={{ fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                          {detailAsset.owner || '—'}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>CREATED</div>
                        <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                          {formatLocalDateTime(detailAsset.createdAt)}
                        </div>
                      </div>
                      <div>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600 }}>LAST UPDATED</div>
                        <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                          {formatLocalDateTime(detailAsset.updatedAt)}
                        </div>
                      </div>
                    </div>

                    {/* Tags */}
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600, marginBottom: '0.4rem' }}>
                        CLASSIFICATION TAGS
                      </div>
                      {detailAsset.tags && detailAsset.tags.length > 0 ? (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                          {detailAsset.tags.map((tag) => (
                            <span
                              key={tag}
                              style={{
                                background: 'var(--color-bg-base)',
                                border: '1px solid var(--color-border)',
                                color: 'var(--color-text-secondary)',
                                padding: '0.2rem 0.5rem',
                                borderRadius: '4px',
                                fontSize: '11px',
                              }}
                            >
                              #{tag}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>No tags assigned</span>
                      )}
                    </div>

                    {/* Description */}
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontWeight: 600, marginBottom: '0.4rem' }}>
                        DESCRIPTION
                      </div>
                      <p style={{ margin: 0, fontSize: '13px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                        {detailAsset.description || 'No description provided.'}
                      </p>
                    </div>
                  </div>
                ) : (
                  /* ── Audit Timeline Tab ── */
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {detailAsset.timeline && detailAsset.timeline.length > 0 ? (
                      detailAsset.timeline.map((entry) => (
                        <div
                          key={entry.id}
                          style={{
                            background: 'var(--color-bg-card)',
                            border: '1px solid var(--color-border)',
                            borderRadius: '6px',
                            padding: '0.75rem',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '0.35rem',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <span
                              style={{
                                fontSize: '11px',
                                fontWeight: 700,
                                color: 'var(--color-accent)',
                              }}
                            >
                              {entry.action}
                            </span>
                            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                              {formatLocalDateTime(entry.timestamp)}
                            </span>
                          </div>

                          <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                            Actor: {entry.actor?.name || entry.actor?.email || 'System'} ({entry.actor?.role || 'AUTO'})
                          </div>

                          {entry.details && typeof entry.details === 'object' && (
                            <div
                              style={{
                                fontSize: '11.5px',
                                background: 'var(--color-bg-base)',
                                padding: '0.4rem 0.6rem',
                                borderRadius: '4px',
                                color: 'var(--color-text-muted)',
                                overflowX: 'auto',
                              }}
                            >
                              {entry.details.changedFields && (
                                <div>Changed: {entry.details.changedFields.join(', ')}</div>
                              )}
                              {entry.details.newStatus && <div>Status: {entry.details.newStatus}</div>}
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div style={{ textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '12px', padding: '2rem' }}>
                        No audit history recorded for this asset.
                      </div>
                    )}
                  </div>
                )
              ) : null}
            </div>

            {/* Drawer Footer Actions */}
            {canMutate && detailAsset && (
              <div
                style={{
                  padding: '1rem 1.25rem',
                  borderTop: '1px solid var(--color-border)',
                  background: 'var(--color-bg-card)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '0.75rem',
                }}
              >
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  {detailAsset.status !== 'DECOMMISSIONED' && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => openConfirmModal('decommission', detailAsset)}
                      style={{ fontSize: '12px', color: 'var(--color-medium)' }}
                    >
                      <PowerOff size={13} /> Decommission
                    </button>
                  )}
                  {isAdmin && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => openConfirmModal('delete', detailAsset)}
                      style={{ fontSize: '12px', color: 'var(--color-critical)' }}
                    >
                      <Trash2 size={13} /> Delete
                    </button>
                  )}
                </div>

                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => openEditModal(detailAsset)}
                  style={{ fontSize: '12px' }}
                >
                  <Pencil size={13} /> Edit Asset
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Confirmation Modal (Decommission / Delete) ─────────────────────── */}
      {confirmModal.isOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1100,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
        >
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: 440,
              background: 'var(--color-bg-card)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--radius-card)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.75rem' }}>
              <AlertCircle
                size={20}
                color={confirmModal.actionType === 'delete' ? 'var(--color-critical)' : 'var(--color-medium)'}
              />
              <span style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                {confirmModal.title}
              </span>
            </div>

            <p style={{ margin: '0 0 1.25rem', fontSize: '13px', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
              {confirmModal.message}
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setConfirmModal({ ...confirmModal, isOpen: false })}
                disabled={confirmModal.submitting}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn"
                onClick={handleConfirmAction}
                disabled={confirmModal.submitting}
                style={{
                  background:
                    confirmModal.actionType === 'delete' ? 'var(--color-critical)' : 'var(--color-medium)',
                  color: '#000',
                  fontWeight: 600,
                }}
              >
                {confirmModal.submitting
                  ? 'Processing…'
                  : confirmModal.actionType === 'delete'
                  ? 'Confirm Permanent Delete'
                  : 'Confirm Decommission'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
