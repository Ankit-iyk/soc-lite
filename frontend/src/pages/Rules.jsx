// src/pages/Rules.jsx
// Detection Rules Management UI for SOC Lite.
// Provides listing, filtering, configuration, enable/disable toggling,
// confirmation dialogs, and manual detection execution.

import { useState, useEffect, useCallback } from 'react';
import {
  SlidersHorizontal,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertCircle,
  Play,
  Lock,
  Edit2,
  Check,
  X,
  Clock,
  Terminal,
  Radio,
  Globe,
  Key,
  Shield,
  Activity,
  ArrowRight,
  Info,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { getRulesApi, updateRuleApi, runDetectionApi } from '../api/rules.api';

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

function getRuleIcon(type) {
  switch (type) {
    case 'SSH_BRUTE_FORCE':   return Terminal;
    case 'PORT_SCAN':         return Radio;
    case 'SUSPICIOUS_IP':     return Globe;
    case 'SUSPICIOUS_ACCESS': return Key;
    default:                  return Shield;
  }
}

function formatRuleTypeName(type) {
  switch (type) {
    case 'SSH_BRUTE_FORCE':   return 'SSH Brute Force';
    case 'PORT_SCAN':         return 'Port Scan';
    case 'SUSPICIOUS_IP':     return 'Suspicious IP';
    case 'SUSPICIOUS_ACCESS': return 'Suspicious Access';
    default:                  return type;
  }
}

function formatRelativeTime(dateStr) {
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

export default function Rules() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'ADMIN';
  const isAnalyst = user?.role === 'ANALYST';
  const canRunDetection = isAdmin || isAnalyst;

  // ── Rules State ────────────────────────────────────────────────────────────
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [successToast, setSuccessToast] = useState('');

  // ── Filters & Search ───────────────────────────────────────────────────────
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // ── Edit Modal State ───────────────────────────────────────────────────────
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [editForm, setEditForm] = useState({});
  const [editValidationErrors, setEditValidationErrors] = useState({});
  const [editSubmitting, setEditSubmitting] = useState(false);
  const [editBackendError, setEditBackendError] = useState('');
  const [isConfirmingSave, setIsConfirmingSave] = useState(false);

  // ── Toggle Status State ────────────────────────────────────────────────────
  const [togglingRuleId, setTogglingRuleId] = useState(null);

  // ── Detection Run Modal State ──────────────────────────────────────────────
  const [runModalOpen, setRunModalOpen] = useState(false);
  const [runRuleId, setRunRuleId] = useState('');
  const [runWindowMinutes, setRunWindowMinutes] = useState('60');
  const [runLimit, setRunLimit] = useState('1000');
  const [runningDetection, setRunningDetection] = useState(false);
  const [runSummary, setRunSummary] = useState(null);
  const [runError, setRunError] = useState('');

  // ── Data Fetching ──────────────────────────────────────────────────────────
  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await getRulesApi();
      if (res?.success && Array.isArray(res.data)) {
        setRules(res.data);
      } else {
        setError('Unexpected API response format.');
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to load detection rules.');
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load on mount
  useEffect(() => {
    let isMounted = true;

    async function loadInitial() {
      try {
        const res = await getRulesApi();
        if (isMounted) {
          if (res?.success && Array.isArray(res.data)) {
            setRules(res.data);
          } else {
            setError('Unexpected API response format.');
          }
        }
      } catch (err) {
        if (isMounted) {
          setError(err.response?.data?.error || err.message || 'Failed to load detection rules.');
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    loadInitial();

    return () => {
      isMounted = false;
    };
  }, []);

  // Auto-dismiss success toast
  useEffect(() => {
    if (successToast) {
      const t = setTimeout(() => setSuccessToast(''), 4000);
      return () => clearTimeout(t);
    }
  }, [successToast]);

  // ── Toggle Enabled Handler ─────────────────────────────────────────────────
  const handleToggleEnabled = async (rule) => {
    if (!isAdmin) return;
    setTogglingRuleId(rule.id);
    const newStatus = !rule.enabled;

    try {
      const res = await updateRuleApi(rule.id, { enabled: newStatus });
      if (res?.success && res.data) {
        setRules((prev) =>
          prev.map((r) => (r.id === rule.id ? { ...r, enabled: newStatus, updatedAt: res.data.updatedAt } : r))
        );
        setSuccessToast(`Rule "${rule.name}" ${newStatus ? 'enabled' : 'disabled'} successfully.`);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update rule status.');
    } finally {
      setTogglingRuleId(null);
    }
  };

  // ── Edit Modal Open / Populate ─────────────────────────────────────────────
  const openEditModal = (rule) => {
    setEditingRule(rule);
    setEditForm({
      enabled: rule.enabled,
      severity: rule.severity,
      description: rule.description || '',
      config: { ...(rule.config || {}) },
    });
    setEditValidationErrors({});
    setEditBackendError('');
    setIsConfirmingSave(false);
    setEditModalOpen(true);
  };

  // ── Client-side Edit Form Validation ───────────────────────────────────────
  const validateForm = () => {
    const errs = {};
    if (!editingRule) return errs;

    const { type } = editingRule;
    const cfg = editForm.config || {};

    switch (type) {
      case 'SSH_BRUTE_FORCE': {
        const threshold = Number(cfg.threshold);
        if (!Number.isInteger(threshold) || threshold < 1 || threshold > 1000) {
          errs.threshold = 'Threshold must be an integer between 1 and 1,000.';
        }
        const windowSec = Number(cfg.windowSeconds);
        if (!Number.isInteger(windowSec) || windowSec < 1 || windowSec > 86400) {
          errs.windowSeconds = 'Window must be an integer between 1 and 86,400 seconds.';
        }
        if (!cfg.eventType || typeof cfg.eventType !== 'string' || !cfg.eventType.trim()) {
          errs.eventType = 'Event type must be specified.';
        }
        break;
      }

      case 'PORT_SCAN': {
        const portThreshold = Number(cfg.portThreshold);
        if (!Number.isInteger(portThreshold) || portThreshold < 1 || portThreshold > 65535) {
          errs.portThreshold = 'Port threshold must be an integer between 1 and 65,535.';
        }
        const windowSec = Number(cfg.windowSeconds);
        if (!Number.isInteger(windowSec) || windowSec < 1 || windowSec > 86400) {
          errs.windowSeconds = 'Window must be an integer between 1 and 86,400 seconds.';
        }
        if (!cfg.eventType || (typeof cfg.eventType === 'string' && !cfg.eventType.trim())) {
          errs.eventType = 'Event type must be specified.';
        }
        break;
      }

      case 'SUSPICIOUS_IP': {
        if (!cfg.matchSource && !cfg.matchDestination) {
          errs.ipMatch = 'At least one of Match Source or Match Destination must be enabled.';
        }
        break;
      }

      case 'SUSPICIOUS_ACCESS': {
        const start = Number(cfg.allowedHoursStart);
        const end = Number(cfg.allowedHoursEnd);
        if (!Number.isInteger(start) || start < 0 || start > 23) {
          errs.allowedHoursStart = 'Start hour must be between 0 and 23.';
        }
        if (!Number.isInteger(end) || end < 1 || end > 24) {
          errs.allowedHoursEnd = 'End hour must be between 1 and 24.';
        }
        if (start >= end) {
          errs.hoursOrder = `Start hour (${start}:00) must be earlier than end hour (${end}:00).`;
        }
        break;
      }
    }

    setEditValidationErrors(errs);
    return Object.keys(errs).length === 0;
  };

  // ── Prepare Differences for Confirmation ───────────────────────────────────
  const getDifferences = () => {
    if (!editingRule) return [];
    const diffs = [];

    if (editForm.enabled !== editingRule.enabled) {
      diffs.push({ field: 'Status', old: editingRule.enabled ? 'Enabled' : 'Disabled', next: editForm.enabled ? 'Enabled' : 'Disabled' });
    }
    if (editForm.severity !== editingRule.severity) {
      diffs.push({ field: 'Severity', old: editingRule.severity, next: editForm.severity });
    }
    if ((editForm.description || '') !== (editingRule.description || '')) {
      diffs.push({ field: 'Description', old: editingRule.description || '(empty)', next: editForm.description || '(empty)' });
    }

    const oldCfg = editingRule.config || {};
    const newCfg = editForm.config || {};

    for (const key of Object.keys(newCfg)) {
      if (newCfg[key] !== oldCfg[key]) {
        diffs.push({ field: `Config: ${key}`, old: String(oldCfg[key]), next: String(newCfg[key]) });
      }
    }

    return diffs;
  };

  // ── Submit Edit Form ───────────────────────────────────────────────────────
  const handleSaveRule = async () => {
    if (!validateForm()) return;

    const diffs = getDifferences();
    if (diffs.length > 0 && !isConfirmingSave) {
      setIsConfirmingSave(true);
      return;
    }

    setEditSubmitting(true);
    setEditBackendError('');

    try {
      const payload = {
        enabled: editForm.enabled,
        severity: editForm.severity,
        description: editForm.description,
        config: editForm.config,
      };

      const res = await updateRuleApi(editingRule.id, payload);
      if (res?.success && res.data) {
        setRules((prev) => prev.map((r) => (r.id === editingRule.id ? res.data : r)));
        setEditModalOpen(false);
        setSuccessToast(`Detection rule "${editingRule.name}" updated successfully.`);
      }
    } catch (err) {
      setEditBackendError(err.response?.data?.error || err.message || 'Failed to update rule.');
      setIsConfirmingSave(false);
    } finally {
      setEditSubmitting(false);
    }
  };

  // ── Manual Detection Execution ─────────────────────────────────────────────
  const handleRunDetection = async () => {
    setRunningDetection(true);
    setRunError('');
    setRunSummary(null);

    try {
      const payload = {};
      if (runRuleId) payload.ruleId = runRuleId;
      if (runWindowMinutes) payload.windowMinutes = parseInt(runWindowMinutes, 10);
      if (runLimit) payload.limit = parseInt(runLimit, 10);

      const res = await runDetectionApi(payload);
      if (res?.success && res.data) {
        setRunSummary(res.data);
        fetchRules(); // Refresh in background
      }
    } catch (err) {
      setRunError(err.response?.data?.error || err.message || 'Detection run failed.');
    } finally {
      setRunningDetection(false);
    }
  };

  // ── Filtered Rules Calculation ─────────────────────────────────────────────
  const filteredRules = rules.filter((r) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchName = r.name?.toLowerCase().includes(q);
      const matchDesc = r.description?.toLowerCase().includes(q);
      const matchType = r.type?.toLowerCase().includes(q);
      if (!matchName && !matchDesc && !matchType) return false;
    }
    if (typeFilter && r.type !== typeFilter) return false;
    if (severityFilter && r.severity !== severityFilter) return false;
    if (statusFilter === 'ENABLED' && !r.enabled) return false;
    if (statusFilter === 'DISABLED' && r.enabled) return false;
    return true;
  });

  const enabledCount = rules.filter((r) => r.enabled).length;
  const disabledCount = rules.filter((r) => !r.enabled).length;

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* ── Success Toast Notification ─────────────────────────────────────── */}
      {successToast && (
        <div
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
            style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', marginLeft: '0.5rem' }}
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ── Top Header Bar ─────────────────────────────────────────────────── */}
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, color: 'var(--color-text-primary)' }}>
              Detection Rules
            </h1>
            <span
              style={{
                fontSize: '11px',
                fontWeight: 600,
                textTransform: 'uppercase',
                padding: '0.2rem 0.55rem',
                borderRadius: '999px',
                backgroundColor: isAdmin ? 'rgba(0, 212, 170, 0.12)' : 'rgba(91, 155, 213, 0.12)',
                color: isAdmin ? 'var(--color-accent)' : 'var(--color-info)',
                border: `1px solid ${isAdmin ? 'rgba(0, 212, 170, 0.3)' : 'rgba(91, 155, 213, 0.3)'}`,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.3rem',
              }}
            >
              {isAdmin ? <Shield size={11} /> : isAnalyst ? <Activity size={11} /> : <Lock size={11} />}
              {isAdmin ? 'Admin (Read/Write)' : isAnalyst ? 'Analyst (Read/Execute)' : 'Viewer (Read-only)'}
            </span>
          </div>
          <p style={{ margin: '0.25rem 0 0 0', color: 'var(--color-text-secondary)', fontSize: '13px' }}>
            Inspect and configure behavioral detection heuristics, sliding window thresholds, and active IOC matching.
          </p>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <button
            onClick={() => fetchRules(true)}
            disabled={loading}
            className="btn btn-secondary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '13px' }}
            title="Refresh rules from database"
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>

          {canRunDetection && (
            <button
              onClick={() => {
                setRunModalOpen(true);
                setRunSummary(null);
                setRunError('');
              }}
              className="btn btn-primary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45rem', fontSize: '13px' }}
              title="Manually trigger detection engine across recent events"
            >
              <Play size={14} fill="currentColor" />
              <span>Run Detection Engine</span>
            </button>
          )}
        </div>
      </div>

      {/* ── Summary Metrics Bar ────────────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
        }}
      >
        <div className="card card-surface" style={{ padding: '0.85rem 1.15rem' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 600 }}>
            Configured Rules
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: '0.2rem' }}>
            {rules.length}
          </div>
        </div>

        <div className="card card-surface" style={{ padding: '0.85rem 1.15rem' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 600 }}>
            Active / Enabled
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--color-accent)', marginTop: '0.2rem' }}>
            {enabledCount}
          </div>
        </div>

        <div className="card card-surface" style={{ padding: '0.85rem 1.15rem' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 600 }}>
            Disabled / Standby
          </div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: disabledCount > 0 ? 'var(--color-text-muted)' : 'var(--color-text-secondary)', marginTop: '0.2rem' }}>
            {disabledCount}
          </div>
        </div>

        <div className="card card-surface" style={{ padding: '0.85rem 1.15rem' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 600 }}>
            Evaluator Engine
          </div>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text-secondary)', marginTop: '0.45rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--color-accent)' }} />
            Deterministic Pure Evaluators
          </div>
        </div>
      </div>

      {/* ── Search & Filter Controls ───────────────────────────────────────── */}
      <div
        className="card card-surface"
        style={{
          padding: '0.75rem 1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ position: 'relative', flex: '1 1 240px', minWidth: '220px' }}>
          <Search size={14} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)' }} />
          <input
            type="text"
            placeholder="Search rules by name, type, or description…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '0.4rem 0.75rem 0.4rem 2.2rem',
              backgroundColor: 'var(--color-bg-base)',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              color: 'var(--color-text-primary)',
              fontSize: '12.5px',
            }}
          />
        </div>

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{
            backgroundColor: 'var(--color-bg-base)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            color: 'var(--color-text-primary)',
            padding: '0.4rem 0.75rem',
            fontSize: '12px',
            cursor: 'pointer',
          }}
        >
          <option value="">All Rule Types</option>
          <option value="SSH_BRUTE_FORCE">SSH Brute Force</option>
          <option value="PORT_SCAN">Port Scan</option>
          <option value="SUSPICIOUS_IP">Suspicious IP</option>
          <option value="SUSPICIOUS_ACCESS">Suspicious Access</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{
            backgroundColor: 'var(--color-bg-base)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            color: 'var(--color-text-primary)',
            padding: '0.4rem 0.75rem',
            fontSize: '12px',
            cursor: 'pointer',
          }}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{
            backgroundColor: 'var(--color-bg-base)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            color: 'var(--color-text-primary)',
            padding: '0.4rem 0.75rem',
            fontSize: '12px',
            cursor: 'pointer',
          }}
        >
          <option value="">All Statuses</option>
          <option value="ENABLED">Enabled Only</option>
          <option value="DISABLED">Disabled Only</option>
        </select>

        {(searchQuery || typeFilter || severityFilter || statusFilter) && (
          <button
            onClick={() => {
              setSearchQuery('');
              setTypeFilter('');
              setSeverityFilter('');
              setStatusFilter('');
            }}
            className="btn btn-ghost"
            style={{ fontSize: '12px', padding: '0.35rem 0.65rem' }}
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* ── Error Banner ───────────────────────────────────────────────────── */}
      {error && (
        <div
          style={{
            padding: '0.85rem 1.15rem',
            backgroundColor: 'rgba(255, 59, 59, 0.1)',
            border: '1px solid rgba(255, 59, 59, 0.3)',
            borderRadius: 'var(--radius-card)',
            color: 'var(--color-critical)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.65rem',
            fontSize: '13px',
          }}
        >
          <AlertCircle size={16} />
          <span>{error}</span>
          <button
            onClick={() => fetchRules(true)}
            style={{
              marginLeft: 'auto',
              background: 'none',
              border: 'none',
              color: 'var(--color-text-primary)',
              textDecoration: 'underline',
              cursor: 'pointer',
              fontSize: '12px',
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Rule Cards Grid ────────────────────────────────────────────────── */}
      {loading ? (
        // Loading Skeleton
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: '1.25rem' }}>
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="card card-surface" style={{ padding: '1.25rem', height: '240px', opacity: 0.6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                <div style={{ width: '36px', height: '36px', borderRadius: '8px', backgroundColor: 'var(--color-bg-elevated)' }} className="spin" />
                <div style={{ flex: 1 }}>
                  <div style={{ width: '60%', height: '14px', backgroundColor: 'var(--color-bg-elevated)', borderRadius: '4px', marginBottom: '0.4rem' }} />
                  <div style={{ width: '40%', height: '10px', backgroundColor: 'var(--color-bg-elevated)', borderRadius: '4px' }} />
                </div>
              </div>
              <div style={{ width: '100%', height: '40px', backgroundColor: 'var(--color-bg-elevated)', borderRadius: '6px', marginBottom: '1rem' }} />
              <div style={{ width: '100%', height: '60px', backgroundColor: 'var(--color-bg-elevated)', borderRadius: '6px' }} />
            </div>
          ))}
        </div>
      ) : filteredRules.length === 0 ? (
        // Empty State
        <div
          className="card card-surface"
          style={{
            padding: '3rem 2rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '0.75rem',
          }}
        >
          <SlidersHorizontal size={36} color="var(--color-text-muted)" />
          <h3 style={{ margin: 0, color: 'var(--color-text-primary)', fontSize: '1.1rem' }}>
            No Detection Rules Found
          </h3>
          <p style={{ margin: 0, color: 'var(--color-text-secondary)', fontSize: '13px', maxWidth: '420px' }}>
            {rules.length === 0
              ? 'No detection rules are configured in the database. Run the backend seed script to initialize baseline rules.'
              : 'No detection rules matched the specified filter criteria. Try clearing the filters.'}
          </p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', gap: '1.25rem' }}>
          {filteredRules.map((rule) => {
            const Icon = getRuleIcon(rule.type);
            const isToggling = togglingRuleId === rule.id;

            return (
              <div
                key={rule.id}
                className="card card-surface"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  padding: '1.25rem',
                  border: rule.enabled ? '1px solid var(--color-border)' : '1px solid var(--color-border-subtle)',
                  opacity: rule.enabled ? 1 : 0.72,
                  transition: 'all 0.2s ease',
                  backgroundColor: rule.enabled ? 'var(--color-bg-surface)' : 'rgba(13, 21, 32, 0.5)',
                }}
              >
                {/* ── Card Header ────────────────────────────────────────── */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.75rem', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem' }}>
                    <div
                      style={{
                        padding: '0.5rem',
                        borderRadius: '8px',
                        backgroundColor: rule.enabled ? 'rgba(0, 212, 170, 0.1)' : 'rgba(255, 255, 255, 0.04)',
                        color: rule.enabled ? 'var(--color-accent)' : 'var(--color-text-muted)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        marginTop: '0.1rem',
                      }}
                    >
                      <Icon size={18} />
                    </div>

                    <div>
                      <h3 style={{ margin: 0, fontSize: '14.5px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                        {rule.name}
                      </h3>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginTop: '0.25rem', flexWrap: 'wrap' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--color-text-muted)',
                            backgroundColor: 'var(--color-bg-base)',
                            padding: '0.1rem 0.4rem',
                            borderRadius: '4px',
                            border: '1px solid var(--color-border-subtle)',
                          }}
                        >
                          {rule.type}
                        </span>

                        <span className={`badge ${getSeverityBadgeClass(rule.severity)}`}>
                          {rule.severity}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Enable / Disable Toggle or Status Pill */}
                  <div>
                    {isAdmin ? (
                      <button
                        onClick={() => handleToggleEnabled(rule)}
                        disabled={isToggling}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.35rem',
                          padding: '0.25rem 0.55rem',
                          borderRadius: '999px',
                          fontSize: '11px',
                          fontWeight: 600,
                          cursor: isToggling ? 'not-allowed' : 'pointer',
                          transition: 'all 0.15s ease',
                          border: rule.enabled ? '1px solid rgba(0, 212, 170, 0.4)' : '1px solid var(--color-border)',
                          backgroundColor: rule.enabled ? 'rgba(0, 212, 170, 0.15)' : 'var(--color-bg-base)',
                          color: rule.enabled ? 'var(--color-accent)' : 'var(--color-text-muted)',
                        }}
                        title={rule.enabled ? 'Click to disable rule' : 'Click to enable rule'}
                      >
                        <span
                          style={{
                            width: '6px',
                            height: '6px',
                            borderRadius: '50%',
                            backgroundColor: rule.enabled ? 'var(--color-accent)' : 'var(--color-text-muted)',
                          }}
                        />
                        <span>{rule.enabled ? 'Active' : 'Disabled'}</span>
                      </button>
                    ) : (
                      <span
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.3rem',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '999px',
                          fontSize: '11px',
                          fontWeight: 600,
                          backgroundColor: rule.enabled ? 'rgba(0, 212, 170, 0.1)' : 'var(--color-bg-base)',
                          color: rule.enabled ? 'var(--color-accent)' : 'var(--color-text-muted)',
                          border: '1px solid var(--color-border-subtle)',
                        }}
                      >
                        <Lock size={10} />
                        <span>{rule.enabled ? 'Active' : 'Disabled'}</span>
                      </span>
                    )}
                  </div>
                </div>

                {/* ── Card Description ───────────────────────────────────── */}
                <p
                  style={{
                    margin: '0 0 0.85rem 0',
                    fontSize: '12.5px',
                    color: 'var(--color-text-secondary)',
                    lineHeight: 1.45,
                    flexGrow: 1,
                  }}
                >
                  {rule.description || 'No description provided.'}
                </p>

                {/* ── Configuration Parameters Matrix ────────────────────── */}
                <div
                  style={{
                    backgroundColor: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border-subtle)',
                    borderRadius: '8px',
                    padding: '0.65rem 0.85rem',
                    marginBottom: '0.85rem',
                    fontSize: '12px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.35rem',
                  }}
                >
                  <div style={{ fontSize: '10.5px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-text-muted)', fontWeight: 600, marginBottom: '0.1rem' }}>
                    Evaluator Parameters
                  </div>

                  {rule.type === 'SSH_BRUTE_FORCE' && (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.4rem' }}>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Threshold: </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)', fontWeight: 600 }}>
                          ≥ {rule.config?.threshold ?? 5} attempts
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Window: </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)', fontWeight: 600 }}>
                          {rule.config?.windowSeconds ?? 60}s
                        </span>
                      </div>
                      <div style={{ gridColumn: 'span 2' }}>
                        <span style={{ color: 'var(--color-text-muted)' }}>Event Type: </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>
                          {rule.config?.eventType ?? 'ssh_login_failed'}
                        </span>
                      </div>
                    </div>
                  )}

                  {rule.type === 'PORT_SCAN' && (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.4rem' }}>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Port Threshold: </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)', fontWeight: 600 }}>
                          ≥ {rule.config?.portThreshold ?? 15} ports
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Window: </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)', fontWeight: 600 }}>
                          {rule.config?.windowSeconds ?? 120}s
                        </span>
                      </div>
                      <div style={{ gridColumn: 'span 2' }}>
                        <span style={{ color: 'var(--color-text-muted)' }}>Target Events: </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>
                          {rule.config?.eventType ?? 'connection_attempt'} / network_connection
                        </span>
                      </div>
                    </div>
                  )}

                  {rule.type === 'SUSPICIOUS_IP' && (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.4rem' }}>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Match Source: </span>
                        <span style={{ color: rule.config?.matchSource ? 'var(--color-accent)' : 'var(--color-text-muted)', fontWeight: 600 }}>
                          {rule.config?.matchSource ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Match Destination: </span>
                        <span style={{ color: rule.config?.matchDestination ? 'var(--color-accent)' : 'var(--color-text-muted)', fontWeight: 600 }}>
                          {rule.config?.matchDestination ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                      <div style={{ gridColumn: 'span 2', fontSize: '11px', color: 'var(--color-text-muted)' }}>
                        Feeds: Active IP threat indicators (AlienVault OTX, AbuseIPDB)
                      </div>
                    </div>
                  )}

                  {rule.type === 'SUSPICIOUS_ACCESS' && (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.4rem' }}>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Approved Hours: </span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)', fontWeight: 600 }}>
                          {String(rule.config?.allowedHoursStart ?? 6).padStart(2, '0')}:00 – {String(rule.config?.allowedHoursEnd ?? 22).padStart(2, '0')}:00 UTC
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)' }}>Weekend Alert: </span>
                        <span style={{ color: rule.config?.alertOnWeekend ? 'var(--color-high)' : 'var(--color-text-muted)', fontWeight: 600 }}>
                          {rule.config?.alertOnWeekend ? 'Active' : 'Ignored'}
                        </span>
                      </div>
                      <div style={{ gridColumn: 'span 2' }}>
                        <span style={{ color: 'var(--color-text-muted)' }}>Target Identity: </span>
                        <span style={{ color: 'var(--color-accent)' }}>
                          {rule.config?.targetRole ?? 'ADMIN'} Accounts Only
                        </span>
                      </div>
                    </div>
                  )}
                </div>

                {/* ── Card Footer ────────────────────────────────────────── */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingTop: '0.75rem',
                    borderTop: '1px solid var(--color-border-subtle)',
                    fontSize: '11.5px',
                    color: 'var(--color-text-muted)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Clock size={12} />
                    <span>Updated {formatRelativeTime(rule.updatedAt)}</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    {canRunDetection && (
                      <button
                        onClick={() => {
                          setRunRuleId(rule.id);
                          setRunModalOpen(true);
                          setRunSummary(null);
                          setRunError('');
                        }}
                        className="btn btn-ghost"
                        style={{ fontSize: '11.5px', padding: '0.25rem 0.5rem', gap: '0.3rem' }}
                        title={`Run detection evaluation for ${rule.name} only`}
                      >
                        <Play size={11} fill="currentColor" />
                        <span>Evaluate</span>
                      </button>
                    )}

                    <button
                      onClick={() => openEditModal(rule)}
                      className={isAdmin ? 'btn btn-secondary' : 'btn btn-ghost'}
                      style={{ fontSize: '11.5px', padding: '0.25rem 0.55rem', gap: '0.3rem' }}
                      title={isAdmin ? 'Edit rule parameters and status' : 'View full rule parameters (Read-only)'}
                    >
                      {isAdmin ? <Edit2 size={11} /> : <Info size={11} />}
                      <span>{isAdmin ? 'Configure' : 'Inspect'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════════
          MODAL: Rule Configuration & Edit Modal
          ═══════════════════════════════════════════════════════════════════════ */}
      {editModalOpen && editingRule && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1000,
            backgroundColor: 'rgba(4, 7, 12, 0.8)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
          className="fade-in"
          onClick={(e) => {
            if (e.target === e.currentTarget && !editSubmitting) {
              setEditModalOpen(false);
            }
          }}
        >
          <div
            className="card card-surface"
            style={{
              width: '100%',
              maxWidth: '560px',
              maxHeight: '90vh',
              overflowY: 'auto',
              border: '1px solid var(--color-border)',
              boxShadow: 'var(--shadow-card)',
              padding: '1.5rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem',
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0, color: 'var(--color-text-primary)' }}>
                    {isAdmin ? 'Configure Detection Rule' : 'Rule Inspector'}
                  </h2>
                  <span className={`badge ${getSeverityBadgeClass(editForm.severity)}`}>
                    {editForm.severity}
                  </span>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', marginTop: '0.2rem' }}>
                  {editingRule.name} ({formatRuleTypeName(editingRule.type)})
                </div>
              </div>

              <button
                onClick={() => setEditModalOpen(false)}
                disabled={editSubmitting}
                className="btn btn-ghost"
                style={{ padding: '0.25rem', color: 'var(--color-text-muted)' }}
              >
                <X size={16} />
              </button>
            </div>

            {/* Backend Error Banner */}
            {editBackendError && (
              <div
                style={{
                  padding: '0.65rem 0.85rem',
                  backgroundColor: 'rgba(255, 59, 59, 0.1)',
                  border: '1px solid rgba(255, 59, 59, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--color-critical)',
                  fontSize: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <AlertCircle size={15} />
                <span>{editBackendError}</span>
              </div>
            )}

            {/* Read-Only Mode Notice for Non-Admins */}
            {!isAdmin && (
              <div
                style={{
                  padding: '0.65rem 0.85rem',
                  backgroundColor: 'rgba(91, 155, 213, 0.08)',
                  border: '1px solid rgba(91, 155, 213, 0.25)',
                  borderRadius: '6px',
                  color: 'var(--color-info)',
                  fontSize: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <Lock size={14} />
                <span>You have read-only access. Rule modifications are restricted to administrators.</span>
              </div>
            )}

            {/* ── Confirmation Step View (Diff Screen) ────────────────────── */}
            {isConfirmingSave ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }} className="fade-in">
                <div
                  style={{
                    padding: '0.75rem',
                    backgroundColor: 'rgba(240, 180, 41, 0.08)',
                    border: '1px solid rgba(240, 180, 41, 0.3)',
                    borderRadius: '6px',
                    color: 'var(--color-medium)',
                    fontSize: '12.5px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                  }}
                >
                  <AlertCircle size={16} />
                  <span>Please review the pending configuration changes before writing to database & audit log:</span>
                </div>

                <div
                  style={{
                    backgroundColor: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '8px',
                    padding: '0.85rem',
                    maxHeight: '220px',
                    overflowY: 'auto',
                    fontSize: '12px',
                  }}
                >
                  {getDifferences().map((d, i) => (
                    <div
                      key={i}
                      style={{
                        padding: '0.45rem 0',
                        borderBottom: i < getDifferences().length - 1 ? '1px solid var(--color-border-subtle)' : 'none',
                        display: 'grid',
                        gridTemplateColumns: '120px 1fr 20px 1fr',
                        alignItems: 'center',
                        gap: '0.4rem',
                      }}
                    >
                      <span style={{ fontWeight: 600, color: 'var(--color-text-secondary)' }}>{d.field}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-critical)', textDecoration: 'line-through' }}>{d.old}</span>
                      <ArrowRight size={12} color="var(--color-text-muted)" />
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-accent)', fontWeight: 600 }}>{d.next}</span>
                    </div>
                  ))}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '0.5rem' }}>
                  <button
                    onClick={() => setIsConfirmingSave(false)}
                    disabled={editSubmitting}
                    className="btn btn-secondary"
                    style={{ fontSize: '12.5px' }}
                  >
                    Back to Edit
                  </button>

                  <button
                    onClick={handleSaveRule}
                    disabled={editSubmitting}
                    className="btn btn-primary"
                    style={{ fontSize: '12.5px', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
                  >
                    {editSubmitting ? <RefreshCw size={13} className="spin" /> : <Check size={13} />}
                    <span>Confirm & Commit Changes</span>
                  </button>
                </div>
              </div>
            ) : (
              /* ── Main Form Inputs ────────────────────────────────────────── */
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {/* Status & Severity Row */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  {/* Enabled Toggle */}
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                      Rule Status
                    </label>
                    <button
                      type="button"
                      disabled={!isAdmin}
                      onClick={() => setEditForm((f) => ({ ...f, enabled: !f.enabled }))}
                      style={{
                        width: '100%',
                        padding: '0.45rem 0.75rem',
                        backgroundColor: editForm.enabled ? 'rgba(0, 212, 170, 0.12)' : 'var(--color-bg-base)',
                        border: `1px solid ${editForm.enabled ? 'var(--color-accent)' : 'var(--color-border)'}`,
                        borderRadius: '6px',
                        color: editForm.enabled ? 'var(--color-accent)' : 'var(--color-text-muted)',
                        fontWeight: 600,
                        fontSize: '12.5px',
                        cursor: isAdmin ? 'pointer' : 'not-allowed',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '0.4rem',
                      }}
                    >
                      <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: editForm.enabled ? 'var(--color-accent)' : 'var(--color-text-muted)' }} />
                      <span>{editForm.enabled ? 'Enabled (Evaluating)' : 'Disabled (Standby)'}</span>
                    </button>
                  </div>

                  {/* Severity Selector */}
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                      Alert Severity
                    </label>
                    <select
                      disabled={!isAdmin}
                      value={editForm.severity || 'MEDIUM'}
                      onChange={(e) => setEditForm((f) => ({ ...f, severity: e.target.value }))}
                      style={{
                        width: '100%',
                        padding: '0.45rem 0.75rem',
                        backgroundColor: 'var(--color-bg-base)',
                        border: '1px solid var(--color-border)',
                        borderRadius: '6px',
                        color: 'var(--color-text-primary)',
                        fontSize: '12.5px',
                        cursor: isAdmin ? 'pointer' : 'not-allowed',
                      }}
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>
                </div>

                {/* Description */}
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                    Rule Description
                  </label>
                  <textarea
                    disabled={!isAdmin}
                    rows={2}
                    value={editForm.description || ''}
                    onChange={(e) => setEditForm((f) => ({ ...f, description: e.target.value }))}
                    placeholder="Describe what activity this rule identifies…"
                    style={{
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      backgroundColor: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                      resize: 'vertical',
                      fontFamily: 'inherit',
                    }}
                  />
                </div>

                {/* ── Type-Specific Parameters ──────────────────────────────── */}
                <div
                  style={{
                    backgroundColor: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '8px',
                    padding: '1rem',
                  }}
                >
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-text-muted)', fontWeight: 600, marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <SlidersHorizontal size={13} />
                    <span>Evaluator Heuristics ({editingRule.type})</span>
                  </div>

                  {/* SSH_BRUTE_FORCE Inputs */}
                  {editingRule.type === 'SSH_BRUTE_FORCE' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                        <div>
                          <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                            Attempt Threshold (1–1,000)
                          </label>
                          <input
                            type="number"
                            min="1"
                            max="1000"
                            disabled={!isAdmin}
                            value={editForm.config?.threshold ?? 5}
                            onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, threshold: parseInt(e.target.value, 10) || '' } }))}
                            style={{
                              width: '100%',
                              padding: '0.4rem 0.65rem',
                              backgroundColor: 'var(--color-bg-base)',
                              border: `1px solid ${editValidationErrors.threshold ? 'var(--color-critical)' : 'var(--color-border)'}`,
                              borderRadius: '6px',
                              color: 'var(--color-text-primary)',
                              fontSize: '12.5px',
                              fontFamily: 'var(--font-mono)',
                            }}
                          />
                          {editValidationErrors.threshold && (
                            <div style={{ color: 'var(--color-critical)', fontSize: '11px', marginTop: '0.2rem' }}>{editValidationErrors.threshold}</div>
                          )}
                        </div>

                        <div>
                          <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                            Window Duration (1–86,400s)
                          </label>
                          <input
                            type="number"
                            min="1"
                            max="86400"
                            disabled={!isAdmin}
                            value={editForm.config?.windowSeconds ?? 60}
                            onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, windowSeconds: parseInt(e.target.value, 10) || '' } }))}
                            style={{
                              width: '100%',
                              padding: '0.4rem 0.65rem',
                              backgroundColor: 'var(--color-bg-base)',
                              border: `1px solid ${editValidationErrors.windowSeconds ? 'var(--color-critical)' : 'var(--color-border)'}`,
                              borderRadius: '6px',
                              color: 'var(--color-text-primary)',
                              fontSize: '12.5px',
                              fontFamily: 'var(--font-mono)',
                            }}
                          />
                          {editValidationErrors.windowSeconds && (
                            <div style={{ color: 'var(--color-critical)', fontSize: '11px', marginTop: '0.2rem' }}>{editValidationErrors.windowSeconds}</div>
                          )}
                        </div>
                      </div>

                      <div>
                        <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                          Target Event Type
                        </label>
                        <input
                          type="text"
                          disabled={!isAdmin}
                          value={editForm.config?.eventType ?? 'ssh_login_failed'}
                          onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, eventType: e.target.value } }))}
                          style={{
                            width: '100%',
                            padding: '0.4rem 0.65rem',
                            backgroundColor: 'var(--color-bg-base)',
                            border: `1px solid ${editValidationErrors.eventType ? 'var(--color-critical)' : 'var(--color-border)'}`,
                            borderRadius: '6px',
                            color: 'var(--color-accent)',
                            fontSize: '12.5px',
                            fontFamily: 'var(--font-mono)',
                          }}
                        />
                        {editValidationErrors.eventType && (
                          <div style={{ color: 'var(--color-critical)', fontSize: '11px', marginTop: '0.2rem' }}>{editValidationErrors.eventType}</div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* PORT_SCAN Inputs */}
                  {editingRule.type === 'PORT_SCAN' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                        <div>
                          <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                            Distinct Port Threshold (1–65,535)
                          </label>
                          <input
                            type="number"
                            min="1"
                            max="65535"
                            disabled={!isAdmin}
                            value={editForm.config?.portThreshold ?? 15}
                            onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, portThreshold: parseInt(e.target.value, 10) || '' } }))}
                            style={{
                              width: '100%',
                              padding: '0.4rem 0.65rem',
                              backgroundColor: 'var(--color-bg-base)',
                              border: `1px solid ${editValidationErrors.portThreshold ? 'var(--color-critical)' : 'var(--color-border)'}`,
                              borderRadius: '6px',
                              color: 'var(--color-text-primary)',
                              fontSize: '12.5px',
                              fontFamily: 'var(--font-mono)',
                            }}
                          />
                          {editValidationErrors.portThreshold && (
                            <div style={{ color: 'var(--color-critical)', fontSize: '11px', marginTop: '0.2rem' }}>{editValidationErrors.portThreshold}</div>
                          )}
                        </div>

                        <div>
                          <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                            Window Duration (1–86,400s)
                          </label>
                          <input
                            type="number"
                            min="1"
                            max="86400"
                            disabled={!isAdmin}
                            value={editForm.config?.windowSeconds ?? 120}
                            onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, windowSeconds: parseInt(e.target.value, 10) || '' } }))}
                            style={{
                              width: '100%',
                              padding: '0.4rem 0.65rem',
                              backgroundColor: 'var(--color-bg-base)',
                              border: `1px solid ${editValidationErrors.windowSeconds ? 'var(--color-critical)' : 'var(--color-border)'}`,
                              borderRadius: '6px',
                              color: 'var(--color-text-primary)',
                              fontSize: '12.5px',
                              fontFamily: 'var(--font-mono)',
                            }}
                          />
                          {editValidationErrors.windowSeconds && (
                            <div style={{ color: 'var(--color-critical)', fontSize: '11px', marginTop: '0.2rem' }}>{editValidationErrors.windowSeconds}</div>
                          )}
                        </div>
                      </div>

                      <div>
                        <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                          Target Event Type (or network_connection)
                        </label>
                        <input
                          type="text"
                          disabled={!isAdmin}
                          value={editForm.config?.eventType ?? 'connection_attempt'}
                          onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, eventType: e.target.value } }))}
                          style={{
                            width: '100%',
                            padding: '0.4rem 0.65rem',
                            backgroundColor: 'var(--color-bg-base)',
                            border: `1px solid ${editValidationErrors.eventType ? 'var(--color-critical)' : 'var(--color-border)'}`,
                            borderRadius: '6px',
                            color: 'var(--color-accent)',
                            fontSize: '12.5px',
                            fontFamily: 'var(--font-mono)',
                          }}
                        />
                        {editValidationErrors.eventType && (
                          <div style={{ color: 'var(--color-critical)', fontSize: '11px', marginTop: '0.2rem' }}>{editValidationErrors.eventType}</div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* SUSPICIOUS_IP Inputs */}
                  {editingRule.type === 'SUSPICIOUS_IP' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: isAdmin ? 'pointer' : 'default', fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                        <input
                          type="checkbox"
                          disabled={!isAdmin}
                          checked={Boolean(editForm.config?.matchSource)}
                          onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, matchSource: e.target.checked } }))}
                          style={{ width: '16px', height: '16px', accentColor: 'var(--color-accent)' }}
                        />
                        <span>Match Source IP against active threat indicators</span>
                      </label>

                      <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: isAdmin ? 'pointer' : 'default', fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                        <input
                          type="checkbox"
                          disabled={!isAdmin}
                          checked={Boolean(editForm.config?.matchDestination)}
                          onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, matchDestination: e.target.checked } }))}
                          style={{ width: '16px', height: '16px', accentColor: 'var(--color-accent)' }}
                        />
                        <span>Match Destination IP against active threat indicators</span>
                      </label>

                      {editValidationErrors.ipMatch && (
                        <div style={{ color: 'var(--color-critical)', fontSize: '11px', marginTop: '0.2rem' }}>{editValidationErrors.ipMatch}</div>
                      )}
                    </div>
                  )}

                  {/* SUSPICIOUS_ACCESS Inputs */}
                  {editingRule.type === 'SUSPICIOUS_ACCESS' && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                        <div>
                          <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                            Schedule Start (0–23 UTC Hour)
                          </label>
                          <input
                            type="number"
                            min="0"
                            max="23"
                            disabled={!isAdmin}
                            value={editForm.config?.allowedHoursStart ?? 6}
                            onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, allowedHoursStart: parseInt(e.target.value, 10) || 0 } }))}
                            style={{
                              width: '100%',
                              padding: '0.4rem 0.65rem',
                              backgroundColor: 'var(--color-bg-base)',
                              border: `1px solid ${editValidationErrors.allowedHoursStart || editValidationErrors.hoursOrder ? 'var(--color-critical)' : 'var(--color-border)'}`,
                              borderRadius: '6px',
                              color: 'var(--color-text-primary)',
                              fontSize: '12.5px',
                              fontFamily: 'var(--font-mono)',
                            }}
                          />
                        </div>

                        <div>
                          <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                            Schedule End (1–24 UTC Hour)
                          </label>
                          <input
                            type="number"
                            min="1"
                            max="24"
                            disabled={!isAdmin}
                            value={editForm.config?.allowedHoursEnd ?? 22}
                            onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, allowedHoursEnd: parseInt(e.target.value, 10) || 1 } }))}
                            style={{
                              width: '100%',
                              padding: '0.4rem 0.65rem',
                              backgroundColor: 'var(--color-bg-base)',
                              border: `1px solid ${editValidationErrors.allowedHoursEnd || editValidationErrors.hoursOrder ? 'var(--color-critical)' : 'var(--color-border)'}`,
                              borderRadius: '6px',
                              color: 'var(--color-text-primary)',
                              fontSize: '12.5px',
                              fontFamily: 'var(--font-mono)',
                            }}
                          />
                        </div>
                      </div>

                      {editValidationErrors.hoursOrder && (
                        <div style={{ color: 'var(--color-critical)', fontSize: '11px' }}>{editValidationErrors.hoursOrder}</div>
                      )}

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem', alignItems: 'center' }}>
                        <div>
                          <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--color-text-secondary)', marginBottom: '0.3rem' }}>
                            Target Account Role
                          </label>
                          <select
                            disabled={!isAdmin}
                            value={editForm.config?.targetRole ?? 'ADMIN'}
                            onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, targetRole: e.target.value } }))}
                            style={{
                              width: '100%',
                              padding: '0.4rem 0.65rem',
                              backgroundColor: 'var(--color-bg-base)',
                              border: '1px solid var(--color-border)',
                              borderRadius: '6px',
                              color: 'var(--color-text-primary)',
                              fontSize: '12px',
                            }}
                          >
                            <option value="ADMIN">ADMIN</option>
                            <option value="ANALYST">ANALYST</option>
                            <option value="VIEWER">VIEWER</option>
                          </select>
                        </div>

                        <div style={{ paddingTop: '1.25rem' }}>
                          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: isAdmin ? 'pointer' : 'default', fontSize: '12.5px', color: 'var(--color-text-primary)' }}>
                            <input
                              type="checkbox"
                              disabled={!isAdmin}
                              checked={Boolean(editForm.config?.alertOnWeekend)}
                              onChange={(e) => setEditForm((f) => ({ ...f, config: { ...f.config, alertOnWeekend: e.target.checked } }))}
                              style={{ width: '16px', height: '16px', accentColor: 'var(--color-high)' }}
                            />
                            <span>Alert on Weekend Logins</span>
                          </label>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Modal Footer Controls */}
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '0.5rem' }}>
                  <button
                    type="button"
                    onClick={() => setEditModalOpen(false)}
                    className="btn btn-secondary"
                    style={{ fontSize: '12.5px' }}
                  >
                    {isAdmin ? 'Cancel' : 'Close'}
                  </button>

                  {isAdmin && (
                    <button
                      type="button"
                      onClick={handleSaveRule}
                      className="btn btn-primary"
                      style={{ fontSize: '12.5px', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
                    >
                      <span>Review & Save Changes</span>
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════════
          MODAL: Manual Detection Execution Modal
          ═══════════════════════════════════════════════════════════════════════ */}
      {runModalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1000,
            backgroundColor: 'rgba(4, 7, 12, 0.8)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
          className="fade-in"
          onClick={(e) => {
            if (e.target === e.currentTarget && !runningDetection) {
              setRunModalOpen(false);
            }
          }}
        >
          <div
            className="card card-surface"
            style={{
              width: '100%',
              maxWidth: '540px',
              maxHeight: '90vh',
              overflowY: 'auto',
              border: '1px solid var(--color-border)',
              boxShadow: 'var(--shadow-card)',
              padding: '1.5rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem',
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 600, margin: 0, color: 'var(--color-text-primary)', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Play size={16} fill="var(--color-accent)" color="var(--color-accent)" />
                  <span>Manual Detection Run</span>
                </h2>
                <div style={{ fontSize: '12px', color: 'var(--color-text-secondary)', marginTop: '0.2rem' }}>
                  Execute detection evaluators on incoming telemetry with deduplication & alert persistence.
                </div>
              </div>

              <button
                onClick={() => setRunModalOpen(false)}
                disabled={runningDetection}
                className="btn btn-ghost"
                style={{ padding: '0.25rem', color: 'var(--color-text-muted)' }}
              >
                <X size={16} />
              </button>
            </div>

            {/* Error Banner */}
            {runError && (
              <div
                style={{
                  padding: '0.65rem 0.85rem',
                  backgroundColor: 'rgba(255, 59, 59, 0.1)',
                  border: '1px solid rgba(255, 59, 59, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--color-critical)',
                  fontSize: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <AlertCircle size={15} />
                <span>{runError}</span>
              </div>
            )}

            {/* Run Parameters Form */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                  Target Rule
                </label>
                <select
                  disabled={runningDetection}
                  value={runRuleId}
                  onChange={(e) => setRunRuleId(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.45rem 0.75rem',
                    backgroundColor: 'var(--color-bg-base)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '6px',
                    color: 'var(--color-text-primary)',
                    fontSize: '12.5px',
                  }}
                >
                  <option value="">All Active Rules ({enabledCount} active)</option>
                  {rules.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name} ({r.enabled ? 'Enabled' : 'Disabled'})
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                    Telemetry Time Window
                  </label>
                  <select
                    disabled={runningDetection}
                    value={runWindowMinutes}
                    onChange={(e) => setRunWindowMinutes(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.45rem 0.75rem',
                      backgroundColor: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    <option value="15">Past 15 minutes</option>
                    <option value="60">Past 1 hour</option>
                    <option value="360">Past 6 hours</option>
                    <option value="1440">Past 24 hours</option>
                    <option value="10080">Past 7 days</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                    Max Event Limit
                  </label>
                  <select
                    disabled={runningDetection}
                    value={runLimit}
                    onChange={(e) => setRunLimit(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.45rem 0.75rem',
                      backgroundColor: 'var(--color-bg-base)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      color: 'var(--color-text-primary)',
                      fontSize: '12.5px',
                    }}
                  >
                    <option value="250">250 events</option>
                    <option value="500">500 events</option>
                    <option value="1000">1,000 events</option>
                    <option value="2500">2,500 events</option>
                  </select>
                </div>
              </div>

              <button
                onClick={handleRunDetection}
                disabled={runningDetection}
                className="btn btn-primary"
                style={{
                  marginTop: '0.5rem',
                  padding: '0.55rem',
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.5rem',
                }}
              >
                {runningDetection ? <RefreshCw size={14} className="spin" /> : <Play size={14} fill="currentColor" />}
                <span>{runningDetection ? 'Evaluating telemetry with detection engine…' : 'Trigger Detection Run'}</span>
              </button>
            </div>

            {/* ── Detection Results Summary ───────────────────────────────── */}
            {runSummary && (
              <div
                style={{
                  backgroundColor: 'var(--color-bg-base)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '8px',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                }}
                className="fade-in"
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-accent)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <CheckCircle2 size={14} />
                    <span>Detection Run Completed Successfully</span>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                    Audit Log Recorded
                  </span>
                </div>

                {/* Metrics Breakdown */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem', textAlign: 'center' }}>
                  <div style={{ padding: '0.5rem', backgroundColor: 'var(--color-bg-surface)', borderRadius: '6px' }}>
                    <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)' }}>Rules</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>{runSummary.rulesEvaluated}</div>
                  </div>
                  <div style={{ padding: '0.5rem', backgroundColor: 'var(--color-bg-surface)', borderRadius: '6px' }}>
                    <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)' }}>Matches</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>{runSummary.matchesFound}</div>
                  </div>
                  <div style={{ padding: '0.5rem', backgroundColor: 'var(--color-bg-surface)', borderRadius: '6px' }}>
                    <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)' }}>Created</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: runSummary.alertsCreated > 0 ? 'var(--color-critical)' : 'var(--color-text-primary)' }}>
                      {runSummary.alertsCreated}
                    </div>
                  </div>
                  <div style={{ padding: '0.5rem', backgroundColor: 'var(--color-bg-surface)', borderRadius: '6px' }}>
                    <div style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--color-text-muted)' }}>Updated</div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: runSummary.alertsUpdated > 0 ? 'var(--color-high)' : 'var(--color-text-primary)' }}>
                      {runSummary.alertsUpdated}
                    </div>
                  </div>
                </div>

                {/* Alerts List */}
                {Array.isArray(runSummary.alerts) && runSummary.alerts.length > 0 ? (
                  <div style={{ marginTop: '0.25rem' }}>
                    <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                      Affected Security Alerts:
                    </div>
                    <div style={{ maxHeight: '140px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                      {runSummary.alerts.map((al, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '0.35rem 0.55rem',
                            backgroundColor: 'var(--color-bg-surface)',
                            borderRadius: '4px',
                            border: '1px solid var(--color-border-subtle)',
                            fontSize: '11.5px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                          }}
                        >
                          <span style={{ color: 'var(--color-text-primary)', fontWeight: 500 }}>{al.title}</span>
                          <span
                            style={{
                              fontSize: '10px',
                              textTransform: 'uppercase',
                              fontWeight: 600,
                              padding: '0.1rem 0.35rem',
                              borderRadius: '4px',
                              backgroundColor: al.action === 'created' ? 'rgba(255, 59, 59, 0.15)' : 'rgba(255, 123, 0, 0.15)',
                              color: al.action === 'created' ? 'var(--color-critical)' : 'var(--color-high)',
                            }}
                          >
                            {al.action}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: '11.5px', color: 'var(--color-text-muted)', textAlign: 'center', padding: '0.4rem' }}>
                    No alerts fired or modified during this evaluation period.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
