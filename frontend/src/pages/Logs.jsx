// src/pages/Logs.jsx
// Security Logs Management: Log Ingestion, Event Normalization, and Raw Log Inspection.

import { useState, useEffect, useCallback, useId } from 'react';
import {
  ScrollText,
  Upload,
  RefreshCw,
  Search,
  Filter,
  X,
  Copy,
  Check,
  Eye,
  AlertCircle,
  FileCode,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import {
  ingestLogsApi,
  getRawLogsApi,
  getEventsApi,
  getEventByIdApi,
} from '../api/logs.api';

// ── Synthetic Demonstration Presets (Synthetic test data only) ───────────────
const SYNTHETIC_PRESETS = [
  {
    label: 'SSH Failure (auth.log)',
    mode: 'single',
    source: 'auth.log',
    content: 'Oct 24 10:15:32 host-01 sshd[28412]: Failed password for invalid user admin from 198.51.100.23 port 45231 ssh2',
  },
  {
    label: 'SSH Success (auth.log)',
    mode: 'single',
    source: 'auth.log',
    content: 'Oct 24 10:16:01 host-01 sshd[28450]: Accepted publickey for analyst from 10.0.0.50 port 51234 ssh2',
  },
  {
    label: 'Firewall Block (firewall)',
    mode: 'single',
    source: 'firewall',
    content: '2026-10-24T10:18:22Z FW-EDGE-01 filterlog: BLOCK,IN,4,TCP,203.0.113.88,10.0.0.1,58210,80',
  },
  {
    label: 'JSON Security Event (json)',
    mode: 'single',
    source: 'json',
    content: JSON.stringify({
      timestamp: new Date().toISOString(),
      eventType: 'waf_blocked_request',
      srcIp: '198.51.100.44',
      dstIp: '10.0.0.15',
      dstPort: 443,
      username: 'anonymous',
      severity: 'HIGH',
      message: 'SQL Injection signature detected in query string',
      metadata: { ruleId: 'OWASP-942100', uri: '/api/v1/users?id=1%20OR%201=1' },
    }, null, 2),
  },
  {
    label: 'Mixed 4-Item Batch',
    mode: 'batch',
    source: 'batch',
    content: JSON.stringify([
      {
        source: 'auth.log',
        content: 'Oct 24 10:25:01 host-01 sshd[30101]: Failed password for root from 198.51.100.23 port 48192 ssh2',
      },
      {
        source: 'auth.log',
        content: 'Oct 24 10:25:05 host-01 sshd[30104]: Failed password for root from 198.51.100.23 port 48195 ssh2',
      },
      {
        source: 'firewall',
        content: '2026-10-24T10:25:10Z FW-EDGE-01 filterlog: BLOCK,IN,4,TCP,198.51.100.23,10.0.0.1,48199,22',
      },
      {
        source: 'json',
        content: JSON.stringify({
          eventType: 'api_login_anomaly',
          srcIp: '203.0.113.88',
          severity: 'MEDIUM',
          message: 'Login from new geographic subnet',
        }),
      },
    ], null, 2),
  },
];

export default function Logs() {
  const { user } = useAuth();
  const canIngest = user?.role === 'ADMIN' || user?.role === 'ANALYST';
  const isViewer = user?.role === 'VIEWER';

  const singleSourceId = useId();
  const singleContentId = useId();
  const batchContentId = useId();

  // Active view tab: 'events' (Normalized) or 'raw' (Raw Logs)
  const [activeTab, setActiveTab] = useState('events');

  // ── Tab 1: Normalized Events State ─────────────────────────────────────────
  const [events, setEvents] = useState([]);
  const [eventsPagination, setEventsPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState('');

  // Filters for Events
  const [eventFilters, setEventFilters] = useState({
    eventType: '',
    severity: '',
    srcIp: '',
    username: '',
  });

  // ── Tab 2: Raw Logs State ──────────────────────────────────────────────────
  const [rawLogs, setRawLogs] = useState([]);
  const [rawLogsPagination, setRawLogsPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  const [rawLogsLoading, setRawLogsLoading] = useState(false);
  const [rawLogsError, setRawLogsError] = useState('');

  // Filters for Raw Logs
  const [rawFilters, setRawFilters] = useState({
    source: '',
    search: '',
  });

  // ── Detail Drawer State ────────────────────────────────────────────────────
  const [selectedEventId, setSelectedEventId] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);

  // ── Ingestion Modal State ──────────────────────────────────────────────────
  const [isIngestOpen, setIsIngestOpen] = useState(false);
  const [ingestMode, setIngestMode] = useState('single'); // 'single' | 'batch'
  const [singleSource, setSingleSource] = useState('auth.log');
  const [singleContent, setSingleContent] = useState('');
  const [batchJson, setBatchJson] = useState('');
  const [ingestLoading, setIngestLoading] = useState(false);
  const [ingestError, setIngestError] = useState('');
  const [ingestSuccess, setIngestSuccess] = useState('');

  // ── Data Fetching Functions ────────────────────────────────────────────────

  const fetchEvents = useCallback(async (page = 1) => {
    await Promise.resolve();
    setEventsLoading(true);
    setEventsError('');
    try {
      const params = {
        page,
        limit: 20,
        ...(eventFilters.eventType && { eventType: eventFilters.eventType }),
        ...(eventFilters.severity && { severity: eventFilters.severity }),
        ...(eventFilters.srcIp && { srcIp: eventFilters.srcIp.trim() }),
        ...(eventFilters.username && { username: eventFilters.username.trim() }),
      };
      const res = await getEventsApi(params);
      if (res?.success) {
        setEvents(res.data || []);
        if (res.pagination) setEventsPagination(res.pagination);
      }
    } catch (err) {
      setEventsError(err.response?.data?.error || err.message || 'Failed to load events.');
    } finally {
      setEventsLoading(false);
    }
  }, [eventFilters]);

  const fetchRawLogs = useCallback(async (page = 1) => {
    await Promise.resolve();
    setRawLogsLoading(true);
    setRawLogsError('');
    try {
      const params = {
        page,
        limit: 20,
        ...(rawFilters.source && { source: rawFilters.source.trim() }),
        ...(rawFilters.search && { search: rawFilters.search.trim() }),
      };
      const res = await getRawLogsApi(params);
      if (res?.success) {
        setRawLogs(res.data || []);
        if (res.pagination) setRawLogsPagination(res.pagination);
      }
    } catch (err) {
      setRawLogsError(err.response?.data?.error || err.message || 'Failed to load raw logs.');
    } finally {
      setRawLogsLoading(false);
    }
  }, [rawFilters]);

  // Initial load and filter synchronization
  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      if (activeTab === 'events') {
        try {
          setEventsLoading(true);
          setEventsError('');
          const params = {
            page: 1,
            limit: 20,
            ...(eventFilters.eventType && { eventType: eventFilters.eventType }),
            ...(eventFilters.severity && { severity: eventFilters.severity }),
            ...(eventFilters.srcIp && { srcIp: eventFilters.srcIp.trim() }),
            ...(eventFilters.username && { username: eventFilters.username.trim() }),
          };
          const res = await getEventsApi(params);
          if (!cancelled && res?.success) {
            setEvents(res.data || []);
            if (res.pagination) setEventsPagination(res.pagination);
          }
        } catch (err) {
          if (!cancelled) setEventsError(err.response?.data?.error || err.message || 'Failed to load events.');
        } finally {
          if (!cancelled) setEventsLoading(false);
        }
      } else {
        try {
          setRawLogsLoading(true);
          setRawLogsError('');
          const params = {
            page: 1,
            limit: 20,
            ...(rawFilters.source && { source: rawFilters.source.trim() }),
            ...(rawFilters.search && { search: rawFilters.search.trim() }),
          };
          const res = await getRawLogsApi(params);
          if (!cancelled && res?.success) {
            setRawLogs(res.data || []);
            if (res.pagination) setRawLogsPagination(res.pagination);
          }
        } catch (err) {
          if (!cancelled) setRawLogsError(err.response?.data?.error || err.message || 'Failed to load raw logs.');
        } finally {
          if (!cancelled) setRawLogsLoading(false);
        }
      }
    }

    loadData();
    return () => { cancelled = true; };
  }, [activeTab, eventFilters, rawFilters]);

  // Fetch Event Details when an event is selected
  useEffect(() => {
    if (!selectedEventId) return;

    let mounted = true;
    async function loadDetail() {
      await Promise.resolve();
      if (!mounted) return;
      setDetailLoading(true);
      setDetailError('');
      try {
        const res = await getEventByIdApi(selectedEventId);
        if (mounted && res?.success) {
          setSelectedEvent(res.data);
        }
      } catch (err) {
        if (mounted) {
          setDetailError(err.response?.data?.error || err.message || 'Failed to load event details.');
        }
      } finally {
        if (mounted) setDetailLoading(false);
      }
    }

    loadDetail();
    return () => { mounted = false; };
  }, [selectedEventId]);

  // Keyboard accessibility: ESC closes modal & drawer
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') {
        if (isIngestOpen) setIsIngestOpen(false);
        if (selectedEventId) setSelectedEventId(null);
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isIngestOpen, selectedEventId]);

  // ── Ingestion Form Submission ──────────────────────────────────────────────
  async function handleIngestSubmit(e) {
    e.preventDefault();
    setIngestError('');
    setIngestSuccess('');
    setIngestLoading(true);

    try {
      let payload;
      if (ingestMode === 'single') {
        if (!singleSource.trim()) throw new Error("Log 'source' is required.");
        if (!singleContent.trim()) throw new Error("Log 'content' cannot be empty.");
        payload = { source: singleSource.trim(), content: singleContent.trim() };
      } else {
        if (!batchJson.trim()) throw new Error('Batch JSON cannot be empty.');
        let parsed;
        try {
          parsed = JSON.parse(batchJson);
        } catch {
          throw new Error('Invalid JSON syntax in batch logs payload.');
        }
        if (!Array.isArray(parsed)) {
          throw new Error('Batch payload must be a JSON array of [{ source, content }, ...].');
        }
        if (parsed.length === 0) {
          throw new Error('Batch array must contain at least 1 log entry.');
        }
        if (parsed.length > 100) {
          throw new Error(`Batch contains ${parsed.length} items. Maximum allowed is 100.`);
        }
        payload = { logs: parsed };
      }

      const res = await ingestLogsApi(payload);
      if (res?.success) {
        setIngestSuccess(`Success: Ingested ${res.data?.count ?? 1} log(s) and normalized ${res.data?.events?.length ?? 1} event(s).`);
        if (ingestMode === 'single') setSingleContent('');

        // Refresh current view
        if (activeTab === 'events') fetchEvents(1);
        else fetchRawLogs(1);
      }
    } catch (err) {
      setIngestError(err.response?.data?.error || err.message || 'Log ingestion failed.');
    } finally {
      setIngestLoading(false);
    }
  }

  function applyPreset(preset) {
    setIngestError('');
    setIngestSuccess('');
    if (preset.mode === 'single') {
      setIngestMode('single');
      setSingleSource(preset.source);
      setSingleContent(preset.content);
    } else {
      setIngestMode('batch');
      setBatchJson(preset.content);
    }
  }

  function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  }

  // ── Helper formatters ──────────────────────────────────────────────────────
  function formatTimestamp(isoStr) {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
    } catch {
      return '—';
    }
  }

  function getSeverityBadgeClass(sev) {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH':     return 'badge-high';
      case 'MEDIUM':   return 'badge-medium';
      case 'LOW':      return 'badge-low';
      default:         return 'badge-info';
    }
  }

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* ── Page Header & Action Controls ─────────────────────────────────── */}
      <div style={{
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
      }}>
        <div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ScrollText size={24} color="var(--color-accent)" />
            <span>Security Logs</span>
          </h1>
          <p className="page-subtitle">
            Ingest, normalize, and inspect security telemetry across connected servers and sensors.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <button
            onClick={() => activeTab === 'events' ? fetchEvents(eventsPagination.page) : fetchRawLogs(rawLogsPagination.page)}
            className="btn btn-ghost"
            title="Refresh current list"
            style={{ padding: '0.45rem 0.75rem', fontSize: '13px' }}
          >
            <RefreshCw size={14} className={eventsLoading || rawLogsLoading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>

          {canIngest ? (
            <button
              onClick={() => {
                setIngestError('');
                setIngestSuccess('');
                setIsIngestOpen(true);
              }}
              className="btn btn-primary"
              style={{ padding: '0.45rem 0.9rem', fontSize: '13px' }}
            >
              <Upload size={14} />
              <span>Ingest Logs</span>
            </button>
          ) : isViewer ? (
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.4rem',
                padding: '0.4rem 0.75rem',
                borderRadius: '6px',
                backgroundColor: 'rgba(240, 180, 41, 0.1)',
                border: '1px solid rgba(240, 180, 41, 0.3)',
                color: 'var(--color-medium)',
                fontSize: '12px',
                fontWeight: 500,
              }}
              title="Log ingestion requires Analyst or Admin privileges"
            >
              <Lock size={12} />
              <span>Read-Only (Viewer)</span>
            </div>
          ) : null}
        </div>
      </div>

      {/* ── Tabs Navigation ───────────────────────────────────────────────── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        borderBottom: '1px solid var(--color-border)',
        paddingBottom: '0.25rem',
      }}>
        <button
          onClick={() => setActiveTab('events')}
          style={{
            padding: '0.55rem 1rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'events' ? '2px solid var(--color-accent)' : '2px solid transparent',
            color: activeTab === 'events' ? 'var(--color-accent)' : 'var(--color-text-secondary)',
            fontWeight: activeTab === 'events' ? 600 : 500,
            fontSize: '13.5px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            transition: 'all 0.15s ease',
          }}
        >
          <span>Normalized Events</span>
          <span style={{
            fontSize: '11px',
            padding: '0.1rem 0.45rem',
            borderRadius: '10px',
            backgroundColor: activeTab === 'events' ? 'rgba(0, 212, 170, 0.15)' : 'var(--color-bg-surface)',
            color: activeTab === 'events' ? 'var(--color-accent)' : 'var(--color-text-muted)',
            fontFamily: 'var(--font-mono)',
          }}>
            {eventsPagination.total}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('raw')}
          style={{
            padding: '0.55rem 1rem',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'raw' ? '2px solid var(--color-accent)' : '2px solid transparent',
            color: activeTab === 'raw' ? 'var(--color-accent)' : 'var(--color-text-secondary)',
            fontWeight: activeTab === 'raw' ? 600 : 500,
            fontSize: '13.5px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            transition: 'all 0.15s ease',
          }}
        >
          <span>Raw Logs</span>
          <span style={{
            fontSize: '11px',
            padding: '0.1rem 0.45rem',
            borderRadius: '10px',
            backgroundColor: activeTab === 'raw' ? 'rgba(0, 212, 170, 0.15)' : 'var(--color-bg-surface)',
            color: activeTab === 'raw' ? 'var(--color-accent)' : 'var(--color-text-muted)',
            fontFamily: 'var(--font-mono)',
          }}>
            {rawLogsPagination.total}
          </span>
        </button>
      </div>

      {/* ── TAB 1: NORMALIZED EVENTS VIEW ─────────────────────────────────── */}
      {activeTab === 'events' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Filters Bar */}
          <div className="card" style={{ padding: '0.85rem 1.1rem' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-text-muted)', fontSize: '12px' }}>
                <Filter size={14} />
                <span>Filters:</span>
              </div>

              {/* Event Type */}
              <input
                type="text"
                placeholder="Filter event type…"
                value={eventFilters.eventType}
                onChange={(e) => setEventFilters(f => ({ ...f, eventType: e.target.value }))}
                style={{
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  padding: '0.35rem 0.65rem',
                  fontSize: '12px',
                  minWidth: '140px',
                }}
              />

              {/* Severity Dropdown */}
              <select
                value={eventFilters.severity}
                onChange={(e) => setEventFilters(f => ({ ...f, severity: e.target.value }))}
                style={{
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  padding: '0.35rem 0.65rem',
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

              {/* Source IP */}
              <input
                type="text"
                placeholder="Source IP (e.g. 198.51.100.23)…"
                value={eventFilters.srcIp}
                onChange={(e) => setEventFilters(f => ({ ...f, srcIp: e.target.value }))}
                style={{
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  padding: '0.35rem 0.65rem',
                  fontSize: '12px',
                  minWidth: '170px',
                  fontFamily: 'var(--font-mono)',
                }}
              />

              {/* Username */}
              <input
                type="text"
                placeholder="Username…"
                value={eventFilters.username}
                onChange={(e) => setEventFilters(f => ({ ...f, username: e.target.value }))}
                style={{
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  padding: '0.35rem 0.65rem',
                  fontSize: '12px',
                  minWidth: '110px',
                }}
              />

              {(eventFilters.eventType || eventFilters.severity || eventFilters.srcIp || eventFilters.username) && (
                <button
                  onClick={() => setEventFilters({ eventType: '', severity: '', srcIp: '', username: '' })}
                  className="btn btn-ghost"
                  style={{ padding: '0.35rem 0.6rem', fontSize: '11px', color: 'var(--color-critical)' }}
                >
                  <X size={12} />
                  <span>Reset</span>
                </button>
              )}
            </div>
          </div>

          {/* Events Table Container */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            {eventsError && (
              <div style={{
                padding: '1.25rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                color: 'var(--color-critical)',
                backgroundColor: 'rgba(255, 59, 59, 0.08)',
                borderBottom: '1px solid rgba(255, 59, 59, 0.2)',
              }}>
                <AlertCircle size={16} />
                <span style={{ fontSize: '13px' }}>{eventsError}</span>
                <button onClick={() => fetchEvents(eventsPagination.page)} className="btn btn-ghost" style={{ marginLeft: 'auto', padding: '0.2rem 0.5rem', fontSize: '11px' }}>
                  Retry
                </button>
              </div>
            )}

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{
                    backgroundColor: 'var(--color-bg-surface)',
                    borderBottom: '1px solid var(--color-border)',
                    color: 'var(--color-text-muted)',
                    fontSize: '11px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem 0.75rem' }}>Severity</th>
                    <th style={{ padding: '0.75rem 0.75rem' }}>Event Type</th>
                    <th style={{ padding: '0.75rem 0.75rem' }}>Source IP:Port</th>
                    <th style={{ padding: '0.75rem 0.75rem' }}>Destination IP:Port</th>
                    <th style={{ padding: '0.75rem 0.75rem' }}>User</th>
                    <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {eventsLoading && events.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '3rem', color: 'var(--color-text-muted)' }}>
                        Loading normalized events…
                      </td>
                    </tr>
                  ) : events.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '3.5rem', color: 'var(--color-text-muted)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
                          <FileCode size={32} color="var(--color-border)" />
                          <span style={{ fontWeight: 500, color: 'var(--color-text-secondary)' }}>No telemetry events recorded</span>
                          <span style={{ fontSize: '12px' }}>Use the Ingest button above to import sample security logs.</span>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    events.map((ev) => {
                      const srcFormatted = ev.srcIp ? `${ev.srcIp}${ev.srcPort ? `:${ev.srcPort}` : ''}` : '—';
                      const dstFormatted = ev.dstIp ? `${ev.dstIp}${ev.dstPort ? `:${ev.dstPort}` : ''}` : '—';

                      return (
                        <tr
                          key={ev.id}
                          style={{
                            borderBottom: '1px solid var(--color-border-subtle)',
                            transition: 'background-color 0.15s ease',
                          }}
                          onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--color-bg-elevated)'}
                          onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                        >
                          <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--color-text-secondary)', whiteSpace: 'nowrap' }}>
                            {formatTimestamp(ev.timestamp)}
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem' }}>
                            <span className={`badge ${getSeverityBadgeClass(ev.severity)}`}>
                              {ev.severity}
                            </span>
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem' }}>
                            <span style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '12px',
                              backgroundColor: 'rgba(0, 212, 170, 0.08)',
                              color: 'var(--color-accent)',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                            }}>
                              {ev.eventType}
                            </span>
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem', fontFamily: 'var(--font-mono)', fontSize: '12px', color: ev.srcIp ? 'var(--color-text-primary)' : 'var(--color-text-muted)' }}>
                            {srcFormatted}
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem', fontFamily: 'var(--font-mono)', fontSize: '12px', color: ev.dstIp ? 'var(--color-text-primary)' : 'var(--color-text-muted)' }}>
                            {dstFormatted}
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem', color: ev.username ? 'var(--color-text-primary)' : 'var(--color-text-muted)' }}>
                            {ev.username || '—'}
                          </td>
                          <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                            <button
                              onClick={() => setSelectedEventId(ev.id)}
                              className="btn btn-ghost"
                              style={{ padding: '0.25rem 0.5rem', fontSize: '11.5px', gap: '0.3rem' }}
                              title="Inspect full normalized event & raw evidence"
                            >
                              <Eye size={13} />
                              <span>Inspect</span>
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Events Pagination */}
            {eventsPagination.totalPages > 1 && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.75rem 1rem',
                borderTop: '1px solid var(--color-border)',
                fontSize: '12px',
                color: 'var(--color-text-muted)',
              }}>
                <span>
                  Showing page {eventsPagination.page} of {eventsPagination.totalPages} ({eventsPagination.total} total events)
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <button
                    disabled={eventsPagination.page <= 1}
                    onClick={() => fetchEvents(eventsPagination.page - 1)}
                    className="btn btn-ghost"
                    style={{ padding: '0.25rem 0.6rem', fontSize: '12px', opacity: eventsPagination.page <= 1 ? 0.4 : 1 }}
                  >
                    Previous
                  </button>
                  <button
                    disabled={eventsPagination.page >= eventsPagination.totalPages}
                    onClick={() => fetchEvents(eventsPagination.page + 1)}
                    className="btn btn-ghost"
                    style={{ padding: '0.25rem 0.6rem', fontSize: '12px', opacity: eventsPagination.page >= eventsPagination.totalPages ? 0.4 : 1 }}
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 2: RAW LOGS VIEW ─────────────────────────────────────────── */}
      {activeTab === 'raw' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Filters Bar */}
          <div className="card" style={{ padding: '0.85rem 1.1rem' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-text-muted)', fontSize: '12px' }}>
                <Search size={14} />
                <span>Search Raw:</span>
              </div>

              <input
                type="text"
                placeholder="Filter source (e.g. auth.log, firewall)…"
                value={rawFilters.source}
                onChange={(e) => setRawFilters(f => ({ ...f, source: e.target.value }))}
                style={{
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  padding: '0.35rem 0.65rem',
                  fontSize: '12px',
                  minWidth: '180px',
                }}
              />

              <input
                type="text"
                placeholder="Substring search in raw content…"
                value={rawFilters.search}
                onChange={(e) => setRawFilters(f => ({ ...f, search: e.target.value }))}
                style={{
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  padding: '0.35rem 0.65rem',
                  fontSize: '12px',
                  minWidth: '220px',
                }}
              />

              {(rawFilters.source || rawFilters.search) && (
                <button
                  onClick={() => setRawFilters({ source: '', search: '' })}
                  className="btn btn-ghost"
                  style={{ padding: '0.35rem 0.6rem', fontSize: '11px', color: 'var(--color-critical)' }}
                >
                  <X size={12} />
                  <span>Reset</span>
                </button>
              )}
            </div>
          </div>

          {/* Raw Logs Table Container */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            {rawLogsError && (
              <div style={{
                padding: '1.25rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                color: 'var(--color-critical)',
                backgroundColor: 'rgba(255, 59, 59, 0.08)',
                borderBottom: '1px solid rgba(255, 59, 59, 0.2)',
              }}>
                <AlertCircle size={16} />
                <span style={{ fontSize: '13px' }}>{rawLogsError}</span>
                <button onClick={() => fetchRawLogs(rawLogsPagination.page)} className="btn btn-ghost" style={{ marginLeft: 'auto', padding: '0.2rem 0.5rem', fontSize: '11px' }}>
                  Retry
                </button>
              </div>
            )}

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{
                    backgroundColor: 'var(--color-bg-surface)',
                    borderBottom: '1px solid var(--color-border)',
                    color: 'var(--color-text-muted)',
                    fontSize: '11px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                  }}>
                    <th style={{ padding: '0.75rem 1rem', width: '180px' }}>Received At</th>
                    <th style={{ padding: '0.75rem 0.75rem', width: '130px' }}>Source</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Verbatim Raw Log Content</th>
                  </tr>
                </thead>
                <tbody>
                  {rawLogsLoading && rawLogs.length === 0 ? (
                    <tr>
                      <td colSpan={3} style={{ textAlign: 'center', padding: '3rem', color: 'var(--color-text-muted)' }}>
                        Loading raw logs…
                      </td>
                    </tr>
                  ) : rawLogs.length === 0 ? (
                    <tr>
                      <td colSpan={3} style={{ textAlign: 'center', padding: '3.5rem', color: 'var(--color-text-muted)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
                          <ScrollText size={32} color="var(--color-border)" />
                          <span style={{ fontWeight: 500, color: 'var(--color-text-secondary)' }}>No raw log entries found</span>
                          <span style={{ fontSize: '12px' }}>Ingest raw logs to inspect byte-for-byte evidence.</span>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    rawLogs.map((log) => (
                      <tr
                        key={log.id}
                        style={{
                          borderBottom: '1px solid var(--color-border-subtle)',
                        }}
                      >
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--color-text-secondary)', verticalAlign: 'top', whiteSpace: 'nowrap' }}>
                          {formatTimestamp(log.receivedAt)}
                        </td>
                        <td style={{ padding: '0.75rem 0.75rem', verticalAlign: 'top' }}>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            fontFamily: 'var(--font-mono)',
                            padding: '0.15rem 0.5rem',
                            borderRadius: '4px',
                            backgroundColor: 'var(--color-bg-surface)',
                            border: '1px solid var(--color-border)',
                            color: 'var(--color-accent)',
                          }}>
                            {log.source}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', verticalAlign: 'top' }}>
                          <div style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '12px',
                            backgroundColor: 'var(--color-bg-surface)',
                            padding: '0.45rem 0.75rem',
                            borderRadius: '5px',
                            border: '1px solid var(--color-border-subtle)',
                            color: 'var(--color-text-primary)',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                            maxHeight: '120px',
                            overflowY: 'auto',
                          }}>
                            {log.rawContent}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Raw Logs Pagination */}
            {rawLogsPagination.totalPages > 1 && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.75rem 1rem',
                borderTop: '1px solid var(--color-border)',
                fontSize: '12px',
                color: 'var(--color-text-muted)',
              }}>
                <span>
                  Showing page {rawLogsPagination.page} of {rawLogsPagination.totalPages} ({rawLogsPagination.total} total logs)
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <button
                    disabled={rawLogsPagination.page <= 1}
                    onClick={() => fetchRawLogs(rawLogsPagination.page - 1)}
                    className="btn btn-ghost"
                    style={{ padding: '0.25rem 0.6rem', fontSize: '12px', opacity: rawLogsPagination.page <= 1 ? 0.4 : 1 }}
                  >
                    Previous
                  </button>
                  <button
                    disabled={rawLogsPagination.page >= rawLogsPagination.totalPages}
                    onClick={() => fetchRawLogs(rawLogsPagination.page + 1)}
                    className="btn btn-ghost"
                    style={{ padding: '0.25rem 0.6rem', fontSize: '12px', opacity: rawLogsPagination.page >= rawLogsPagination.totalPages ? 0.4 : 1 }}
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── EVENT DETAIL DRAWER ───────────────────────────────────────────── */}
      {selectedEventId && (
        <div style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.6)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          justifyContent: 'flex-end',
          zIndex: 100,
        }}
        onClick={(e) => {
          if (e.target === e.currentTarget) setSelectedEventId(null);
        }}
        >
          <div style={{
            width: '100%',
            maxWidth: '560px',
            height: '100%',
            backgroundColor: 'var(--color-bg-card)',
            borderLeft: '1px solid var(--color-border)',
            boxShadow: 'var(--shadow-card)',
            display: 'flex',
            flexDirection: 'column',
            overflowY: 'auto',
          }}>
            {/* Drawer Header */}
            <div style={{
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--color-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Event Telemetry Inspector
                </h3>
                <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                  ID: {selectedEventId}
                </span>
              </div>
              <button
                onClick={() => setSelectedEventId(null)}
                className="btn btn-ghost"
                style={{ padding: '0.35rem', borderRadius: '50%' }}
                title="Close (ESC)"
              >
                <X size={16} />
              </button>
            </div>

            {/* Drawer Body */}
            <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem', flex: 1 }}>
              {detailLoading ? (
                <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--color-text-muted)' }}>
                  Loading event telemetry…
                </div>
              ) : detailError ? (
                <div style={{ color: 'var(--color-critical)', backgroundColor: 'rgba(255, 59, 59, 0.1)', padding: '1rem', borderRadius: '6px' }}>
                  {detailError}
                </div>
              ) : selectedEvent ? (
                <>
                  {/* Overview Card */}
                  <div style={{
                    backgroundColor: 'var(--color-bg-surface)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '8px',
                    padding: '1rem',
                    display: 'grid',
                    gridTemplateColumns: 'repeat(2, 1fr)',
                    gap: '1rem',
                  }}>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Severity</div>
                      <div style={{ marginTop: '0.25rem' }}>
                        <span className={`badge ${getSeverityBadgeClass(selectedEvent.severity)}`}>
                          {selectedEvent.severity}
                        </span>
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Event Type</div>
                      <div style={{ marginTop: '0.25rem', fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--color-accent)' }}>
                        {selectedEvent.eventType}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Timestamp</div>
                      <div style={{ marginTop: '0.25rem', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                        {formatTimestamp(selectedEvent.timestamp)}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Authenticated User</div>
                      <div style={{ marginTop: '0.25rem', fontSize: '13px' }}>
                        {selectedEvent.username || '—'}
                      </div>
                    </div>
                  </div>

                  {/* Network Attribution */}
                  <div style={{
                    backgroundColor: 'var(--color-bg-surface)',
                    border: '1px solid var(--color-border)',
                    borderRadius: '8px',
                    padding: '1rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.75rem',
                  }}>
                    <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                      Network Attribution
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)', display: 'block', fontSize: '10px' }}>SOURCE ADDRESS</span>
                        <span>{selectedEvent.srcIp || '—'}</span>
                        {selectedEvent.srcPort && <span style={{ color: 'var(--color-text-muted)' }}>:{selectedEvent.srcPort}</span>}
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)', display: 'block', fontSize: '10px' }}>DESTINATION ADDRESS</span>
                        <span>{selectedEvent.dstIp || '—'}</span>
                        {selectedEvent.dstPort && <span style={{ color: 'var(--color-text-muted)' }}>:{selectedEvent.dstPort}</span>}
                      </div>
                      <div>
                        <span style={{ color: 'var(--color-text-muted)', display: 'block', fontSize: '10px' }}>REPORTING HOSTNAME</span>
                        <span>{selectedEvent.hostname || '—'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Normalized Message */}
                  {selectedEvent.message && (
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                        Event Message
                      </div>
                      <div style={{
                        padding: '0.75rem',
                        backgroundColor: 'var(--color-bg-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: '6px',
                        fontSize: '12.5px',
                        color: 'var(--color-text-primary)',
                      }}>
                        {selectedEvent.message}
                      </div>
                    </div>
                  )}

                  {/* Extended Metadata JSON */}
                  {selectedEvent.metadata && (
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
                        Extended Metadata Attributes
                      </div>
                      <pre style={{
                        margin: 0,
                        padding: '0.75rem',
                        backgroundColor: 'var(--color-bg-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: '6px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11.5px',
                        color: 'var(--color-text-secondary)',
                        overflowX: 'auto',
                      }}>
                        {JSON.stringify(selectedEvent.metadata, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Originating Raw Evidence Log */}
                  {selectedEvent.rawLog && (
                    <div>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        marginBottom: '0.35rem',
                      }}>
                        <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                          Originating Raw Log Evidence ({selectedEvent.rawLog.source})
                        </div>
                        <button
                          onClick={() => copyToClipboard(selectedEvent.rawLog.rawContent)}
                          className="btn btn-ghost"
                          style={{ padding: '0.2rem 0.5rem', fontSize: '11px', gap: '0.3rem' }}
                          title="Copy raw text to clipboard"
                        >
                          {copiedRaw ? <Check size={12} color="var(--color-accent)" /> : <Copy size={12} />}
                          <span>{copiedRaw ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre style={{
                        margin: 0,
                        padding: '0.75rem',
                        backgroundColor: '#05080c',
                        border: '1px solid var(--color-border)',
                        borderRadius: '6px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11.5px',
                        color: '#a0aec0',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}>
                        {selectedEvent.rawLog.rawContent}
                      </pre>
                    </div>
                  )}
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* ── INGESTION MODAL ──────────────────────────────────────────────── */}
      {isIngestOpen && (
        <div style={{
          position: 'fixed',
          inset: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '1.5rem',
          zIndex: 110,
        }}
        onClick={(e) => {
          if (e.target === e.currentTarget) setIsIngestOpen(false);
        }}
        >
          <div style={{
            width: '100%',
            maxWidth: '640px',
            backgroundColor: 'var(--color-bg-card)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-card)',
            boxShadow: 'var(--shadow-card)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--color-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Ingest Telemetry Log
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                  Submit live log strings or batch telemetry directly into the normalization engine.
                </span>
              </div>
              <button
                onClick={() => setIsIngestOpen(false)}
                className="btn btn-ghost"
                style={{ padding: '0.35rem', borderRadius: '50%' }}
                title="Close (ESC)"
              >
                <X size={16} />
              </button>
            </div>

            {/* Modal Body */}
            <form onSubmit={handleIngestSubmit} style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Synthetic Presets Helper */}
              <div>
                <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                  Quick-Fill Synthetic Test Presets:
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.4rem' }}>
                  {SYNTHETIC_PRESETS.map((p) => (
                    <button
                      key={p.label}
                      type="button"
                      onClick={() => applyPreset(p)}
                      style={{
                        padding: '0.3rem 0.6rem',
                        fontSize: '11.5px',
                        backgroundColor: 'var(--color-bg-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: '5px',
                        color: 'var(--color-text-secondary)',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = 'var(--color-accent)';
                        e.currentTarget.style.color = 'var(--color-accent)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = 'var(--color-border)';
                        e.currentTarget.style.color = 'var(--color-text-secondary)';
                      }}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Mode Toggle */}
              <div style={{ display: 'flex', gap: '0.5rem', backgroundColor: 'var(--color-bg-surface)', padding: '0.25rem', borderRadius: '6px' }}>
                <button
                  type="button"
                  onClick={() => { setIngestMode('single'); setIngestError(''); }}
                  style={{
                    flex: 1,
                    padding: '0.45rem',
                    fontSize: '12.5px',
                    fontWeight: ingestMode === 'single' ? 600 : 500,
                    backgroundColor: ingestMode === 'single' ? 'var(--color-bg-elevated)' : 'transparent',
                    color: ingestMode === 'single' ? 'var(--color-accent)' : 'var(--color-text-muted)',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer',
                  }}
                >
                  Single Log Entry
                </button>
                <button
                  type="button"
                  onClick={() => { setIngestMode('batch'); setIngestError(''); }}
                  style={{
                    flex: 1,
                    padding: '0.45rem',
                    fontSize: '12.5px',
                    fontWeight: ingestMode === 'batch' ? 600 : 500,
                    backgroundColor: ingestMode === 'batch' ? 'var(--color-bg-elevated)' : 'transparent',
                    color: ingestMode === 'batch' ? 'var(--color-accent)' : 'var(--color-text-muted)',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer',
                  }}
                >
                  Batch Telemetry (Up to 100)
                </button>
              </div>

              {/* Feedback Alerts */}
              {ingestError && (
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: 'rgba(255, 59, 59, 0.1)',
                  border: '1px solid rgba(255, 59, 59, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--color-critical)',
                  fontSize: '12.5px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}>
                  <AlertCircle size={15} />
                  <span>{ingestError}</span>
                </div>
              )}

              {ingestSuccess && (
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: 'rgba(0, 212, 170, 0.1)',
                  border: '1px solid rgba(0, 212, 170, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--color-accent)',
                  fontSize: '12.5px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}>
                  <CheckCircle2 size={15} />
                  <span>{ingestSuccess}</span>
                </div>
              )}

              {/* Single Mode Form */}
              {ingestMode === 'single' ? (
                <>
                  <div>
                    <label htmlFor={singleSourceId} style={{ display: 'block', fontSize: '12px', color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                      Telemetry Source Identifier (e.g. auth.log, firewall, json)
                    </label>
                    <input
                      id={singleSourceId}
                      type="text"
                      required
                      value={singleSource}
                      onChange={(e) => setSingleSource(e.target.value)}
                      placeholder="auth.log"
                      style={{
                        width: '100%',
                        padding: '0.55rem 0.75rem',
                        backgroundColor: 'var(--color-bg-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: '6px',
                        color: 'var(--color-text-primary)',
                        fontSize: '13px',
                        fontFamily: 'var(--font-mono)',
                      }}
                    />
                  </div>

                  <div>
                    <label htmlFor={singleContentId} style={{ display: 'block', fontSize: '12px', color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                      Raw Log String Content
                    </label>
                    <textarea
                      id={singleContentId}
                      rows={5}
                      required
                      value={singleContent}
                      onChange={(e) => setSingleContent(e.target.value)}
                      placeholder="Oct 24 10:15:32 host-01 sshd[28412]: Failed password for root from 198.51.100.23 port 45231 ssh2"
                      style={{
                        width: '100%',
                        padding: '0.65rem 0.75rem',
                        backgroundColor: 'var(--color-bg-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: '6px',
                        color: 'var(--color-text-primary)',
                        fontSize: '12.5px',
                        fontFamily: 'var(--font-mono)',
                        resize: 'vertical',
                      }}
                    />
                  </div>
                </>
              ) : (
                /* Batch Mode Form */
                <div>
                  <label htmlFor={batchContentId} style={{ display: 'block', fontSize: '12px', color: 'var(--color-text-secondary)', marginBottom: '0.35rem' }}>
                    JSON Array of Logs (Max 100 items: [{`{"source": "...", "content": "..."}`}, ...])
                  </label>
                  <textarea
                    id={batchContentId}
                    rows={8}
                    required
                    value={batchJson}
                    onChange={(e) => setBatchJson(e.target.value)}
                    placeholder="[&#10;  { &quot;source&quot;: &quot;auth.log&quot;, &quot;content&quot;: &quot;...&quot; }&#10;]"
                    style={{
                      width: '100%',
                      padding: '0.65rem 0.75rem',
                      backgroundColor: 'var(--color-bg-surface)',
                      border: '1px solid var(--color-border)',
                      borderRadius: '6px',
                      color: 'var(--color-text-primary)',
                      fontSize: '12px',
                      fontFamily: 'var(--font-mono)',
                      resize: 'vertical',
                    }}
                  />
                </div>
              )}

              {/* Action Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setIsIngestOpen(false)}
                  className="btn btn-ghost"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={ingestLoading}
                  className="btn btn-primary"
                  style={{ minWidth: '120px', justifyContent: 'center' }}
                >
                  {ingestLoading ? 'Ingesting…' : 'Ingest & Normalize'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
