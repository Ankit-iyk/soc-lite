// src/pages/Reports.jsx
// PDF Security Reports UI for SOC Lite (Phase 10).
// Report type selection, optional date range, live JSON preview with charts,
// and PDF download. RBAC enforced: VIEWER can preview but not download.

import { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  Download,
  Eye,
  RefreshCw,
  Lock,
  Calendar,
  ShieldAlert,
  FolderOpen,
  Globe,
  Server,
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  Zap,
  X,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { getReportTypesApi, previewReportApi, downloadReportApi } from '../api/reports.api';

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityColor(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return '#ef4444';
    case 'HIGH':     return '#f97316';
    case 'MEDIUM':   return '#eab308';
    case 'LOW':      return '#22c55e';
    default:         return '#94a3b8';
  }
}

function statusColor(status) {
  switch ((status || '').toUpperCase()) {
    case 'OPEN':          return '#ef4444';
    case 'INVESTIGATING': return '#f97316';
    case 'ACKNOWLEDGED':  return '#eab308';
    case 'RESOLVED':      return '#22c55e';
    case 'CLOSED':        return '#94a3b8';
    case 'ACTIVE':        return '#22c55e';
    case 'INACTIVE':      return '#eab308';
    case 'EXPIRED':
    case 'REVOKED':       return '#ef4444';
    default:              return '#94a3b8';
  }
}

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function getSeverityBadgeClass(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH':     return 'badge-high';
    case 'MEDIUM':   return 'badge-medium';
    case 'LOW':      return 'badge-low';
    default:         return 'badge-info';
  }
}

function getStatusBadgeClass(status) {
  switch ((status || '').toUpperCase()) {
    case 'OPEN':          return 'badge-critical';
    case 'INVESTIGATING': return 'badge-high';
    case 'ACKNOWLEDGED':  return 'badge-medium';
    case 'RESOLVED':
    case 'ACTIVE':        return 'badge-low';
    case 'CLOSED':
    case 'INACTIVE':      return 'badge-info';
    case 'EXPIRED':
    case 'REVOKED':       return 'badge-critical';
    default:              return 'badge-info';
  }
}

// ── Type icons map ────────────────────────────────────────────────────────────

const TYPE_ICONS = {
  SECURITY_OVERVIEW:   <ShieldAlert size={22} />,
  ALERTS:              <AlertCircle size={22} />,
  INCIDENTS:           <FolderOpen size={22} />,
  THREAT_INTELLIGENCE: <Globe size={22} />,
  ASSETS:              <Server size={22} />,
};

const TYPE_COLORS = {
  SECURITY_OVERVIEW:   '#6366f1',
  ALERTS:              '#ef4444',
  INCIDENTS:           '#f97316',
  THREAT_INTELLIGENCE: '#22d3ee',
  ASSETS:              '#22c55e',
};

// ── Mini bar chart ────────────────────────────────────────────────────────────

function MiniBarChart({ items, colorFn, maxWidth = 260 }) {
  if (!items || items.length === 0) {
    return <p style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>No data available.</p>;
  }
  const maxCount = Math.max(...items.map(i => i.count), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {items.map(item => (
        <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{
            width: '110px', fontSize: '0.78rem', color: 'var(--text-muted)',
            textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap',
            flexShrink: 0,
          }}>
            {item.label}
          </span>
          <div style={{
            flex: 1, height: '14px', background: 'var(--bg-card)',
            borderRadius: '4px', maxWidth: `${maxWidth}px`, position: 'relative',
          }}>
            <div style={{
              position: 'absolute', top: 0, left: 0,
              height: '100%', borderRadius: '4px',
              width: `${Math.round((item.count / maxCount) * 100)}%`,
              background: colorFn ? colorFn(item.label) : 'var(--accent)',
              transition: 'width 0.4s ease',
            }} />
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', width: '28px', textAlign: 'right' }}>
            {item.count}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '10px',
      padding: '16px 20px',
      borderLeft: `3px solid ${color || 'var(--accent)'}`,
      minWidth: 0,
    }}>
      <div style={{ fontSize: '1.6rem', fontWeight: 700, color: color || 'var(--text-primary)', lineHeight: 1.2 }}>
        {value ?? '—'}
      </div>
      <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>{label}</div>
    </div>
  );
}

// ── Preview panel renderers ───────────────────────────────────────────────────

function PreviewSecurityOverview({ report }) {
  const s = report.summary;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: '12px' }}>
        <StatCard label="Total Alerts"       value={s.totalAlerts}       color="#6366f1" />
        <StatCard label="Open Alerts"        value={s.openAlerts}        color={s.openAlerts > 0 ? '#ef4444' : '#22c55e'} />
        <StatCard label="Critical Alerts"    value={s.criticalAlerts}    color="#ef4444" />
        <StatCard label="Total Incidents"    value={s.totalIncidents}    color="#22d3ee" />
        <StatCard label="Open Incidents"     value={s.openIncidents}     color={s.openIncidents > 0 ? '#f97316' : '#22c55e'} />
        <StatCard label="Resolved Incidents" value={s.resolvedIncidents} color="#22c55e" />
        <StatCard label="Active IOCs"        value={s.activeIocs}        color="#f97316" />
        <StatCard label="Assets Tracked"     value={s.totalAssets}       color="#94a3b8" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            Alert Severity
          </h4>
          <MiniBarChart items={report.alertsBySeverity.map(r => ({ label: r.severity, count: r.count }))} colorFn={severityColor} />
        </div>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            Incident Severity
          </h4>
          <MiniBarChart items={report.incidentsBySeverity.map(r => ({ label: r.severity, count: r.count }))} colorFn={severityColor} />
        </div>
      </div>

      <div>
        <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
          Recent Alerts
        </h4>
        <PreviewTable
          headers={['Title', 'Severity', 'Status', 'Fired At']}
          rows={report.recentAlerts.map(a => [
            a.title,
            <span key="sev" className={getSeverityBadgeClass(a.severity)}>{a.severity}</span>,
            <span key="status" className={getStatusBadgeClass(a.status)}>{a.status}</span>,
            fmtDate(a.firedAt),
          ])}
        />
      </div>

      <div>
        <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
          Recent Incidents
        </h4>
        <PreviewTable
          headers={['Title', 'Severity', 'Status', 'Created At']}
          rows={report.recentIncidents.map(i => [
            i.title,
            <span key="sev" className={getSeverityBadgeClass(i.severity)}>{i.severity}</span>,
            <span key="status" className={getStatusBadgeClass(i.status)}>{i.status}</span>,
            fmtDate(i.createdAt),
          ])}
        />
      </div>
    </div>
  );
}

function PreviewAlerts({ report }) {
  const s = report.summary;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: '12px' }}>
        <StatCard label="Total Alerts" value={s.total} color="#6366f1" />
        {s.bySeverity.map(r => (
          <StatCard key={r.severity} label={r.severity} value={r.count} color={severityColor(r.severity)} />
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>Severity</h4>
          <MiniBarChart items={s.bySeverity.map(r => ({ label: r.severity, count: r.count }))} colorFn={severityColor} />
        </div>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>Status</h4>
          <MiniBarChart items={s.byStatus.map(r => ({ label: r.status, count: r.count }))} colorFn={statusColor} />
        </div>
      </div>

      {report.topTriggeredRules && report.topTriggeredRules.length > 0 && (
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>Top Triggered Rules</h4>
          <MiniBarChart items={report.topTriggeredRules.map(r => ({ label: r.ruleName, count: r.count }))} colorFn={() => '#22d3ee'} />
        </div>
      )}

      <div>
        <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
          Alert Listing ({report.alerts.length})
        </h4>
        <PreviewTable
          headers={['Title', 'Severity', 'Status', 'Rule', 'Fired At']}
          rows={report.alerts.map(a => [
            a.title,
            <span key="sev" className={getSeverityBadgeClass(a.severity)}>{a.severity}</span>,
            <span key="status" className={getStatusBadgeClass(a.status)}>{a.status}</span>,
            a.rule,
            fmtDate(a.firedAt),
          ])}
        />
      </div>
    </div>
  );
}

function PreviewIncidents({ report }) {
  const s = report.summary;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: '12px' }}>
        <StatCard label="Total" value={s.total} color="#6366f1" />
        <StatCard
          label="Avg Resolution"
          value={s.avgResolutionHours !== null ? `${s.avgResolutionHours}h` : 'N/A'}
          color="#22d3ee"
        />
        {s.byStatus.map(r => (
          <StatCard key={r.status} label={r.status} value={r.count} color={statusColor(r.status)} />
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>Severity</h4>
          <MiniBarChart items={s.bySeverity.map(r => ({ label: r.severity, count: r.count }))} colorFn={severityColor} />
        </div>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>Status</h4>
          <MiniBarChart items={s.byStatus.map(r => ({ label: r.status, count: r.count }))} colorFn={statusColor} />
        </div>
      </div>

      <div>
        <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
          Incident Listing ({report.incidents.length})
        </h4>
        <PreviewTable
          headers={['Title', 'Severity', 'Status', 'Assigned', 'Alerts', 'Created']}
          rows={report.incidents.map(i => [
            i.title,
            <span key="sev" className={getSeverityBadgeClass(i.severity)}>{i.severity}</span>,
            <span key="status" className={getStatusBadgeClass(i.status)}>{i.status}</span>,
            i.assignedTo,
            i.linkedAlerts,
            fmtDate(i.createdAt),
          ])}
        />
      </div>
    </div>
  );
}

function PreviewThreatIntel({ report }) {
  const s = report.summary;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: '12px' }}>
        <StatCard label="Total IOCs" value={s.total} color="#6366f1" />
        {s.byStatus.map(r => (
          <StatCard key={r.status} label={r.status} value={r.count} color={statusColor(r.status)} />
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>IOC Types</h4>
          <MiniBarChart items={s.byType.map(r => ({ label: r.type, count: r.count }))} colorFn={() => '#22d3ee'} />
        </div>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>Verdicts</h4>
          <MiniBarChart
            items={s.verdictBreakdown.map(r => ({ label: r.verdict ?? 'UNKNOWN', count: r.count }))}
            colorFn={severityColor}
          />
        </div>
      </div>

      <div>
        <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
          IOC Listing ({report.iocs.length})
        </h4>
        <PreviewTable
          headers={['Type', 'Value', 'Severity', 'Status', 'Verdict', 'Added']}
          rows={report.iocs.map(i => [
            i.type,
            <span key="val" style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#22d3ee' }}>{i.value}</span>,
            <span key="sev" className={getSeverityBadgeClass(i.severity)}>{i.severity}</span>,
            <span key="status" className={getStatusBadgeClass(i.status)}>{i.status}</span>,
            i.lastVerdict,
            fmtDate(i.addedAt),
          ])}
        />
      </div>
    </div>
  );
}

function PreviewAssets({ report }) {
  const s = report.summary;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: '12px' }}>
        <StatCard label="Total Assets" value={s.total} color="#6366f1" />
        {s.byStatus.map(r => (
          <StatCard key={r.status} label={r.status} value={r.count} color={statusColor(r.status)} />
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>By Type</h4>
          <MiniBarChart items={s.byType.map(r => ({ label: r.type, count: r.count }))} colorFn={() => '#22d3ee'} />
        </div>
        <div>
          <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>By Criticality</h4>
          <MiniBarChart items={s.byCriticality.map(r => ({ label: r.criticality, count: r.count }))} colorFn={severityColor} />
        </div>
      </div>

      <div>
        <h4 style={{ fontSize: '0.82rem', color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
          Asset Inventory ({report.assets.length})
        </h4>
        <PreviewTable
          headers={['Name', 'Hostname / IP', 'Type', 'Criticality', 'Status', 'Environment']}
          rows={report.assets.map(a => [
            a.name,
            [a.hostname, a.ipAddress].filter(Boolean).join(' / ') || '—',
            a.type,
            <span key="crit" className={getSeverityBadgeClass(a.criticality)}>{a.criticality}</span>,
            <span key="status" className={getStatusBadgeClass(a.status)}>{a.status}</span>,
            a.environment ?? '—',
          ])}
        />
      </div>
    </div>
  );
}

// ── Shared preview table ──────────────────────────────────────────────────────

function PreviewTable({ headers, rows }) {
  if (!rows || rows.length === 0) {
    return <p style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>No records found.</p>;
  }
  return (
    <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid var(--border)' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
        <thead>
          <tr style={{ background: 'var(--bg-card)' }}>
            {headers.map(h => (
              <th key={h} style={{
                padding: '8px 12px', textAlign: 'left',
                color: 'var(--accent)', fontWeight: 600,
                fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.07em',
                borderBottom: '1px solid var(--border)',
              }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, ri) => (
            <tr key={ri} style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.15s' }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-card)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              {row.map((cell, ci) => (
                <td key={ci} style={{ padding: '8px 12px', color: 'var(--text-primary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Preview renderer dispatch ────────────────────────────────────────────────

function renderPreview(type, report) {
  switch (type) {
    case 'SECURITY_OVERVIEW':   return <PreviewSecurityOverview report={report} />;
    case 'ALERTS':              return <PreviewAlerts report={report} />;
    case 'INCIDENTS':           return <PreviewIncidents report={report} />;
    case 'THREAT_INTELLIGENCE': return <PreviewThreatIntel report={report} />;
    case 'ASSETS':              return <PreviewAssets report={report} />;
    default:                    return <p style={{ color: 'var(--text-muted)' }}>Unknown report type.</p>;
  }
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Reports() {
  const { user } = useAuth();
  const canDownload = user?.role === 'ADMIN' || user?.role === 'ANALYST';

  const [reportTypes, setReportTypes]     = useState([]);
  const [selectedType, setSelectedType]   = useState(null);
  const [startDate, setStartDate]         = useState('');
  const [endDate, setEndDate]             = useState('');
  const [previewData, setPreviewData]     = useState(null);
  const [loadingTypes, setLoadingTypes]   = useState(true);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [downloading, setDownloading]     = useState(false);
  const [error, setError]                 = useState(null);
  const [toast, setToast]                 = useState(null);

  // Load report types on mount
  useEffect(() => {
    (async () => {
      try {
        const res = await getReportTypesApi();
        setReportTypes(res.data || []);
      } catch {
        setError('Failed to load report types.');
      } finally {
        setLoadingTypes(false);
      }
    })();
  }, []);

  // Show ephemeral toast
  const showToast = useCallback((msg, ok = true) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 4000);
  }, []);

  // Preview handler
  const handlePreview = useCallback(async () => {
    if (!selectedType) return;
    setLoadingPreview(true);
    setError(null);
    setPreviewData(null);
    try {
      const params = { type: selectedType };
      if (startDate) params.startDate = startDate;
      if (endDate)   params.endDate   = endDate;
      const res = await previewReportApi(params);
      setPreviewData(res.data);
    } catch (e) {
      const msg = e.response?.data?.error || 'Failed to load preview.';
      setError(msg);
    } finally {
      setLoadingPreview(false);
    }
  }, [selectedType, startDate, endDate]);


  // Download handler
  const handleDownload = useCallback(async () => {
    if (!selectedType || !canDownload) return;
    setDownloading(true);
    try {
      const params = { type: selectedType };
      if (startDate) params.startDate = startDate;
      if (endDate)   params.endDate   = endDate;
      const { blobUrl, filename } = await downloadReportApi(params);

      // Trigger browser download
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);

      showToast(`Downloaded: ${filename}`, true);
    } catch (e) {
      const msg = e.response?.data?.error || 'PDF download failed.';
      showToast(msg, false);
    } finally {
      setDownloading(false);
    }
  }, [selectedType, startDate, endDate, canDownload, showToast]);

  const selectedMeta = reportTypes.find(t => t.key === selectedType);

  return (
    <div style={{ padding: '28px 32px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* ── Page header ────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '28px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '44px', height: '44px', borderRadius: '12px',
            background: 'linear-gradient(135deg, #6366f1, #22d3ee)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <FileText size={22} color="#fff" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Security Reports
            </h1>
            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Generate, preview, and download PDF security reports based on live data
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {selectedType && (
            <button
              className="btn-ghost"
              onClick={handlePreview}
              disabled={loadingPreview}
              style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              {loadingPreview
                ? <RefreshCw size={15} className="spin" />
                : <Eye size={15} />}
              {loadingPreview ? 'Loading…' : 'Preview'}
            </button>
          )}

          {canDownload ? (
            <button
              className="btn-primary"
              onClick={handleDownload}
              disabled={!selectedType || downloading}
              style={{ display: 'flex', alignItems: 'center', gap: '6px', opacity: !selectedType ? 0.5 : 1 }}
            >
              {downloading
                ? <RefreshCw size={15} className="spin" />
                : <Download size={15} />}
              {downloading ? 'Generating PDF…' : 'Download PDF'}
            </button>
          ) : (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              color: 'var(--text-muted)', fontSize: '0.82rem',
              border: '1px solid var(--border)', borderRadius: '8px', padding: '7px 14px',
            }}>
              <Lock size={14} />
              Preview only (VIEWER)
            </div>
          )}
        </div>
      </div>

      {/* ── Toast ──────────────────────────────────────────────────────── */}
      {toast && (
        <div style={{
          position: 'fixed', bottom: '24px', right: '24px', zIndex: 9999,
          background: toast.ok ? '#052e16' : '#1c0f0f',
          border: `1px solid ${toast.ok ? '#22c55e' : '#ef4444'}`,
          color: toast.ok ? '#86efac' : '#fca5a5',
          borderRadius: '10px', padding: '12px 18px',
          display: 'flex', alignItems: 'center', gap: '10px',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          maxWidth: '360px',
          animation: 'slideInRight 0.25s ease',
        }}>
          {toast.ok ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
          <span style={{ fontSize: '0.85rem' }}>{toast.msg}</span>
          <button onClick={() => setToast(null)} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'inherit' }}>
            <X size={14} />
          </button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: '24px', alignItems: 'start' }}>
        {/* ── Left panel: type selection + date range ──────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Report type cards */}
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: '12px', padding: '18px',
          }}>
            <h3 style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px' }}>
              Report Type
            </h3>

            {loadingTypes ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: '20px' }}>
                <RefreshCw size={18} className="spin" style={{ color: 'var(--accent)' }} />
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {reportTypes.map(type => {
                  const isSelected = selectedType === type.key;
                  const accentColor = TYPE_COLORS[type.key] || '#6366f1';
                  return (
                    <button
                      key={type.key}
                      onClick={() => {
                        setSelectedType(type.key);
                        setPreviewData(null);
                        setError(null);
                      }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '12px',
                        padding: '10px 12px', borderRadius: '8px', cursor: 'pointer',
                        border: isSelected ? `1px solid ${accentColor}` : '1px solid transparent',
                        background: isSelected ? `${accentColor}18` : 'transparent',
                        transition: 'all 0.15s ease', textAlign: 'left', width: '100%',
                      }}
                      onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'var(--bg-card)'; }}
                      onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'transparent'; }}
                    >
                      <div style={{ color: accentColor, flexShrink: 0 }}>
                        {TYPE_ICONS[type.key]}
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {type.label}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: '2px' }}>
                          {type.description}
                        </div>
                      </div>
                      {isSelected && <ChevronRight size={14} style={{ color: accentColor, flexShrink: 0, marginLeft: 'auto' }} />}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Date range */}
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: '12px', padding: '18px',
          }}>
            <h3 style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Calendar size={13} /> Date Range
            </h3>

            {selectedMeta && !selectedMeta.supportsDateRange ? (
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: 0 }}>
                This report type covers all available data and does not support date filtering.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                    Start date
                  </label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={e => setStartDate(e.target.value)}
                    style={{
                      width: '100%', background: 'var(--bg-card)', border: '1px solid var(--border)',
                      borderRadius: '6px', padding: '7px 10px', color: 'var(--text-primary)', fontSize: '0.83rem',
                    }}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                    End date
                  </label>
                  <input
                    type="date"
                    value={endDate}
                    onChange={e => setEndDate(e.target.value)}
                    style={{
                      width: '100%', background: 'var(--bg-card)', border: '1px solid var(--border)',
                      borderRadius: '6px', padding: '7px 10px', color: 'var(--text-primary)', fontSize: '0.83rem',
                    }}
                  />
                </div>
                {(startDate || endDate) && (
                  <button
                    onClick={() => { setStartDate(''); setEndDate(''); }}
                    style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left', padding: 0, display: 'flex', alignItems: 'center', gap: '4px' }}
                  >
                    <X size={12} /> Clear dates
                  </button>
                )}
                <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', margin: 0 }}>
                  Optional. Leave blank for all available data. Max 365-day range.
                </p>
              </div>
            )}
          </div>

          {/* Tips */}
          <div style={{
            background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.2)',
            borderRadius: '10px', padding: '14px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#6366f1', fontSize: '0.8rem', fontWeight: 600 }}>
              <Zap size={13} /> Tips
            </div>
            <ul style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0, padding: '0 0 0 16px', lineHeight: 1.7 }}>
              <li>Click <strong>Preview</strong> to see live data before downloading.</li>
              <li>PDF download requires <strong>ANALYST</strong> or <strong>ADMIN</strong> role.</li>
              <li>Reports reflect real-time data from the database.</li>
            </ul>
          </div>
        </div>

        {/* ── Right panel: preview ─────────────────────────────────────── */}
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: '12px', minHeight: '500px',
        }}>
          {!selectedType ? (
            /* No selection state */
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '500px', gap: '16px', padding: '40px' }}>
              <div style={{
                width: '72px', height: '72px', borderRadius: '18px',
                background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <FileText size={32} style={{ color: '#6366f1', opacity: 0.6 }} />
              </div>
              <div style={{ textAlign: 'center' }}>
                <h3 style={{ color: 'var(--text-primary)', fontWeight: 600, margin: '0 0 8px' }}>
                  Select a report type
                </h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: 0, maxWidth: '300px' }}>
                  Choose one of the five report types on the left, optionally set a date range, then click Preview or Download PDF.
                </p>
              </div>
            </div>
          ) : loadingPreview ? (
            /* Loading state */
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '500px', gap: '14px' }}>
              <RefreshCw size={28} className="spin" style={{ color: '#6366f1' }} />
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Loading preview data…</p>
            </div>
          ) : error ? (
            /* Error state */
            <div style={{ padding: '32px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
              <AlertCircle size={28} style={{ color: '#ef4444' }} />
              <p style={{ color: '#fca5a5', fontSize: '0.85rem', textAlign: 'center', maxWidth: '360px' }}>{error}</p>
              <button className="btn-ghost" onClick={handlePreview} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <RefreshCw size={14} /> Retry
              </button>
            </div>
          ) : previewData ? (
            /* Preview content */
            <div>
              {/* Preview header */}
              <div style={{
                padding: '20px 24px', borderBottom: '1px solid var(--border)',
                background: `linear-gradient(135deg, ${TYPE_COLORS[previewData.type] || '#6366f1'}18, transparent)`,
                borderRadius: '12px 12px 0 0',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ color: TYPE_COLORS[previewData.type] || '#6366f1' }}>
                    {TYPE_ICONS[previewData.type]}
                  </div>
                  <div>
                    <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {reportTypes.find(t => t.key === previewData.type)?.label ?? previewData.type}
                    </h2>
                    <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Generated {fmtDate(previewData.generatedAt)}
                      {previewData.dateRange?.startDate && ` • From ${fmtDate(previewData.dateRange.startDate)}`}
                      {previewData.dateRange?.endDate   && ` to ${fmtDate(previewData.dateRange.endDate)}`}
                    </p>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="btn-ghost"
                    onClick={handlePreview}
                    style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.8rem' }}
                  >
                    <RefreshCw size={13} /> Refresh
                  </button>
                  {canDownload && (
                    <button
                      className="btn-primary"
                      onClick={handleDownload}
                      disabled={downloading}
                      style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.8rem' }}
                    >
                      {downloading ? <RefreshCw size={13} className="spin" /> : <Download size={13} />}
                      {downloading ? 'Generating…' : 'Download PDF'}
                    </button>
                  )}
                </div>
              </div>

              {/* Preview body */}
              <div style={{ padding: '24px' }}>
                {renderPreview(previewData.type, previewData.report)}
              </div>
            </div>
          ) : (
            /* Selected but not previewed yet */
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '500px', gap: '16px', padding: '40px' }}>
              <div style={{
                width: '64px', height: '64px', borderRadius: '16px',
                background: `${TYPE_COLORS[selectedType] || '#6366f1'}18`,
                border: `1px solid ${TYPE_COLORS[selectedType] || '#6366f1'}40`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: TYPE_COLORS[selectedType] || '#6366f1',
              }}>
                {TYPE_ICONS[selectedType]}
              </div>
              <div style={{ textAlign: 'center' }}>
                <h3 style={{ color: 'var(--text-primary)', fontWeight: 600, margin: '0 0 8px' }}>
                  {selectedMeta?.label}
                </h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: '0 0 20px', maxWidth: '320px' }}>
                  {selectedMeta?.description}
                </p>
                <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                  <button
                    className="btn-ghost"
                    onClick={handlePreview}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <Eye size={14} /> Preview data
                  </button>
                  {canDownload && (
                    <button
                      className="btn-primary"
                      onClick={handleDownload}
                      disabled={downloading}
                      style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                    >
                      {downloading ? <RefreshCw size={14} className="spin" /> : <Download size={14} />}
                      {downloading ? 'Generating…' : 'Download PDF'}
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes slideInRight {
          from { opacity: 0; transform: translateX(20px); }
          to   { opacity: 1; transform: translateX(0); }
        }
      `}</style>
    </div>
  );
}
