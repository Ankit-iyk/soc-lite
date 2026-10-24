// src/pages/Dashboard.jsx
// Phase 1: Shows the layout and structure of the dashboard without any data.
// Live statistics and charts will be wired up in Phase 7
// after the backend, database, and detection engine are in place.

import { LayoutDashboard, BellDot, FolderOpen, Activity } from 'lucide-react';

// These are UI skeleton cards — they show the dashboard structure,
// NOT real numbers. The labels make this explicit.
const SKELETON_CARDS = [
  { icon: Activity,       label: 'Total Events Today',  note: 'Live data — Phase 7' },
  { icon: BellDot,        label: 'Open Alerts',         note: 'Live data — Phase 7' },
  { icon: FolderOpen,     label: 'Active Incidents',    note: 'Live data — Phase 7' },
  { icon: LayoutDashboard,label: 'Assets Monitored',    note: 'Live data — Phase 7' },
];

function SkeletonCard({ icon: Icon, label, note }) {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <div style={{
          width: 36, height: 36,
          background: 'var(--color-bg-elevated)',
          borderRadius: 8,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '1px solid var(--color-border)',
        }}>
          <Icon size={16} color="var(--color-accent)" />
        </div>
        <span style={{ fontSize: '13px', color: 'var(--color-text-secondary)', fontWeight: 500 }}>
          {label}
        </span>
      </div>
      {/* Skeleton shimmer instead of a made-up number */}
      <div style={{
        height: 28,
        background: 'linear-gradient(90deg, var(--color-bg-elevated) 25%, var(--color-border) 50%, var(--color-bg-elevated) 75%)',
        backgroundSize: '200% 100%',
        borderRadius: 6,
        animation: 'shimmer 1.8s infinite',
      }} />
      <p style={{ margin: 0, fontSize: '11px', color: 'var(--color-text-muted)' }}>
        ⚙ {note}
      </p>
    </div>
  );
}

function ChartPlaceholder({ title, phase }) {
  return (
    <div className="card" style={{ minHeight: 220 }}>
      <p className="card-title">{title}</p>
      <div style={{
        height: 160,
        border: '2px dashed var(--color-border)',
        borderRadius: 8,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '0.5rem',
        color: 'var(--color-text-muted)',
        fontSize: '12px',
      }}>
        <Activity size={22} color="var(--color-border)" />
        <span>Recharts chart — Phase {phase}</span>
      </div>
    </div>
  );
}

export default function Dashboard() {
  return (
    <div className="fade-in">
      <div className="page-header">
        <h1 className="page-title">Security Operations Dashboard</h1>
        <p className="page-subtitle">
          Live statistics will appear here after log ingestion and the detection
          engine are implemented (Phases 3 – 7).
        </p>
      </div>

      {/* KPI row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '1rem',
        marginBottom: '1.5rem',
      }}>
        {SKELETON_CARDS.map(card => (
          <SkeletonCard key={card.label} {...card} />
        ))}
      </div>

      {/* Chart row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
        gap: '1rem',
      }}>
        <ChartPlaceholder title="Events Over Time (24 h)"       phase={7} />
        <ChartPlaceholder title="Alerts by Severity"            phase={7} />
        <ChartPlaceholder title="Top Source IPs"                phase={7} />
        <ChartPlaceholder title="Incidents by Status"           phase={7} />
      </div>

      {/* Shimmer keyframe — defined inline because it's page-specific */}
      <style>{`
        @keyframes shimmer {
          0%   { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>
    </div>
  );
}
