import { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CircleCheck,
  CircleX,
  Clock3,
  Monitor,
  RefreshCw,
  ShieldOff,
} from 'lucide-react';
import { getCollectorsApi } from '../api/collectors.api';

function formatTime(value) {
  if (!value) return 'Never';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}

function collectorState(collector, now) {
  if (!collector.enabled || collector.revokedAt) return 'REVOKED';
  const status = collector.collectorStatus;
  if (!status) return 'WAITING';
  if (status.status === 'ERROR') return 'ERROR';
  const lastCheckin = new Date(status.lastCheckinAt).getTime();
  if (!Number.isFinite(lastCheckin) || now - lastCheckin > 90_000) return 'STALE';
  if (status.status !== 'OK') return 'WAITING';
  return 'OK';
}

const STATE_STYLE = {
  OK: { label: 'Healthy', color: '#34d399', Icon: CircleCheck },
  ERROR: { label: 'Error', color: '#fb7185', Icon: CircleX },
  STALE: { label: 'Stale', color: '#fbbf24', Icon: AlertTriangle },
  WAITING: { label: 'Awaiting check-in', color: 'var(--text-muted)', Icon: Clock3 },
  REVOKED: { label: 'Revoked', color: 'var(--text-muted)', Icon: ShieldOff },
};

export default function Collectors() {
  const [collectors, setCollectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [now, setNow] = useState(0);
  const [refreshVersion, setRefreshVersion] = useState(0);

  useEffect(() => {
    let active = true;

    async function loadCollectors() {
      try {
        const response = await getCollectorsApi();
        if (active) {
          setCollectors(response.data || []);
          setError('');
        }
      } catch (requestError) {
        if (active) setError(requestError.response?.data?.error || 'Collector status could not be loaded.');
      } finally {
        if (active) {
          setLoading(false);
          setNow(new Date().getTime());
        }
      }
    }

    loadCollectors();
    const timer = setInterval(loadCollectors, 15_000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [refreshVersion]);

  const healthyCount = collectors.filter((collector) => collectorState(collector, now) === 'OK').length;

  return (
    <section style={{ padding: '28px 32px', maxWidth: '1440px', margin: '0 auto' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap', marginBottom: 24 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--accent)', marginBottom: 8 }}>
            <Activity size={18} />
            <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase' }}>Collection fleet</span>
          </div>
          <h1 style={{ margin: 0, color: 'var(--text-primary)', fontSize: '1.55rem' }}>Windows collectors</h1>
          <p style={{ margin: '7px 0 0', color: 'var(--text-muted)', fontSize: 13 }}>
            {healthyCount} healthy of {collectors.filter((collector) => collector.enabled).length} enabled
          </p>
        </div>
        <button
          type="button"
          onClick={() => setRefreshVersion((version) => version + 1)}
          title="Refresh collector status"
          aria-label="Refresh collector status"
          disabled={loading}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '9px 12px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-primary)', cursor: 'pointer' }}
        >
          <RefreshCw size={15} /> Refresh
        </button>
      </header>

      {error && (
        <div role="alert" style={{ padding: 12, marginBottom: 16, border: '1px solid #fb7185', borderRadius: 6, color: '#fecdd3' }}>
          {error}
        </div>
      )}

      <div style={{ overflowX: 'auto', borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
        <table style={{ width: '100%', minWidth: 850, borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase' }}>
              {['Collector', 'Status', 'Last check-in', 'Last event', 'Events', 'Channels', 'Recent error'].map((heading) => (
                <th key={heading} style={{ padding: '12px 10px', fontWeight: 700 }}>{heading}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {collectors.map((collector) => {
              const status = collector.collectorStatus;
              const state = collectorState(collector, now);
              const { label, color, Icon } = STATE_STYLE[state];
              return (
                <tr key={collector.id} style={{ borderTop: '1px solid var(--border)', color: 'var(--text-primary)', fontSize: 13 }}>
                  <td style={{ padding: '15px 10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 9, fontWeight: 650 }}>
                      <Monitor size={16} color="var(--accent)" /> {collector.name}
                    </div>
                    <div style={{ margin: '5px 0 0 25px', color: 'var(--text-muted)', fontSize: 12 }}>
                      {status?.hostname || 'Host not reported'}{status?.platform ? ` · ${status.platform}` : ''}
                    </div>
                  </td>
                  <td style={{ padding: '15px 10px', whiteSpace: 'nowrap' }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color, fontWeight: 650 }}>
                      <Icon size={15} /> {label}
                    </span>
                  </td>
                  <td style={{ padding: '15px 10px', whiteSpace: 'nowrap' }}>{formatTime(status?.lastCheckinAt)}</td>
                  <td style={{ padding: '15px 10px', whiteSpace: 'nowrap' }}>{formatTime(status?.lastEventAt)}</td>
                  <td style={{ padding: '15px 10px' }}>{status?.eventsIngested ?? 0}</td>
                  <td style={{ padding: '15px 10px' }}>{status?.channels?.join(', ') || 'Not reported'}</td>
                  <td style={{ padding: '15px 10px', color: status?.lastError ? '#fda4af' : 'var(--text-muted)', maxWidth: 260 }}>
                    {status?.lastError || 'None'}
                  </td>
                </tr>
              );
            })}
            {!loading && !error && collectors.length === 0 && (
              <tr>
                <td colSpan={7} style={{ padding: '36px 12px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No collectors enrolled.
                </td>
              </tr>
            )}
            {loading && collectors.length === 0 && (
              <tr>
                <td colSpan={7} style={{ padding: '36px 12px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Loading collector status…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 12, color: 'var(--text-muted)', fontSize: 12 }}>
        <Clock3 size={13} /> A collector is marked stale after 90 seconds without a check-in.
      </p>
    </section>
  );
}