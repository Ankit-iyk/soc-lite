// src/components/layout/Topbar.jsx
// Top navigation bar showing: page title, API health dot, user profile badge, and logout.

import { Bell, User, LogOut, LogIn } from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

// Map routes → human-readable titles
const PAGE_TITLES = {
  '/':            'Dashboard',
  '/logs':        'Security Logs',
  '/alerts':      'Alert Management',
  '/incidents':   'Incident Tracking',
  '/assets':      'Asset Management',
  '/threat-intel':'Threat Intelligence',
  '/rules':       'Detection Rules',
  '/reports':     'Security Reports',
  '/settings':    'Settings',
};

export default function Topbar({ apiStatus }) {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { user, isAuthenticated, logout } = useAuth();
  const title = PAGE_TITLES[pathname] ?? 'SOC Lite';

  async function handleLogout() {
    await logout();
    navigate('/login');
  }

  return (
    <header className="topbar">
      {/* Page title */}
      <h1 style={{ flex: 1, margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--color-text-primary)' }}>
        {title}
      </h1>

      {/* API health indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '12px', color: 'var(--color-text-muted)', marginRight: '0.75rem' }}>
        <span
          className={`status-dot ${apiStatus === 'ok' ? 'online' : apiStatus === 'checking' ? 'idle' : 'offline'}`}
        />
        <span>
          {apiStatus === 'ok'       ? 'API Online'
         : apiStatus === 'checking' ? 'Connecting…'
         : 'API Offline'}
        </span>
      </div>

      {/* Notification bell (placeholder) */}
      <button
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-text-secondary)', padding: '0.4rem', marginRight: '0.5rem' }}
        title="Notifications (coming in Phase 5)"
      >
        <Bell size={16} />
      </button>

      {/* User Session Info / Profile */}
      {isAuthenticated && user ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div
              style={{
                width: 30, height: 30,
                borderRadius: '50%',
                background: 'rgba(0, 212, 170, 0.12)',
                border: '1px solid rgba(0, 212, 170, 0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--color-accent)',
              }}
              title={user.email}
            >
              <User size={15} />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.2 }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>
                {user.name}
              </span>
              <span style={{
                fontSize: '0.65rem',
                fontFamily: 'var(--font-mono)',
                color: user.role === 'ADMIN' ? 'var(--color-critical)' : 'var(--color-accent)',
                letterSpacing: '0.04em',
              }}>
                [{user.role}]
              </span>
            </div>
          </div>

          <button
            onClick={handleLogout}
            style={{
              background: 'none',
              border: '1px solid var(--color-border)',
              borderRadius: '6px',
              padding: '0.35rem 0.55rem',
              cursor: 'pointer',
              color: 'var(--color-text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              fontSize: '0.75rem',
              transition: 'all 0.15s',
            }}
            title="Log out of console"
          >
            <LogOut size={13} />
            <span>Logout</span>
          </button>
        </div>
      ) : (
        <button
          onClick={() => navigate('/login')}
          style={{
            backgroundColor: 'var(--color-accent)',
            color: '#080d14',
            border: 'none',
            borderRadius: '6px',
            padding: '0.4rem 0.75rem',
            cursor: 'pointer',
            fontSize: '0.78rem',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <LogIn size={13} />
          <span>Sign In</span>
        </button>
      )}
    </header>
  );
}
