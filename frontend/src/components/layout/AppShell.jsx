// src/components/layout/AppShell.jsx
// Root layout component that wraps all authenticated pages.
// Renders the sidebar + topbar + page outlet.
// Polls the backend /api/health every 30 s to show API status.

import { useState, useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Topbar from './Topbar';

const HEALTH_URL = '/api/health'; // proxied to http://localhost:3000/api/health by Vite

export default function AppShell() {
  const [collapsed, setCollapsed]   = useState(false);
  const [apiStatus, setApiStatus]   = useState('checking'); // 'checking' | 'ok' | 'error'

  // Poll the backend health endpoint
  useEffect(() => {
    let cancelled = false;

    async function checkHealth() {
      try {
        const res = await fetch(HEALTH_URL);
        if (!cancelled) setApiStatus(res.ok ? 'ok' : 'error');
      } catch {
        if (!cancelled) setApiStatus('error');
      }
    }

    checkHealth(); // immediate first check
    const interval = setInterval(checkHealth, 30_000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  return (
    <div className="app-shell">
      <Sidebar
        collapsed={collapsed}
        onToggle={() => setCollapsed(c => !c)}
      />
      <div className="main-content">
        <Topbar apiStatus={apiStatus} />
        <main className="page-content">
          {/* React Router renders the matched page here */}
          <Outlet />
        </main>
      </div>
    </div>
  );
}
