// src/router/index.jsx
// Defines all application routes using React Router v6 data router.
//
// Structure:
//   / (AppShell layout)
//   ├── /              → Dashboard
//   ├── /logs          → Logs
//   ├── /alerts        → Alerts
//   ├── /incidents     → Incidents
//   ├── /assets        → Assets
//   ├── /threat-intel  → ThreatIntel
//   ├── /rules         → Rules
//   ├── /reports       → Reports
//   └── /settings      → Settings
//
//   /login             → Login (outside the shell — no sidebar/topbar)

import { createBrowserRouter } from 'react-router-dom';
import AppShell   from '../components/layout/AppShell';
import Dashboard  from '../pages/Dashboard';
import Logs       from '../pages/Logs';
import Alerts     from '../pages/Alerts';
import Incidents  from '../pages/Incidents';
import Assets     from '../pages/Assets';
import ThreatIntel from '../pages/ThreatIntel';
import Rules      from '../pages/Rules';
import Reports    from '../pages/Reports';
import Settings   from '../pages/Settings';
import Login      from '../pages/Login';

export const router = createBrowserRouter([
  // Public route (no layout shell)
  {
    path: '/login',
    element: <Login />,
  },
  // Protected shell — all main pages live inside here
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true,              element: <Dashboard />  },
      { path: 'logs',             element: <Logs />       },
      { path: 'alerts',           element: <Alerts />     },
      { path: 'incidents',        element: <Incidents />  },
      { path: 'assets',           element: <Assets />     },
      { path: 'threat-intel',     element: <ThreatIntel />},
      { path: 'rules',            element: <Rules />      },
      { path: 'reports',          element: <Reports />    },
      { path: 'settings',         element: <Settings />   },
    ],
  },
]);
