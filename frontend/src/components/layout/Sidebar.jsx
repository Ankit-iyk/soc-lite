// src/components/layout/Sidebar.jsx
// The persistent left-hand navigation panel.
// Uses React Router's NavLink so the active page is automatically highlighted.

import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ScrollText,
  BellDot,
  FolderOpen,
  Server,
  Shield,
  SlidersHorizontal,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { cn } from '../../utils/cn';

// Navigation items — grouped by section
const NAV = [
  {
    section: 'Overview',
    items: [
      { to: '/',          icon: LayoutDashboard,    label: 'Dashboard'    },
    ],
  },
  {
    section: 'Detection',
    items: [
      { to: '/logs',      icon: ScrollText,          label: 'Logs'         },
      { to: '/alerts',    icon: BellDot,             label: 'Alerts'       },
      { to: '/incidents', icon: FolderOpen,          label: 'Incidents'    },
    ],
  },
  {
    section: 'Intelligence',
    items: [
      { to: '/assets',       icon: Server,            label: 'Assets'        },
      { to: '/threat-intel', icon: Shield,            label: 'Threat Intel'  },
      { to: '/rules',        icon: SlidersHorizontal, label: 'Rules'         },
    ],
  },
  {
    section: 'Reporting',
    items: [
      { to: '/reports',   icon: FileText,            label: 'Reports'      },
      { to: '/settings',  icon: Settings,            label: 'Settings'     },
    ],
  },
];

export default function Sidebar({ collapsed, onToggle }) {
  return (
    <aside className={cn('sidebar', collapsed && 'sidebar-collapsed')}>
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="brand-icon">
          <Shield size={18} color="#000" />
        </div>
        {!collapsed && (
          <div className="brand-text">
            <span className="brand-name">SOC Lite</span>
            <span className="brand-tagline">Threat Operations</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1 }}>
        {NAV.map(({ section, items }) => (
          <div key={section} className="nav-section">
            {!collapsed && (
              <p className="nav-section-label">{section}</p>
            )}
            {items.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}  /* exact match for the dashboard root */
                className={({ isActive }) =>
                  cn('nav-item', isActive && 'active')
                }
                title={collapsed ? label : undefined}
              >
                <Icon className="nav-icon" />
                {!collapsed && <span>{label}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        className="nav-item"
        onClick={onToggle}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        style={{ marginBottom: '0.75rem' }}
      >
        {collapsed
          ? <ChevronRight className="nav-icon" />
          : <><ChevronLeft className="nav-icon" /><span>Collapse</span></>
        }
      </button>
    </aside>
  );
}
