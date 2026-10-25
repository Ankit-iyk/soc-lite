// src/router/index.jsx
// Defines all application routes using React Router v6 data router.
// Implements route-level lazy loading and code splitting for optimal bundle performance (Phase 12).

import { createBrowserRouter } from 'react-router-dom';
import AppShell from '../components/layout/AppShell';

export const router = createBrowserRouter([
  // Public route (no layout shell)
  {
    path: '/login',
    lazy: async () => {
      const { default: Component } = await import('../pages/Login');
      return { Component };
    },
  },
  // Protected shell — all main pages live inside here
  {
    path: '/',
    element: <AppShell />,
    children: [
      {
        index: true,
        lazy: async () => {
          const { default: Component } = await import('../pages/Dashboard');
          return { Component };
        },
      },
      {
        path: 'logs',
        lazy: async () => {
          const { default: Component } = await import('../pages/Logs');
          return { Component };
        },
      },
      {
        path: 'alerts',
        lazy: async () => {
          const { default: Component } = await import('../pages/Alerts');
          return { Component };
        },
      },
      {
        path: 'incidents',
        lazy: async () => {
          const { default: Component } = await import('../pages/Incidents');
          return { Component };
        },
      },
      {
        path: 'assets',
        lazy: async () => {
          const { default: Component } = await import('../pages/Assets');
          return { Component };
        },
      },
      {
        path: 'threat-intel',
        lazy: async () => {
          const { default: Component } = await import('../pages/ThreatIntel');
          return { Component };
        },
      },
      {
        path: 'rules',
        lazy: async () => {
          const { default: Component } = await import('../pages/Rules');
          return { Component };
        },
      },
      {
        path: 'reports',
        lazy: async () => {
          const { default: Component } = await import('../pages/Reports');
          return { Component };
        },
      },
      {
        path: 'settings',
        lazy: async () => {
          const { default: Component } = await import('../pages/Settings');
          return { Component };
        },
      },
    ],
  },
]);
