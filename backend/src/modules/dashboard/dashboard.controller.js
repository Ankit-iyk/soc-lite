// src/modules/dashboard/dashboard.controller.js
// Controllers for Security Operations Center Dashboard (Phase 7).

import prisma from '../../config/prisma.js';
import { validateDashboardQuery } from './dashboard.validation.js';

/**
 * Format human-readable incident identifier.
 * e.g. "INC-A1B2C3D4"
 */
function formatReadableId(id) {
  if (!id || typeof id !== 'string') return 'INC-UNKNOWN';
  return `INC-${id.slice(0, 8).toUpperCase()}`;
}

/**
 * Generates contiguous, non-overlapping time buckets for time series charting.
 * @param {string} timeWindow - '24h' or '7d'
 * @param {Date} now - current time
 * @returns {{ buckets: Array<{ label: string, timestamp: string, count: number, _startMs: number, _endMs: number }>, windowStart: Date }}
 */
function buildTimeBuckets(timeWindow, now) {
  const buckets = [];
  const nowMs = now.getTime();

  if (timeWindow === '7d') {
    // 7 daily buckets (each 24h = 86,400,000 ms)
    const dayMs = 86400000;
    const windowStartMs = nowMs - 7 * dayMs;

    for (let i = 0; i < 7; i++) {
      const startMs = windowStartMs + i * dayMs;
      const endMs = startMs + dayMs;
      const endDate = new Date(endMs);

      // Deterministic UTC-based date label e.g. "Oct 24"
      const label = endDate.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        timeZone: 'UTC',
      });

      buckets.push({
        label,
        timestamp: endDate.toISOString(),
        count: 0,
        _startMs: startMs,
        _endMs: endMs,
      });
    }

    return { buckets, windowStart: new Date(windowStartMs) };
  }

  // Default: 24 hourly buckets (each 1h = 3,600,000 ms)
  const hourMs = 3600000;
  const windowStartMs = nowMs - 24 * hourMs;

  for (let i = 0; i < 24; i++) {
    const startMs = windowStartMs + i * hourMs;
    const endMs = startMs + hourMs;
    const endDate = new Date(endMs);

    // Deterministic UTC-based hour label e.g. "14:00"
    const hours = String(endDate.getUTCHours()).padStart(2, '0');
    const label = `${hours}:00`;

    buckets.push({
      label,
      timestamp: endDate.toISOString(),
      count: 0,
      _startMs: startMs,
      _endMs: endMs,
    });
  }

  return { buckets, windowStart: new Date(windowStartMs) };
}

/**
 * GET /api/dashboard/summary
 * Returns aggregated metrics, alert volume time series, severity distributions,
 * incident status breakdowns, and recent items.
 *
 * Query parameters:
 * - timeWindow: '24h' | '7d' (default: '24h')
 * - recentLimit: number (1-20, default: 5)
 *
 * Protected: ADMIN, ANALYST, VIEWER can view dashboard metrics.
 */
export async function getDashboardSummary(req, res, next) {
  try {
    const validation = validateDashboardQuery(req.query);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        error: validation.error,
      });
    }

    const { timeWindow, recentLimit } = validation.sanitized;
    const now = new Date();
    const { buckets, windowStart } = buildTimeBuckets(timeWindow, now);

    // Execute independent database queries concurrently using Promise.all
    const [
      totalEvents,
      totalAlerts,
      openAlerts,
      criticalHighAlerts,
      openIncidents,
      investigatingIncidents,
      alertSeverityGroups,
      incidentStatusGroups,
      alertsInWindow,
      recentAlerts,
      recentIncidentsRaw,
    ] = await Promise.all([
      // 1. Total events count
      prisma.event.count(),

      // 2. Total alerts count
      prisma.alert.count(),

      // 3. Open alerts count
      prisma.alert.count({
        where: { status: 'OPEN' },
      }),

      // 4. Critical & High severity alerts
      prisma.alert.count({
        where: { severity: { in: ['CRITICAL', 'HIGH'] } },
      }),

      // 5. Open incidents
      prisma.incident.count({
        where: { status: 'OPEN' },
      }),

      // 6. Investigating incidents
      prisma.incident.count({
        where: { status: 'INVESTIGATING' },
      }),

      // 7. Alert severity distribution
      prisma.alert.groupBy({
        by: ['severity'],
        _count: { _all: true },
      }),

      // 8. Incident status distribution
      prisma.incident.groupBy({
        by: ['status'],
        _count: { _all: true },
      }),

      // 9. Alerts within the chart time window
      prisma.alert.findMany({
        where: {
          firedAt: {
            gte: windowStart,
            lte: now,
          },
        },
        select: {
          id: true,
          firedAt: true,
        },
      }),

      // 10. Recent alerts
      prisma.alert.findMany({
        take: recentLimit,
        orderBy: [
          { firedAt: 'desc' },
          { id: 'desc' },
        ],
        select: {
          id: true,
          title: true,
          severity: true,
          status: true,
          firedAt: true,
          rule: {
            select: {
              id: true,
              name: true,
              type: true,
            },
          },
        },
      }),

      // 11. Recent incidents
      prisma.incident.findMany({
        take: recentLimit,
        orderBy: [
          { createdAt: 'desc' },
          { id: 'desc' },
        ],
        include: {
          assignedTo: {
            select: {
              id: true,
              name: true,
              email: true,
              role: true,
            },
          },
          _count: {
            select: {
              incidentAlerts: true,
            },
          },
        },
      }),
    ]);

    // ── Aggregate alerts into time series buckets ────────────────────────────
    for (const alert of alertsInWindow) {
      const alertTime = alert.firedAt.getTime();
      for (let i = 0; i < buckets.length; i++) {
        const bucket = buckets[i];
        // If alert falls in bucket [start, end), or is exactly at now in the final bucket
        if (
          (alertTime >= bucket._startMs && alertTime < bucket._endMs) ||
          (i === buckets.length - 1 && alertTime >= bucket._startMs && alertTime <= bucket._endMs)
        ) {
          bucket.count += 1;
          break;
        }
      }
    }

    // Strip internal helper timestamps
    const alertsOverTime = buckets.map(({ label, timestamp, count }) => ({
      label,
      timestamp,
      count,
    }));

    // ── Build complete Severity Distribution (all enum values represented) ──
    const severityMap = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    for (const group of alertSeverityGroups) {
      if (group.severity in severityMap) {
        severityMap[group.severity] = group._count._all;
      }
    }
    const alertSeverityDistribution = [
      { severity: 'CRITICAL', count: severityMap.CRITICAL },
      { severity: 'HIGH', count: severityMap.HIGH },
      { severity: 'MEDIUM', count: severityMap.MEDIUM },
      { severity: 'LOW', count: severityMap.LOW },
    ];

    // ── Build complete Incident Status Distribution ──────────────────────────
    const statusMap = {
      OPEN: 0,
      INVESTIGATING: 0,
      RESOLVED: 0,
      CLOSED: 0,
    };
    for (const group of incidentStatusGroups) {
      if (group.status in statusMap) {
        statusMap[group.status] = group._count._all;
      }
    }
    const incidentStatusDistribution = [
      { status: 'OPEN', count: statusMap.OPEN },
      { status: 'INVESTIGATING', count: statusMap.INVESTIGATING },
      { status: 'RESOLVED', count: statusMap.RESOLVED },
      { status: 'CLOSED', count: statusMap.CLOSED },
    ];

    // ── Format Recent Incidents ──────────────────────────────────────────────
    const recentIncidents = recentIncidentsRaw.map((inc) => ({
      id: inc.id,
      readableId: formatReadableId(inc.id),
      title: inc.title,
      severity: inc.severity,
      status: inc.status,
      createdAt: inc.createdAt,
      assignedTo: inc.assignedTo,
      alertCount: inc._count?.incidentAlerts || 0,
    }));

    return res.status(200).json({
      success: true,
      data: {
        kpis: {
          totalEvents,
          totalAlerts,
          openAlerts,
          criticalHighAlerts,
          openIncidents,
          investigatingIncidents,
        },
        alertsOverTime,
        alertSeverityDistribution,
        incidentStatusDistribution,
        recentAlerts,
        recentIncidents,
        generatedAt: now.toISOString(),
      },
    });
  } catch (err) {
    next(err);
  }
}
