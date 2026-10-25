// backend/src/modules/reports/reports.service.js
// Data-gathering service for Phase 10 Security Reports.
// Each report type collects data from Prisma and returns a structured payload.

import prisma from '../../config/prisma.js';

/**
 * Build a Prisma date range filter from optional start/end Dates.
 * Returns an object suitable for use in a `where` clause.
 * @param {Date|null} startDate
 * @param {Date|null} endDate
 * @param {string} field - The DateTime field to filter on
 * @returns {object}
 */
function buildDateFilter(startDate, endDate, field) {
  if (!startDate && !endDate) return {};
  const filter = {};
  if (startDate) filter.gte = startDate;
  if (endDate)   filter.lte = endDate;
  return { [field]: filter };
}

// ── Security Overview ────────────────────────────────────────────────────────

export async function getSecurityOverviewData({ startDate, endDate }) {
  const alertWhere  = buildDateFilter(startDate, endDate, 'firedAt');
  const incWhere    = buildDateFilter(startDate, endDate, 'createdAt');
  const iocWhere    = buildDateFilter(startDate, endDate, 'addedAt');
  const auditWhere  = buildDateFilter(startDate, endDate, 'timestamp');

  const [
    totalAlerts,
    openAlerts,
    criticalAlerts,
    totalIncidents,
    openIncidents,
    resolvedIncidents,
    totalIocs,
    activeIocs,
    totalAssets,
    totalAuditLogs,
    alertsBySeverity,
    incidentsBySeverity,
    recentAlerts,
    recentIncidents,
  ] = await Promise.all([
    prisma.alert.count({ where: alertWhere }),
    prisma.alert.count({ where: { ...alertWhere, status: 'OPEN' } }),
    prisma.alert.count({ where: { ...alertWhere, severity: 'CRITICAL' } }),
    prisma.incident.count({ where: incWhere }),
    prisma.incident.count({ where: { ...incWhere, status: 'OPEN' } }),
    prisma.incident.count({ where: { ...incWhere, status: 'RESOLVED' } }),
    prisma.threatIndicator.count({ where: iocWhere }),
    prisma.threatIndicator.count({ where: { ...iocWhere, status: 'ACTIVE' } }),
    prisma.asset.count(),
    prisma.auditLog.count({ where: auditWhere }),
    prisma.alert.groupBy({ by: ['severity'], where: alertWhere, _count: { id: true } }),
    prisma.incident.groupBy({ by: ['severity'], where: incWhere, _count: { id: true } }),
    prisma.alert.findMany({
      where: alertWhere,
      orderBy: { firedAt: 'desc' },
      take: 10,
      select: { id: true, title: true, severity: true, status: true, firedAt: true },
    }),
    prisma.incident.findMany({
      where: incWhere,
      orderBy: { createdAt: 'desc' },
      take: 10,
      select: { id: true, title: true, severity: true, status: true, createdAt: true },
    }),
  ]);

  return {
    summary: {
      totalAlerts, openAlerts, criticalAlerts,
      totalIncidents, openIncidents, resolvedIncidents,
      totalIocs, activeIocs,
      totalAssets, totalAuditLogs,
    },
    alertsBySeverity: alertsBySeverity.map(r => ({ severity: r.severity, count: r._count.id })),
    incidentsBySeverity: incidentsBySeverity.map(r => ({ severity: r.severity, count: r._count.id })),
    recentAlerts,
    recentIncidents,
  };
}

// ── Alerts Report ────────────────────────────────────────────────────────────

export async function getAlertsReportData({ startDate, endDate }) {
  const where = buildDateFilter(startDate, endDate, 'firedAt');

  const [total, bySeverity, byStatus, topRules, recentAlerts] = await Promise.all([
    prisma.alert.count({ where }),
    prisma.alert.groupBy({ by: ['severity'], where, _count: { id: true } }),
    prisma.alert.groupBy({ by: ['status'], where, _count: { id: true } }),
    prisma.alert.groupBy({
      by: ['ruleId'],
      where: { ...where, ruleId: { not: null } },
      _count: { id: true },
      orderBy: { _count: { id: 'desc' } },
      take: 5,
    }),
    prisma.alert.findMany({
      where,
      orderBy: { firedAt: 'desc' },
      take: 50,
      include: {
        rule: { select: { name: true, type: true } },
      },
    }),
  ]);

  // Resolve rule names for top rules
  const ruleIds = topRules.map(r => r.ruleId).filter(Boolean);
  const rules = ruleIds.length
    ? await prisma.detectionRule.findMany({
        where: { id: { in: ruleIds } },
        select: { id: true, name: true },
      })
    : [];
  const ruleMap = Object.fromEntries(rules.map(r => [r.id, r.name]));

  return {
    summary: {
      total,
      bySeverity: bySeverity.map(r => ({ severity: r.severity, count: r._count.id })),
      byStatus:   byStatus.map(r => ({ status: r.status, count: r._count.id })),
    },
    topTriggeredRules: topRules.map(r => ({
      ruleName: ruleMap[r.ruleId] ?? 'Unknown',
      count: r._count.id,
    })),
    alerts: recentAlerts.map(a => ({
      id: a.id,
      title: a.title,
      severity: a.severity,
      status: a.status,
      rule: a.rule?.name ?? '—',
      firedAt: a.firedAt,
    })),
  };
}

// ── Incidents Report ─────────────────────────────────────────────────────────

export async function getIncidentsReportData({ startDate, endDate }) {
  const where = buildDateFilter(startDate, endDate, 'createdAt');

  const [total, bySeverity, byStatus, incidents] = await Promise.all([
    prisma.incident.count({ where }),
    prisma.incident.groupBy({ by: ['severity'], where, _count: { id: true } }),
    prisma.incident.groupBy({ by: ['status'], where, _count: { id: true } }),
    prisma.incident.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 50,
      include: {
        assignedTo:     { select: { name: true, email: true } },
        incidentAlerts: { select: { alertId: true } },
      },
    }),
  ]);

  // Average resolution time for resolved incidents (resolvedAt - createdAt)
  const resolved = incidents.filter(i => i.resolvedAt && i.createdAt);
  const avgResolutionHours = resolved.length
    ? resolved.reduce((acc, i) => {
        return acc + (i.resolvedAt - i.createdAt) / 3_600_000;
      }, 0) / resolved.length
    : null;

  return {
    summary: {
      total,
      bySeverity: bySeverity.map(r => ({ severity: r.severity, count: r._count.id })),
      byStatus:   byStatus.map(r => ({ status: r.status, count: r._count.id })),
      avgResolutionHours: avgResolutionHours !== null ? +avgResolutionHours.toFixed(1) : null,
    },
    incidents: incidents.map(i => ({
      id: i.id,
      title: i.title,
      severity: i.severity,
      status: i.status,
      assignedTo: i.assignedTo?.name ?? '—',
      linkedAlerts: i.incidentAlerts.length,
      createdAt: i.createdAt,
      resolvedAt: i.resolvedAt ?? null,
    })),
  };
}

// ── Threat Intelligence Report ───────────────────────────────────────────────

export async function getThreatIntelReportData({ startDate, endDate }) {
  const where = buildDateFilter(startDate, endDate, 'addedAt');

  const [total, byType, bySeverity, byStatus, iocs, enrichmentStats] = await Promise.all([
    prisma.threatIndicator.count({ where }),
    prisma.threatIndicator.groupBy({ by: ['type'],     where, _count: { id: true } }),
    prisma.threatIndicator.groupBy({ by: ['severity'], where, _count: { id: true } }),
    prisma.threatIndicator.groupBy({ by: ['status'],   where, _count: { id: true } }),
    prisma.threatIndicator.findMany({
      where,
      orderBy: { addedAt: 'desc' },
      take: 50,
      include: {
        enrichments: {
          orderBy: { queriedAt: 'desc' },
          take: 1,
          select: { provider: true, verdict: true, score: true },
        },
      },
    }),
    prisma.iocEnrichment.groupBy({
      by: ['verdict'],
      where: {
        indicator: where,
        verdict: { not: null },
      },
      _count: { id: true },
    }),
  ]);

  return {
    summary: {
      total,
      byType:     byType.map(r => ({ type: r.type, count: r._count.id })),
      bySeverity: bySeverity.map(r => ({ severity: r.severity, count: r._count.id })),
      byStatus:   byStatus.map(r => ({ status: r.status, count: r._count.id })),
      verdictBreakdown: enrichmentStats.map(r => ({ verdict: r.verdict, count: r._count.id })),
    },
    iocs: iocs.map(i => ({
      id: i.id,
      type: i.type,
      value: i.value,
      severity: i.severity,
      status: i.status,
      source: i.source,
      lastVerdict: i.enrichments[0]?.verdict ?? '—',
      addedAt: i.addedAt,
    })),
  };
}

// ── Assets Report ─────────────────────────────────────────────────────────────

export async function getAssetsReportData() {
  const [total, byType, byCriticality, byStatus, assets] = await Promise.all([
    prisma.asset.count(),
    prisma.asset.groupBy({ by: ['type'],        _count: { id: true }, orderBy: { _count: { id: 'desc' } } }),
    prisma.asset.groupBy({ by: ['criticality'], _count: { id: true } }),
    prisma.asset.groupBy({ by: ['status'],      _count: { id: true } }),
    prisma.asset.findMany({
      orderBy: { criticality: 'desc' },
      take: 100,
      select: {
        id: true, name: true, hostname: true, ipAddress: true,
        type: true, status: true, criticality: true, environment: true,
        operatingSystem: true, owner: true, createdAt: true,
      },
    }),
  ]);

  return {
    summary: {
      total,
      byType:        byType.map(r => ({ type: r.type, count: r._count.id })),
      byCriticality: byCriticality.map(r => ({ criticality: r.criticality, count: r._count.id })),
      byStatus:      byStatus.map(r => ({ status: r.status, count: r._count.id })),
    },
    assets,
  };
}
