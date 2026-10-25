// backend/src/modules/reports/reports.controller.js
// Controller actions for Phase 10 Security Reports.

import prisma from '../../config/prisma.js';
import { validateReportQuery, REPORT_TYPES } from './reports.validation.js';
import {
  getSecurityOverviewData,
  getAlertsReportData,
  getIncidentsReportData,
  getThreatIntelReportData,
  getAssetsReportData,
} from './reports.service.js';
import { generatePDF } from './reports.pdf.js';

/**
 * Map report type to data-fetching function.
 */
const DATA_FETCHERS = {
  SECURITY_OVERVIEW:   getSecurityOverviewData,
  ALERTS:              getAlertsReportData,
  INCIDENTS:           getIncidentsReportData,
  THREAT_INTELLIGENCE: getThreatIntelReportData,
  ASSETS:              (_) => getAssetsReportData(),   // assets ignores date range
};

// ── GET /api/reports/types ────────────────────────────────────────────────────

/**
 * Return the list of supported report types and their metadata.
 */
export async function getReportTypes(req, res, next) {
  try {
    const types = [
      {
        key:         'SECURITY_OVERVIEW',
        label:       'Security Overview',
        description: 'Aggregated platform snapshot: alerts, incidents, IOCs, and recent activity.',
        supportsDateRange: true,
      },
      {
        key:         'ALERTS',
        label:       'Alerts Report',
        description: 'Detailed alert breakdown by severity, status, and top triggered rules.',
        supportsDateRange: true,
      },
      {
        key:         'INCIDENTS',
        label:       'Incidents Report',
        description: 'Incident listing with lifecycle stats, resolution times, and assignments.',
        supportsDateRange: true,
      },
      {
        key:         'THREAT_INTELLIGENCE',
        label:       'Threat Intelligence Report',
        description: 'IOC inventory, enrichment verdicts, type distribution, and severity breakdown.',
        supportsDateRange: true,
      },
      {
        key:         'ASSETS',
        label:       'Asset Inventory Report',
        description: 'Complete asset inventory by type, criticality, and environment.',
        supportsDateRange: false,
      },
    ];

    return res.status(200).json({ success: true, data: types });
  } catch (err) {
    next(err);
  }
}

// ── GET /api/reports/preview ─────────────────────────────────────────────────

/**
 * Return the structured JSON data for a report — useful for previewing
 * or rendering charts in the frontend before generating the PDF.
 */
export async function previewReport(req, res, next) {
  try {
    const { isValid, error, sanitized } = validateReportQuery(req.query);
    if (!isValid) {
      return res.status(400).json({ success: false, error });
    }

    const { type, startDate, endDate } = sanitized;
    const fetcher = DATA_FETCHERS[type];
    if (!fetcher) {
      return res.status(400).json({ success: false, error: `Unsupported report type: ${type}` });
    }

    const data = await fetcher({ startDate, endDate });

    // Audit log
    await prisma.auditLog.create({
      data: {
        userId:     req.user.id,
        action:     'REPORT_PREVIEW',
        targetType: 'Report',
        targetId:   type,
        ipAddress:  req.ip,
        details:    { type, startDate, endDate },
      },
    }).catch(() => {}); // Non-blocking

    return res.status(200).json({
      success: true,
      data: {
        type,
        generatedAt: new Date().toISOString(),
        dateRange: { startDate, endDate },
        report: data,
      },
    });
  } catch (err) {
    next(err);
  }
}

// ── GET /api/reports/download ────────────────────────────────────────────────

/**
 * Generate and stream a PDF report to the client.
 * Requires ADMIN or ANALYST role (enforced in routes).
 */
export async function downloadReport(req, res, next) {
  try {
    const { isValid, error, sanitized } = validateReportQuery(req.query);
    if (!isValid) {
      return res.status(400).json({ success: false, error });
    }

    const { type, startDate, endDate } = sanitized;
    const fetcher = DATA_FETCHERS[type];
    if (!fetcher) {
      return res.status(400).json({ success: false, error: `Unsupported report type: ${type}` });
    }

    const data = await fetcher({ startDate, endDate });

    // Build a safe filename
    const dateStr = new Date().toISOString().split('T')[0];
    const filename = `soc-lite-${type.toLowerCase().replace(/_/g, '-')}-${dateStr}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Audit log (fire and forget)
    prisma.auditLog.create({
      data: {
        userId:     req.user.id,
        action:     'REPORT_DOWNLOAD',
        targetType: 'Report',
        targetId:   type,
        ipAddress:  req.ip,
        details:    { type, startDate, endDate, filename },
      },
    }).catch(() => {});

    // Stream the PDF
    generatePDF({ type, data, startDate, endDate, res });
  } catch (err) {
    next(err);
  }
}
