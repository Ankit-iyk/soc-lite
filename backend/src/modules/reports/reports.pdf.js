// backend/src/modules/reports/reports.pdf.js
// PDF generation service for Phase 10 Security Reports using PDFKit.
// Produces a polished, branded PDF from structured report data.

import PDFDocument from 'pdfkit';

// ── Brand palette ─────────────────────────────────────────────────────────
const COLORS = {
  bg:       '#0f1117',
  primary:  '#6366f1',   // indigo-500
  accent:   '#22d3ee',   // cyan-400
  text:     '#e2e8f0',
  muted:    '#94a3b8',
  border:   '#1e293b',
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  white:    '#ffffff',
  dark1:    '#0f172a',
  dark2:    '#1e293b',
  dark3:    '#334155',
};

function severityColor(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return COLORS.critical;
    case 'HIGH':     return COLORS.high;
    case 'MEDIUM':   return COLORS.medium;
    case 'LOW':      return COLORS.low;
    default:         return COLORS.muted;
  }
}

function statusColor(status) {
  switch ((status || '').toUpperCase()) {
    case 'OPEN':          return COLORS.critical;
    case 'INVESTIGATING': return COLORS.high;
    case 'ACKNOWLEDGED':  return COLORS.medium;
    case 'RESOLVED':      return COLORS.low;
    case 'CLOSED':        return COLORS.muted;
    case 'ACTIVE':        return COLORS.low;
    case 'INACTIVE':      return COLORS.medium;
    case 'EXPIRED':       return COLORS.critical;
    case 'REVOKED':       return COLORS.critical;
    default:              return COLORS.muted;
  }
}

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// ── PDF helpers ──────────────────────────────────────────────────────────────

/**
 * Draw a full-width colored bar.
 */
function drawBar(doc, y, height, color) {
  doc.rect(0, y, doc.page.width, height).fill(color);
}

/**
 * Draw a page header with gradient-like effect.
 */
function drawHeader(doc, title, subtitle) {
  // Background gradient simulation using overlapping rectangles
  drawBar(doc, 0, 90, COLORS.dark1);
  doc.rect(0, 0, doc.page.width, 90).fill(COLORS.dark2);

  // Accent stripe at top
  doc.rect(0, 0, doc.page.width, 5).fill(COLORS.primary);

  // SOC Lite brand
  doc.fontSize(10).fillColor(COLORS.primary).text('SOC LITE', 40, 20);
  doc.fontSize(8).fillColor(COLORS.muted).text('Security Operations Center', 40, 32);

  // Report title
  doc.fontSize(22).fillColor(COLORS.white).text(title, 40, 45);

  // Subtitle / date line
  if (subtitle) {
    doc.fontSize(9).fillColor(COLORS.muted).text(subtitle, 40, 72);
  }

  // Generated timestamp on right side
  const ts = `Generated: ${new Date().toUTCString()}`;
  doc.fontSize(8).fillColor(COLORS.muted).text(ts, 0, 22, { align: 'right', width: doc.page.width - 40 });

  doc.y = 105;
}

/**
 * Draw a section heading.
 */
function sectionHeading(doc, text) {
  // Ensure we have space (add page if needed)
  if (doc.y > doc.page.height - 120) {
    doc.addPage();
  }

  doc.moveDown(0.6);
  const y = doc.y;
  doc.rect(40, y, doc.page.width - 80, 1).fill(COLORS.primary);
  doc.moveDown(0.15);
  doc.fontSize(13).fillColor(COLORS.primary).text(text, 40, doc.y);
  doc.moveDown(0.4);
}

/**
 * Draw a row of summary stat cards (up to 4 per row).
 * @param {Array<{label:string, value:string|number, color?:string}>} stats
 */
function drawStatCards(doc, stats) {
  const pageWidth = doc.page.width - 80; // 40px margin each side
  const cardW = (pageWidth - (stats.length - 1) * 12) / stats.length;
  const cardH = 56;
  const startX = 40;
  const startY = doc.y;

  stats.forEach((stat, i) => {
    const x = startX + i * (cardW + 12);
    // Card background
    doc.roundedRect(x, startY, cardW, cardH, 6).fill(COLORS.dark2);
    // Color accent on left
    doc.rect(x, startY, 3, cardH).fill(stat.color || COLORS.primary);

    // Value
    doc.fontSize(22).fillColor(stat.color || COLORS.white)
       .text(String(stat.value), x + 12, startY + 8, { width: cardW - 16, align: 'left' });

    // Label
    doc.fontSize(8).fillColor(COLORS.muted)
       .text(stat.label, x + 12, startY + 36, { width: cardW - 16, align: 'left' });
  });

  doc.y = startY + cardH + 14;
}

/**
 * Draw a simple bar chart for category breakdowns.
 * @param {Array<{label:string, count:number, color?:string}>} items
 */
function drawBarChart(doc, items, maxBarWidth = 240) {
  if (!items || items.length === 0) {
    doc.fontSize(9).fillColor(COLORS.muted).text('  No data available.', 40, doc.y);
    doc.moveDown(0.5);
    return;
  }

  const maxCount = Math.max(...items.map(i => i.count), 1);
  const rowH = 20;
  const labelW = 110;
  const chartX = 40 + labelW + 8;

  items.forEach(item => {
    if (doc.y + rowH > doc.page.height - 60) doc.addPage();
    const y = doc.y;
    const barW = Math.round((item.count / maxCount) * maxBarWidth);

    // Label
    doc.fontSize(9).fillColor(COLORS.text)
       .text(item.label, 40, y + 4, { width: labelW, align: 'left' });

    // Bar background
    doc.roundedRect(chartX, y + 2, maxBarWidth, 14, 3).fill(COLORS.dark3);

    // Bar fill
    if (barW > 0) {
      doc.roundedRect(chartX, y + 2, barW, 14, 3).fill(item.color || COLORS.primary);
    }

    // Count label
    doc.fontSize(9).fillColor(COLORS.white)
       .text(String(item.count), chartX + maxBarWidth + 8, y + 4);

    doc.y = y + rowH;
  });

  doc.moveDown(0.5);
}

/**
 * Draw a table with headers and rows.
 * @param {string[]} headers
 * @param {Array<string[]>} rows
 * @param {number[]} colWidths
 */
function drawTable(doc, headers, rows, colWidths) {
  const pageWidth = doc.page.width - 80;
  const total = colWidths.reduce((a, b) => a + b, 0);
  const scale = pageWidth / total;
  const scaledWidths = colWidths.map(w => w * scale);
  const startX = 40;
  const headerH = 20;
  const rowH = 18;

  // Header background
  doc.rect(startX, doc.y, pageWidth, headerH).fill(COLORS.dark2);
  let cx = startX;
  headers.forEach((h, i) => {
    doc.fontSize(8).fillColor(COLORS.accent)
       .text(h.toUpperCase(), cx + 5, doc.y + 5, { width: scaledWidths[i] - 6, align: 'left' });
    cx += scaledWidths[i];
  });
  doc.y += headerH;

  // Rows
  rows.forEach((row, ri) => {
    if (doc.y + rowH > doc.page.height - 50) {
      doc.addPage();
      // Redraw header on new page
      doc.rect(startX, doc.y, pageWidth, headerH).fill(COLORS.dark2);
      cx = startX;
      headers.forEach((h, i) => {
        doc.fontSize(8).fillColor(COLORS.accent)
           .text(h.toUpperCase(), cx + 5, doc.y + 5, { width: scaledWidths[i] - 6, align: 'left' });
        cx += scaledWidths[i];
      });
      doc.y += headerH;
    }

    const rowY = doc.y;
    // Alternating row background
    if (ri % 2 === 0) {
      doc.rect(startX, rowY, pageWidth, rowH).fill(COLORS.dark3 + '55');
    }

    cx = startX;
    row.forEach((cell, ci) => {
      const cellStr = cell === null || cell === undefined ? '—' : String(cell);
      doc.fontSize(8).fillColor(COLORS.text)
         .text(cellStr, cx + 5, rowY + 4, {
           width: scaledWidths[ci] - 8,
           align: 'left',
           ellipsis: true,
         });
      cx += scaledWidths[ci];
    });

    doc.y = rowY + rowH;
  });

  doc.moveDown(0.5);
}

/**
 * Draw the PDF footer on the current page.
 */
function drawFooter(doc, pageNum, reportTitle) {
  const y = doc.page.height - 32;
  doc.rect(0, y - 5, doc.page.width, 37).fill(COLORS.dark2);
  doc.rect(0, y - 5, doc.page.width, 2).fill(COLORS.primary);
  doc.fontSize(7).fillColor(COLORS.muted)
     .text(`${reportTitle} • SOC Lite`, 40, y + 4);
  doc.text(`Page ${pageNum}`, 0, y + 4, { align: 'right', width: doc.page.width - 40 });
}

// ── Main PDF Builder ─────────────────────────────────────────────────────────

/**
 * Generate a PDF security report and pipe it to `res` (Express response).
 * @param {object} params
 * @param {string} params.type - Report type key
 * @param {object} params.data - Structured report data from reports.service.js
 * @param {Date|null} params.startDate
 * @param {Date|null} params.endDate
 * @param {import('express').Response} params.res - Express response stream
 */
export function generatePDF({ type, data, startDate, endDate, res }) {
  const doc = new PDFDocument({
    size: 'A4',
    margin: 0,
    bufferPages: true,
    autoFirstPage: true,
    info: {
      Title: `SOC Lite — ${type.replace(/_/g, ' ')} Report`,
      Author: 'SOC Lite Platform',
      Creator: 'SOC Lite PDF Engine v1.0',
    },
  });

  // Pipe to response
  doc.pipe(res);

  // ── Page background ──────────────────────────────────────────────────────
  doc.rect(0, 0, doc.page.width, doc.page.height).fill(COLORS.bg);

  // ── Header ───────────────────────────────────────────────────────────────
  const prettyType = type.replace(/_/g, ' ');
  const dateRange = (startDate || endDate)
    ? `Period: ${startDate ? fmtDate(startDate) : 'All time'} → ${endDate ? fmtDate(endDate) : 'Now'}`
    : 'Period: All available data';

  drawHeader(doc, `${prettyType} REPORT`, dateRange);

  let pageNum = 1;

  // ── Report-type-specific content ─────────────────────────────────────────

  if (type === 'SECURITY_OVERVIEW') {
    renderSecurityOverview(doc, data);
  } else if (type === 'ALERTS') {
    renderAlertsReport(doc, data);
  } else if (type === 'INCIDENTS') {
    renderIncidentsReport(doc, data);
  } else if (type === 'THREAT_INTELLIGENCE') {
    renderThreatIntelReport(doc, data);
  } else if (type === 'ASSETS') {
    renderAssetsReport(doc, data);
  }

  // ── Footer on each page ──────────────────────────────────────────────────
  const pages = doc.bufferedPageRange();
  for (let i = 0; i < pages.count; i++) {
    doc.switchToPage(pages.start + i);
    drawFooter(doc, i + 1, prettyType);
  }

  doc.end();
}

// ── Renderers ────────────────────────────────────────────────────────────────

function renderSecurityOverview(doc, data) {
  const s = data.summary;

  sectionHeading(doc, 'Platform Summary');
  drawStatCards(doc, [
    { label: 'Total Alerts',      value: s.totalAlerts,      color: COLORS.primary },
    { label: 'Open Alerts',       value: s.openAlerts,       color: s.openAlerts > 0 ? COLORS.critical : COLORS.low },
    { label: 'Critical Alerts',   value: s.criticalAlerts,   color: COLORS.critical },
    { label: 'Total Incidents',   value: s.totalIncidents,   color: COLORS.accent },
  ]);
  drawStatCards(doc, [
    { label: 'Open Incidents',    value: s.openIncidents,    color: s.openIncidents > 0 ? COLORS.high : COLORS.low },
    { label: 'Resolved Incidents',value: s.resolvedIncidents,color: COLORS.low },
    { label: 'Active IOCs',       value: s.activeIocs,       color: COLORS.high },
    { label: 'Assets Tracked',    value: s.totalAssets,      color: COLORS.muted },
  ]);

  sectionHeading(doc, 'Alert Severity Breakdown');
  drawBarChart(doc, data.alertsBySeverity.map(r => ({
    label: r.severity, count: r.count, color: severityColor(r.severity),
  })));

  sectionHeading(doc, 'Incident Severity Breakdown');
  drawBarChart(doc, data.incidentsBySeverity.map(r => ({
    label: r.severity, count: r.count, color: severityColor(r.severity),
  })));

  sectionHeading(doc, 'Recent Alerts (Top 10)');
  drawTable(doc,
    ['Title', 'Severity', 'Status', 'Fired At'],
    data.recentAlerts.map(a => [a.title, a.severity, a.status, fmtDate(a.firedAt)]),
    [220, 70, 70, 120],
  );

  sectionHeading(doc, 'Recent Incidents (Top 10)');
  drawTable(doc,
    ['Title', 'Severity', 'Status', 'Created At'],
    data.recentIncidents.map(i => [i.title, i.severity, i.status, fmtDate(i.createdAt)]),
    [220, 70, 70, 120],
  );
}

function renderAlertsReport(doc, data) {
  const s = data.summary;

  sectionHeading(doc, 'Alert Summary');
  drawStatCards(doc, [
    { label: 'Total Alerts', value: s.total,                           color: COLORS.primary },
    { label: 'Critical',     value: s.bySeverity.find(r => r.severity === 'CRITICAL')?.count ?? 0, color: COLORS.critical },
    { label: 'High',         value: s.bySeverity.find(r => r.severity === 'HIGH')?.count ?? 0,     color: COLORS.high },
    { label: 'Open',         value: s.byStatus.find(r => r.status === 'OPEN')?.count ?? 0,         color: COLORS.high },
  ]);

  sectionHeading(doc, 'Severity Distribution');
  drawBarChart(doc, s.bySeverity.map(r => ({
    label: r.severity, count: r.count, color: severityColor(r.severity),
  })));

  sectionHeading(doc, 'Status Distribution');
  drawBarChart(doc, s.byStatus.map(r => ({
    label: r.status, count: r.count, color: statusColor(r.status),
  })));

  if (data.topTriggeredRules && data.topTriggeredRules.length > 0) {
    sectionHeading(doc, 'Top Triggered Rules');
    drawBarChart(doc, data.topTriggeredRules.map(r => ({
      label: r.ruleName, count: r.count, color: COLORS.accent,
    })));
  }

  sectionHeading(doc, `Alert Listing (${data.alerts.length})`);
  drawTable(doc,
    ['Title', 'Severity', 'Status', 'Rule', 'Fired At'],
    data.alerts.map(a => [a.title, a.severity, a.status, a.rule, fmtDate(a.firedAt)]),
    [180, 65, 65, 100, 110],
  );
}

function renderIncidentsReport(doc, data) {
  const s = data.summary;

  sectionHeading(doc, 'Incident Summary');
  const resolutionLabel = s.avgResolutionHours !== null
    ? `${s.avgResolutionHours}h`
    : 'N/A';
  drawStatCards(doc, [
    { label: 'Total Incidents',       value: s.total,         color: COLORS.primary },
    { label: 'Open',                  value: s.byStatus.find(r => r.status === 'OPEN')?.count ?? 0,          color: COLORS.critical },
    { label: 'Resolved',              value: s.byStatus.find(r => r.status === 'RESOLVED')?.count ?? 0,      color: COLORS.low },
    { label: 'Avg Resolution Time',   value: resolutionLabel, color: COLORS.accent },
  ]);

  sectionHeading(doc, 'Severity Distribution');
  drawBarChart(doc, s.bySeverity.map(r => ({
    label: r.severity, count: r.count, color: severityColor(r.severity),
  })));

  sectionHeading(doc, 'Status Distribution');
  drawBarChart(doc, s.byStatus.map(r => ({
    label: r.status, count: r.count, color: statusColor(r.status),
  })));

  sectionHeading(doc, `Incident Listing (${data.incidents.length})`);
  drawTable(doc,
    ['Title', 'Severity', 'Status', 'Assigned To', 'Alerts', 'Created At'],
    data.incidents.map(i => [
      i.title, i.severity, i.status, i.assignedTo,
      String(i.linkedAlerts), fmtDate(i.createdAt),
    ]),
    [160, 60, 80, 90, 40, 110],
  );
}

function renderThreatIntelReport(doc, data) {
  const s = data.summary;

  sectionHeading(doc, 'Threat Intelligence Summary');
  drawStatCards(doc, [
    { label: 'Total IOCs',  value: s.total,                                                  color: COLORS.primary },
    { label: 'Active IOCs', value: s.byStatus.find(r => r.status === 'ACTIVE')?.count ?? 0, color: COLORS.low },
    { label: 'Malicious',   value: s.verdictBreakdown.find(r => r.verdict === 'MALICIOUS')?.count ?? 0, color: COLORS.critical },
    { label: 'Suspicious',  value: s.verdictBreakdown.find(r => r.verdict === 'SUSPICIOUS')?.count ?? 0, color: COLORS.high },
  ]);

  sectionHeading(doc, 'IOC Type Breakdown');
  drawBarChart(doc, s.byType.map(r => ({ label: r.type, count: r.count, color: COLORS.accent })));

  sectionHeading(doc, 'Verdict Breakdown');
  drawBarChart(doc, s.verdictBreakdown.map(r => ({
    label: r.verdict ?? 'UNKNOWN', count: r.count, color: statusColor(r.verdict),
  })));

  sectionHeading(doc, 'Severity Distribution');
  drawBarChart(doc, s.bySeverity.map(r => ({
    label: r.severity, count: r.count, color: severityColor(r.severity),
  })));

  sectionHeading(doc, `IOC Listing (${data.iocs.length})`);
  drawTable(doc,
    ['Type', 'Value', 'Severity', 'Status', 'Verdict', 'Added At'],
    data.iocs.map(i => [i.type, i.value, i.severity, i.status, i.lastVerdict, fmtDate(i.addedAt)]),
    [45, 160, 65, 65, 70, 110],
  );
}

function renderAssetsReport(doc, data) {
  const s = data.summary;

  sectionHeading(doc, 'Asset Summary');
  drawStatCards(doc, [
    { label: 'Total Assets',  value: s.total,                                                       color: COLORS.primary },
    { label: 'Active',        value: s.byStatus.find(r => r.status === 'ACTIVE')?.count ?? 0,       color: COLORS.low },
    { label: 'Critical',      value: s.byCriticality.find(r => r.criticality === 'CRITICAL')?.count ?? 0, color: COLORS.critical },
    { label: 'Decommissioned',value: s.byStatus.find(r => r.status === 'DECOMMISSIONED')?.count ?? 0, color: COLORS.muted },
  ]);

  sectionHeading(doc, 'Asset Type Breakdown');
  drawBarChart(doc, s.byType.map(r => ({ label: r.type, count: r.count, color: COLORS.accent })));

  sectionHeading(doc, 'Criticality Breakdown');
  drawBarChart(doc, s.byCriticality.map(r => ({
    label: r.criticality, count: r.count, color: severityColor(r.criticality),
  })));

  sectionHeading(doc, `Asset Listing (${data.assets.length})`);
  drawTable(doc,
    ['Name', 'Hostname / IP', 'Type', 'Criticality', 'Status', 'Environment'],
    data.assets.map(a => [
      a.name,
      [a.hostname, a.ipAddress].filter(Boolean).join(' / ') || '—',
      a.type, a.criticality, a.status, a.environment ?? '—',
    ]),
    [120, 130, 70, 70, 65, 85],
  );
}
