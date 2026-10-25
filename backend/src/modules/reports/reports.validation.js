// backend/src/modules/reports/reports.validation.js
// Input validation for Phase 10 Security Reports.

/**
 * Allowed report types exposed to the API.
 */
export const REPORT_TYPES = ['SECURITY_OVERVIEW', 'ALERTS', 'INCIDENTS', 'THREAT_INTELLIGENCE', 'ASSETS'];

/**
 * Validate and sanitize query parameters for report generation.
 *
 * @param {object} query - Express req.query
 * @returns {{ isValid: boolean, error?: string, sanitized?: object }}
 */
export function validateReportQuery(query = {}) {
  const { type, startDate, endDate, format = 'pdf' } = query;

  // type is required
  if (!type) {
    return { isValid: false, error: 'Report type is required. Allowed: ' + REPORT_TYPES.join(', ') };
  }

  const upperType = String(type).toUpperCase();
  if (!REPORT_TYPES.includes(upperType)) {
    return {
      isValid: false,
      error: `Invalid report type "${type}". Allowed: ${REPORT_TYPES.join(', ')}`,
    };
  }

  // format must be pdf or json
  const lowerFormat = String(format).toLowerCase();
  if (!['pdf', 'json'].includes(lowerFormat)) {
    return { isValid: false, error: 'Invalid format. Allowed: pdf, json' };
  }

  // Date validation — both optional, but if provided must be ISO 8601
  let parsedStart = null;
  let parsedEnd = null;

  if (startDate) {
    parsedStart = new Date(startDate);
    if (isNaN(parsedStart.getTime())) {
      return { isValid: false, error: 'Invalid startDate. Use ISO 8601 format (e.g. 2025-01-01).' };
    }
  }

  if (endDate) {
    parsedEnd = new Date(endDate);
    if (isNaN(parsedEnd.getTime())) {
      return { isValid: false, error: 'Invalid endDate. Use ISO 8601 format (e.g. 2025-12-31).' };
    }
  }

  if (parsedStart && parsedEnd && parsedStart > parsedEnd) {
    return { isValid: false, error: 'startDate must be before endDate.' };
  }

  // Clamp the range: no more than 1 year
  if (parsedStart && parsedEnd) {
    const oneYearMs = 365 * 24 * 60 * 60 * 1000;
    if (parsedEnd - parsedStart > oneYearMs) {
      return { isValid: false, error: 'Date range cannot exceed 365 days.' };
    }
  }

  return {
    isValid: true,
    sanitized: {
      type: upperType,
      format: lowerFormat,
      startDate: parsedStart,
      endDate: parsedEnd,
    },
  };
}
