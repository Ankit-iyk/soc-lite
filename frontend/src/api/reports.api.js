// frontend/src/api/reports.api.js
// API client methods for Phase 10 Security Reports.

import api from './client';

/**
 * Fetch the list of available report types.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @returns {Promise<{ success: boolean, data: Array<object> }>}
 */
export async function getReportTypesApi() {
  const response = await api.get('/reports/types');
  return response.data;
}

/**
 * Fetch the JSON preview data for a report.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 * @param {{ type: string, startDate?: string, endDate?: string }} params
 * @returns {Promise<{ success: boolean, data: object }>}
 */
export async function previewReportApi(params = {}) {
  const response = await api.get('/reports/preview', { params });
  return response.data;
}

/**
 * Trigger a PDF download for a report.
 * Allowed roles: ADMIN, ANALYST (VIEWER is blocked server-side).
 * Returns a Blob URL the browser can use to download the file.
 * @param {{ type: string, startDate?: string, endDate?: string }} params
 * @returns {Promise<{ blobUrl: string, filename: string }>}
 */
export async function downloadReportApi(params = {}) {
  const response = await api.get('/reports/download', {
    params,
    responseType: 'blob',
    timeout: 60000, // PDF generation can take a moment
  });

  const blob = new Blob([response.data], { type: 'application/pdf' });
  const blobUrl = URL.createObjectURL(blob);

  // Extract filename from Content-Disposition header if available
  const disposition = response.headers['content-disposition'] || '';
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match ? match[1] : `soc-lite-report-${params.type?.toLowerCase() ?? 'report'}.pdf`;

  return { blobUrl, filename };
}
