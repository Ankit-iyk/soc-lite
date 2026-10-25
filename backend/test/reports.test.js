// test/reports.test.js
// Integration tests for Phase 10 Security Reports API.
// Uses Node 22 native test runner with real PostgreSQL/Prisma and Express HTTP.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;

// ── Helpers ──────────────────────────────────────────────────────────────────

async function get(path, token, extraHeaders = {}) {
  return fetch(`${baseUrl}${path}`, {
    headers: {
      Authorization: token ? `Bearer ${token}` : undefined,
      ...extraHeaders,
    },
  });
}

// ── Suite setup ───────────────────────────────────────────────────────────────

describe('Phase 10 — Security Reports API', () => {
  before(async () => {
    [adminUser, analystUser, viewerUser] = await Promise.all([
      prisma.user.findFirst({ where: { role: 'ADMIN' } }),
      prisma.user.findFirst({ where: { role: 'ANALYST' } }),
      prisma.user.findFirst({ where: { role: 'VIEWER' } }),
    ]);

    assert.ok(adminUser,   'Seed admin user must exist');
    assert.ok(analystUser, 'Seed analyst user must exist');
    assert.ok(viewerUser,  'Seed viewer user must exist');

    adminToken   = signToken({ userId: adminUser.id,   email: adminUser.email,   role: adminUser.role });
    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });
    viewerToken  = signToken({ userId: viewerUser.id,  email: viewerUser.email,  role: viewerUser.role });

    await new Promise((resolve) => {
      server = app.listen(0, () => {
        baseUrl = `http://127.0.0.1:${server.address().port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
  });

  // ── 1. Authentication & RBAC ────────────────────────────────────────────

  describe('1. Authentication — GET /api/reports/types', () => {
    it('returns 401 without a token', async () => {
      const res = await get('/api/reports/types', null);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.equal(body.success, false);
    });

    it('returns 200 for VIEWER', async () => {
      const res = await get('/api/reports/types', viewerToken);
      assert.equal(res.status, 200);
    });

    it('returns 200 for ANALYST', async () => {
      const res = await get('/api/reports/types', analystToken);
      assert.equal(res.status, 200);
    });

    it('returns 200 for ADMIN', async () => {
      const res = await get('/api/reports/types', adminToken);
      assert.equal(res.status, 200);
    });
  });

  // ── 2. GET /api/reports/types ────────────────────────────────────────────

  describe('2. GET /api/reports/types', () => {
    it('returns all 5 report types', async () => {
      const res = await get('/api/reports/types', adminToken);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(Array.isArray(body.data));
      assert.equal(body.data.length, 5);
    });

    it('each type has key, label, description, supportsDateRange', async () => {
      const res = await get('/api/reports/types', adminToken);
      const body = await res.json();
      for (const t of body.data) {
        assert.ok(t.key,         `Missing key in type ${JSON.stringify(t)}`);
        assert.ok(t.label,       `Missing label in type ${JSON.stringify(t)}`);
        assert.ok(t.description, `Missing description in type ${JSON.stringify(t)}`);
        assert.ok(typeof t.supportsDateRange === 'boolean');
      }
    });

    it('includes expected report type keys', async () => {
      const res = await get('/api/reports/types', viewerToken);
      const body = await res.json();
      const keys = body.data.map(t => t.key);
      assert.ok(keys.includes('SECURITY_OVERVIEW'));
      assert.ok(keys.includes('ALERTS'));
      assert.ok(keys.includes('INCIDENTS'));
      assert.ok(keys.includes('THREAT_INTELLIGENCE'));
      assert.ok(keys.includes('ASSETS'));
    });
  });

  // ── 3. GET /api/reports/preview — input validation ───────────────────────

  describe('3. GET /api/reports/preview — validation', () => {
    it('returns 400 when type is missing', async () => {
      const res = await get('/api/reports/preview', adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /type is required/i);
    });

    it('returns 400 for unknown report type', async () => {
      const res = await get('/api/reports/preview?type=BOGUS', adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /invalid report type/i);
    });

    it('returns 400 for invalid startDate', async () => {
      const res = await get('/api/reports/preview?type=ALERTS&startDate=not-a-date', adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /startDate/i);
    });

    it('returns 400 when startDate > endDate', async () => {
      const res = await get('/api/reports/preview?type=ALERTS&startDate=2025-12-01&endDate=2025-01-01', adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /startDate must be before endDate/i);
    });

    it('returns 400 for date range > 365 days', async () => {
      const res = await get('/api/reports/preview?type=ALERTS&startDate=2020-01-01&endDate=2025-12-31', adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /365 days/i);
    });
  });

  // ── 4. GET /api/reports/preview — SECURITY_OVERVIEW ─────────────────────

  describe('4. GET /api/reports/preview — SECURITY_OVERVIEW', () => {
    it('returns 200 with correct structure for ADMIN', async () => {
      const res = await get('/api/reports/preview?type=SECURITY_OVERVIEW', adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data);
      assert.equal(body.data.type, 'SECURITY_OVERVIEW');
      assert.ok(body.data.generatedAt);
      assert.ok(body.data.report);
    });

    it('preview.report has summary with expected keys', async () => {
      const res = await get('/api/reports/preview?type=SECURITY_OVERVIEW', adminToken);
      const body = await res.json();
      const { summary } = body.data.report;
      assert.ok(typeof summary.totalAlerts    === 'number');
      assert.ok(typeof summary.openAlerts     === 'number');
      assert.ok(typeof summary.totalIncidents === 'number');
      assert.ok(typeof summary.totalAssets    === 'number');
    });

    it('preview includes recentAlerts array', async () => {
      const res = await get('/api/reports/preview?type=SECURITY_OVERVIEW', adminToken);
      const body = await res.json();
      assert.ok(Array.isArray(body.data.report.recentAlerts));
    });

    it('accepts date range query params', async () => {
      const res = await get(
        '/api/reports/preview?type=SECURITY_OVERVIEW&startDate=2024-01-01&endDate=2024-12-30',
        adminToken,
      );
      assert.equal(res.status, 200);
    });

    it('VIEWER can access preview', async () => {
      const res = await get('/api/reports/preview?type=SECURITY_OVERVIEW', viewerToken);
      assert.equal(res.status, 200);
    });
  });

  // ── 5. GET /api/reports/preview — ALERTS ────────────────────────────────

  describe('5. GET /api/reports/preview — ALERTS', () => {
    it('returns 200 with alerts report structure', async () => {
      const res = await get('/api/reports/preview?type=ALERTS', adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      const { report } = body.data;
      assert.ok(report.summary);
      assert.ok(typeof report.summary.total === 'number');
      assert.ok(Array.isArray(report.summary.bySeverity));
      assert.ok(Array.isArray(report.summary.byStatus));
      assert.ok(Array.isArray(report.alerts));
    });

    it('case-insensitive type param (alerts → ALERTS)', async () => {
      const res = await get('/api/reports/preview?type=alerts', analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.type, 'ALERTS');
    });
  });

  // ── 6. GET /api/reports/preview — INCIDENTS ──────────────────────────────

  describe('6. GET /api/reports/preview — INCIDENTS', () => {
    it('returns incidents report with summary and listing', async () => {
      const res = await get('/api/reports/preview?type=INCIDENTS', analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      const { report } = body.data;
      assert.ok(report.summary);
      assert.ok(typeof report.summary.total === 'number');
      assert.ok(Array.isArray(report.incidents));
    });

    it('avgResolutionHours is number or null', async () => {
      const res = await get('/api/reports/preview?type=INCIDENTS', adminToken);
      const body = await res.json();
      const { avgResolutionHours } = body.data.report.summary;
      assert.ok(typeof avgResolutionHours === 'number' || avgResolutionHours === null);
    });
  });

  // ── 7. GET /api/reports/preview — THREAT_INTELLIGENCE ───────────────────

  describe('7. GET /api/reports/preview — THREAT_INTELLIGENCE', () => {
    it('returns threat intel report with iocs array', async () => {
      const res = await get('/api/reports/preview?type=THREAT_INTELLIGENCE', adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      const { report } = body.data;
      assert.ok(report.summary);
      assert.ok(Array.isArray(report.iocs));
      assert.ok(Array.isArray(report.summary.byType));
    });
  });

  // ── 8. GET /api/reports/preview — ASSETS ────────────────────────────────

  describe('8. GET /api/reports/preview — ASSETS', () => {
    it('returns assets report with summary and asset listing', async () => {
      const res = await get('/api/reports/preview?type=ASSETS', adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      const { report } = body.data;
      assert.ok(report.summary);
      assert.ok(typeof report.summary.total === 'number');
      assert.ok(Array.isArray(report.assets));
    });
  });

  // ── 9. GET /api/reports/download — RBAC ─────────────────────────────────

  describe('9. GET /api/reports/download — RBAC', () => {
    it('returns 401 without token', async () => {
      const res = await get('/api/reports/download?type=ALERTS', null);
      assert.equal(res.status, 401);
    });

    it('returns 403 for VIEWER', async () => {
      const res = await get('/api/reports/download?type=ALERTS', viewerToken);
      assert.equal(res.status, 403);
    });

    it('returns PDF for ANALYST', async () => {
      const res = await get('/api/reports/download?type=ALERTS', analystToken);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'application/pdf');
      const disposition = res.headers.get('content-disposition');
      assert.ok(disposition);
      assert.ok(disposition.includes('alerts'));
      assert.ok(disposition.includes('.pdf'));
    });

    it('returns PDF for ADMIN', async () => {
      const res = await get('/api/reports/download?type=SECURITY_OVERVIEW', adminToken);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'application/pdf');
    });

    it('PDF body is non-empty binary', async () => {
      const res = await get('/api/reports/download?type=ALERTS', adminToken);
      const buffer = await res.arrayBuffer();
      assert.ok(buffer.byteLength > 1024, `PDF too small: ${buffer.byteLength} bytes`);
    });

    it('PDF starts with %PDF magic bytes', async () => {
      const res = await get('/api/reports/download?type=ALERTS', adminToken);
      const buffer = Buffer.from(await res.arrayBuffer());
      const magic = buffer.slice(0, 4).toString('ascii');
      assert.equal(magic, '%PDF', `Expected PDF magic bytes, got: ${magic}`);
    });
  });

  // ── 10. GET /api/reports/download — all report types ────────────────────

  describe('10. GET /api/reports/download — all report types', () => {
    const types = ['SECURITY_OVERVIEW', 'ALERTS', 'INCIDENTS', 'THREAT_INTELLIGENCE', 'ASSETS'];

    for (const type of types) {
      it(`generates valid PDF for type=${type}`, async () => {
        const res = await get(`/api/reports/download?type=${type}`, adminToken);
        assert.equal(res.status, 200, `Expected 200 for type=${type}`);
        assert.equal(res.headers.get('content-type'), 'application/pdf');
        const buf = Buffer.from(await res.arrayBuffer());
        assert.ok(buf.byteLength > 512, `PDF for ${type} is too small: ${buf.byteLength} bytes`);
        assert.equal(buf.slice(0, 4).toString('ascii'), '%PDF');
      });
    }
  });

  // ── 11. Download — validation still enforced ─────────────────────────────

  describe('11. GET /api/reports/download — input validation', () => {
    it('returns 400 for missing type', async () => {
      const res = await get('/api/reports/download', adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
    });

    it('returns 400 for invalid type', async () => {
      const res = await get('/api/reports/download?type=INVALID', adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
    });

    it('accepts date range for download', async () => {
      const res = await get(
        '/api/reports/download?type=ALERTS&startDate=2024-01-01&endDate=2024-12-30',
        adminToken,
      );
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'application/pdf');
    });
  });

  // ── 12. Audit log creation ────────────────────────────────────────────────

  describe('12. Audit logging', () => {
    it('creates REPORT_PREVIEW audit log entry on preview', async () => {
      const before = await prisma.auditLog.count({
        where: { userId: adminUser.id, action: 'REPORT_PREVIEW', targetId: 'ASSETS' },
      });

      await get('/api/reports/preview?type=ASSETS', adminToken);

      // Give async fire-and-forget a moment
      await new Promise(r => setTimeout(r, 150));

      const after = await prisma.auditLog.count({
        where: { userId: adminUser.id, action: 'REPORT_PREVIEW', targetId: 'ASSETS' },
      });

      assert.ok(after > before, 'Expected a new REPORT_PREVIEW audit log entry');
    });

    it('creates REPORT_DOWNLOAD audit log entry on download', async () => {
      const before = await prisma.auditLog.count({
        where: { userId: analystUser.id, action: 'REPORT_DOWNLOAD' },
      });

      const res = await get('/api/reports/download?type=INCIDENTS', analystToken);
      // consume the stream so the request completes
      await res.arrayBuffer();

      await new Promise(r => setTimeout(r, 200));

      const after = await prisma.auditLog.count({
        where: { userId: analystUser.id, action: 'REPORT_DOWNLOAD' },
      });

      assert.ok(after > before, 'Expected a new REPORT_DOWNLOAD audit log entry');
    });
  });
});
