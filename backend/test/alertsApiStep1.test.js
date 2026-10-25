// test/alertsApiStep1.test.js
// Focused integration tests for Phase 5 Step 1 Alert Management API & RBAC.
// Uses Node 22 native test runner (node:test).

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { AlertStatus, Severity, RuleType } from '@prisma/client';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;
let testRule;
let createdAlertIds = [];
let createdAuditLogIds = [];

describe('Phase 5 Step 1 — Alert Management API & RBAC', () => {
  before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });

    adminUser = await prisma.user.findUnique({ where: { email: 'admin@soclite.local' } });
    analystUser = await prisma.user.findUnique({ where: { email: 'analyst@soclite.local' } });
    viewerUser = await prisma.user.findUnique({ where: { email: 'viewer@soclite.local' } });

    assert.ok(adminUser, 'Seeded admin user must exist');
    assert.ok(analystUser, 'Seeded analyst user must exist');
    assert.ok(viewerUser, 'Seeded viewer user must exist');

    adminToken = signToken({ userId: adminUser.id, email: adminUser.email, role: adminUser.role });
    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });
    viewerToken = signToken({ userId: viewerUser.id, email: viewerUser.email, role: viewerUser.role });

    testRule = await prisma.detectionRule.findFirst();
    assert.ok(testRule, 'At least one detection rule must exist');
  });

  after(async () => {
    // Cleanup any created alerts & audit logs
    if (createdAlertIds.length > 0) {
      await prisma.alertEvent.deleteMany({ where: { alertId: { in: createdAlertIds } } });
      await prisma.alert.deleteMany({ where: { id: { in: createdAlertIds } } });
    }
    await prisma.auditLog.deleteMany({
      where: {
        action: { in: ['ALERT_ACK', 'ALERT_CLOSE'] },
      },
    });

    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  // Helper to create a test alert
  async function createTestAlert(overrides = {}) {
    const alert = await prisma.alert.create({
      data: {
        ruleId: overrides.ruleId || testRule.id,
        title: overrides.title || 'Test Alert Title',
        description: overrides.description || 'Test Alert Description',
        severity: overrides.severity || Severity.HIGH,
        status: overrides.status || AlertStatus.OPEN,
        firedAt: overrides.firedAt || new Date(),
        acknowledgedAt: overrides.acknowledgedAt || null,
        acknowledgedBy: overrides.acknowledgedBy || null,
      },
    });
    createdAlertIds.push(alert.id);
    return alert;
  }

  // ── Authentication & RBAC ──────────────────────────────────────────────────

  it('rejects unauthenticated GET /api/alerts with 401', async () => {
    const res = await fetch(`${baseUrl}/api/alerts`);
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.success, false);
  });

  it('rejects unauthenticated GET /api/alerts/stats with 401', async () => {
    const res = await fetch(`${baseUrl}/api/alerts/stats`);
    assert.equal(res.status, 401);
  });

  it('rejects unauthenticated GET /api/alerts/:id with 401', async () => {
    const res = await fetch(`${baseUrl}/api/alerts/00000000-0000-0000-0000-000000000000`);
    assert.equal(res.status, 401);
  });

  it('rejects unauthenticated PATCH /api/alerts/:id/status with 401', async () => {
    const res = await fetch(`${baseUrl}/api/alerts/00000000-0000-0000-0000-000000000000/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
    });
    assert.equal(res.status, 401);
  });

  it('allows VIEWER to read alerts and stats', async () => {
    const res = await fetch(`${baseUrl}/api/alerts`, {
      headers: { Authorization: `Bearer ${viewerToken}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.data));
    assert.ok(body.pagination);

    const statsRes = await fetch(`${baseUrl}/api/alerts/stats`, {
      headers: { Authorization: `Bearer ${viewerToken}` },
    });
    assert.equal(statsRes.status, 200);
    const statsBody = await statsRes.json();
    assert.equal(statsBody.success, true);
    assert.ok(typeof statsBody.data.total === 'number');
    assert.ok(statsBody.data.byStatus);
    assert.ok(statsBody.data.bySeverity);
  });

  it('forbids VIEWER from modifying alert status with 403', async () => {
    const alert = await createTestAlert();
    const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${viewerToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
    });
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.ok(body.error.includes('Access denied'));
  });

  // ── GET /api/alerts Query Filtering & Pagination ───────────────────────────

  it('filters alerts by status', async () => {
    const openAlert = await createTestAlert({ status: AlertStatus.OPEN, title: 'Open Filter Test' });
    const closedAlert = await createTestAlert({ status: AlertStatus.CLOSED, title: 'Closed Filter Test' });

    const res = await fetch(`${baseUrl}/api/alerts?status=CLOSED`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.data.every((a) => a.status === 'CLOSED'));
    assert.ok(body.data.some((a) => a.id === closedAlert.id));
    assert.ok(!body.data.some((a) => a.id === openAlert.id));
  });

  it('filters alerts by search query matching title', async () => {
    const alert = await createTestAlert({ title: 'UniqueKeywordForSearchTest' });

    const res = await fetch(`${baseUrl}/api/alerts?search=UniqueKeywordForSearchTest`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.length, 1);
    assert.equal(body.data[0].id, alert.id);
  });

  it('rejects invalid query parameters with 400', async () => {
    const resBadPage = await fetch(`${baseUrl}/api/alerts?page=-1`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(resBadPage.status, 400);

    const resBadStatus = await fetch(`${baseUrl}/api/alerts?status=UNKNOWN`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(resBadStatus.status, 400);
  });

  // ── GET /api/alerts/:id ────────────────────────────────────────────────────

  it('returns 400 for malformed UUID in GET /api/alerts/:id', async () => {
    const res = await fetch(`${baseUrl}/api/alerts/invalid-id`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.ok(body.error.includes('UUID'));
  });

  it('returns 404 for non-existent alert', async () => {
    const res = await fetch(`${baseUrl}/api/alerts/00000000-0000-0000-0000-000000000000`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(res.status, 404);
  });

  it('returns single alert with attached detection rule and evidence', async () => {
    const alert = await createTestAlert({ title: 'Detail Test Alert' });

    const res = await fetch(`${baseUrl}/api/alerts/${alert.id}`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.id, alert.id);
    assert.equal(body.data.title, 'Detail Test Alert');
    assert.ok(body.data.rule);
    assert.equal(body.data.rule.id, testRule.id);
    assert.ok(Array.isArray(body.data.evidence));
  });

  // ── PATCH /api/alerts/:id/status & Audit Logging ───────────────────────────

  it('allows ANALYST to transition OPEN alert to ACKNOWLEDGED with audit log', async () => {
    const alert = await createTestAlert({ status: AlertStatus.OPEN });

    const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${analystToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.status, 'ACKNOWLEDGED');
    assert.ok(body.data.acknowledgedAt);
    assert.equal(body.data.acknowledgedBy, analystUser.name);

    // Verify AuditLog record
    const auditLog = await prisma.auditLog.findFirst({
      where: {
        targetType: 'Alert',
        targetId: alert.id,
        action: 'ALERT_ACK',
      },
    });
    assert.ok(auditLog, 'Audit log entry must be created');
    assert.equal(auditLog.userId, analystUser.id);
    assert.equal(auditLog.details.previous.status, 'OPEN');
    assert.equal(auditLog.details.updated.status, 'ACKNOWLEDGED');
  });

  it('rejects transitioning already ACKNOWLEDGED alert to ACKNOWLEDGED', async () => {
    const alert = await createTestAlert({
      status: AlertStatus.ACKNOWLEDGED,
      acknowledgedAt: new Date(),
      acknowledgedBy: analystUser.name,
    });

    const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${analystToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.ok(body.error.includes('already in ACKNOWLEDGED'));
  });

  it('allows transitioning ACKNOWLEDGED alert to CLOSED while preserving acknowledgement metadata', async () => {
    const ackDate = new Date('2026-01-01T12:00:00Z');
    const alert = await createTestAlert({
      status: AlertStatus.ACKNOWLEDGED,
      acknowledgedAt: ackDate,
      acknowledgedBy: 'Initial Analyst',
    });

    const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'CLOSED' }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.status, 'CLOSED');
    assert.equal(body.data.acknowledgedBy, 'Initial Analyst');
    assert.equal(new Date(body.data.acknowledgedAt).getTime(), ackDate.getTime());

    // Verify AuditLog for ALERT_CLOSE
    const auditLog = await prisma.auditLog.findFirst({
      where: {
        targetType: 'Alert',
        targetId: alert.id,
        action: 'ALERT_CLOSE',
      },
    });
    assert.ok(auditLog);
    assert.equal(auditLog.userId, adminUser.id);
    assert.equal(auditLog.details.previous.status, 'ACKNOWLEDGED');
    assert.equal(auditLog.details.updated.status, 'CLOSED');
  });

  it('forbids acknowledging an already CLOSED alert', async () => {
    const alert = await createTestAlert({ status: AlertStatus.CLOSED });

    const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${analystToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.ok(body.error.includes('Cannot acknowledge an alert that is already CLOSED'));
  });

  it('rejects transitioning alert to OPEN', async () => {
    const alert = await createTestAlert({ status: AlertStatus.CLOSED });

    const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${analystToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'OPEN' }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.ok(body.error.includes('Allowed target statuses'));
  });
});
