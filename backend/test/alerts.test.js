// test/alerts.test.js
// Dedicated comprehensive test suite for Alert Management (Phase 5 Step 2).
// Uses Node 22 native test runner (node:test).

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { AlertStatus, Severity } from '@prisma/client';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;
let testRuleA;
let testRuleB;

// Track created IDs for strict test cleanup
const createdAlertIds = [];
const createdEventIds = [];
const createdRawLogIds = [];

describe('Phase 5 Step 2 — Dedicated Alert Management Test Suite', () => {
  before(async () => {
    // Start dynamic test server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });

    // Load seeded users
    adminUser = await prisma.user.findUnique({ where: { email: 'admin@soclite.local' } });
    analystUser = await prisma.user.findUnique({ where: { email: 'analyst@soclite.local' } });
    viewerUser = await prisma.user.findUnique({ where: { email: 'viewer@soclite.local' } });

    assert.ok(adminUser, 'Seeded admin user must exist');
    assert.ok(analystUser, 'Seeded analyst user must exist');
    assert.ok(viewerUser, 'Seeded viewer user must exist');

    adminToken = signToken({ userId: adminUser.id, email: adminUser.email, role: adminUser.role });
    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });
    viewerToken = signToken({ userId: viewerUser.id, email: viewerUser.email, role: viewerUser.role });

    // Load two distinct detection rules for filtering tests
    const rules = await prisma.detectionRule.findMany({ take: 2 });
    assert.ok(rules.length >= 2, 'Must have at least 2 seeded detection rules');
    testRuleA = rules[0];
    testRuleB = rules[1];
  });

  after(async () => {
    // 1. Clean up alert events and alerts created in tests
    if (createdAlertIds.length > 0) {
      await prisma.alertEvent.deleteMany({ where: { alertId: { in: createdAlertIds } } });
      await prisma.incidentAlert.deleteMany({ where: { alertId: { in: createdAlertIds } } });
      await prisma.alert.deleteMany({ where: { id: { in: createdAlertIds } } });
      await prisma.auditLog.deleteMany({
        where: {
          targetType: 'Alert',
          targetId: { in: createdAlertIds },
        },
      });
    }

    // 2. Clean up events and raw logs created in tests
    if (createdEventIds.length > 0) {
      await prisma.event.deleteMany({ where: { id: { in: createdEventIds } } });
    }
    if (createdRawLogIds.length > 0) {
      await prisma.rawLog.deleteMany({ where: { id: { in: createdRawLogIds } } });
    }

    // 3. Close test server and disconnect
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  // ── Helper fixtures ────────────────────────────────────────────────────────

  async function createAlert(overrides = {}) {
    const alert = await prisma.alert.create({
      data: {
        ruleId: overrides.ruleId !== undefined ? overrides.ruleId : testRuleA.id,
        title: overrides.title || `Test Alert ${Date.now()}_${Math.random().toString(36).substring(7)}`,
        description: overrides.description || 'Test alert description for test suite',
        severity: overrides.severity || Severity.MEDIUM,
        status: overrides.status || AlertStatus.OPEN,
        firedAt: overrides.firedAt || new Date(),
        acknowledgedAt: overrides.acknowledgedAt || null,
        acknowledgedBy: overrides.acknowledgedBy || null,
      },
    });
    createdAlertIds.push(alert.id);
    return alert;
  }

  async function createRawLogAndEvent(overrides = {}) {
    let rawLogId = null;
    if (overrides.includeRawLog !== false) {
      const rawLog = await prisma.rawLog.create({
        data: {
          source: overrides.source || 'auth.log',
          rawContent: overrides.rawContent || 'Oct 25 12:00:00 server sshd[1234]: Failed password for root',
        },
      });
      createdRawLogIds.push(rawLog.id);
      rawLogId = rawLog.id;
    }

    const event = await prisma.event.create({
      data: {
        rawLogId,
        eventType: overrides.eventType || 'ssh_login_failed',
        timestamp: overrides.timestamp || new Date(),
        srcIp: overrides.srcIp || '192.168.1.100',
        dstIp: overrides.dstIp || '10.0.0.1',
        srcPort: overrides.srcPort || 44321,
        dstPort: overrides.dstPort || 22,
        username: overrides.username || 'root',
        hostname: overrides.hostname || 'auth-srv-01',
        message: overrides.message || 'Failed SSH login attempt',
        severity: overrides.severity || Severity.HIGH,
      },
    });
    createdEventIds.push(event.id);
    return { event, rawLogId };
  }

  async function linkAlertEvent(alertId, eventId) {
    return prisma.alertEvent.create({
      data: { alertId, eventId },
    });
  }

  // ── 1. Listing and Filtering ───────────────────────────────────────────────

  describe('Listing and Filtering (GET /api/alerts)', () => {
    it('orders alerts by firedAt descending by default', async () => {
      const t1 = new Date('2026-01-01T10:00:00.000Z');
      const t2 = new Date('2026-01-02T10:00:00.000Z');
      const t3 = new Date('2026-01-03T10:00:00.000Z');

      const a1 = await createAlert({ title: 'OrderTest Oldest', firedAt: t1 });
      const a2 = await createAlert({ title: 'OrderTest Middle', firedAt: t2 });
      const a3 = await createAlert({ title: 'OrderTest Newest', firedAt: t3 });

      const res = await fetch(`${baseUrl}/api/alerts?search=OrderTest`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.length, 3);

      assert.equal(body.data[0].id, a3.id);
      assert.equal(body.data[1].id, a2.id);
      assert.equal(body.data[2].id, a1.id);
    });

    it('returns consistent pagination metadata and handles limit boundaries', async () => {
      const res = await fetch(`${baseUrl}/api/alerts?page=1&limit=2`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(Array.isArray(body.data));
      assert.ok(body.data.length <= 2);
      assert.equal(body.pagination.page, 1);
      assert.equal(body.pagination.limit, 2);
      assert.ok(body.pagination.total >= 3);
      assert.equal(body.pagination.totalPages, Math.ceil(body.pagination.total / 2));
    });

    it('returns empty data array for high page number beyond total count', async () => {
      const res = await fetch(`${baseUrl}/api/alerts?page=9999&limit=50`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.deepEqual(body.data, []);
      assert.equal(body.pagination.page, 9999);
      assert.ok(body.pagination.total >= 0);
    });

    it('filters alerts strictly by status (OPEN, ACKNOWLEDGED, CLOSED)', async () => {
      const openAlert = await createAlert({ status: AlertStatus.OPEN, title: 'StatusFilter OPEN' });
      const ackAlert = await createAlert({ status: AlertStatus.ACKNOWLEDGED, title: 'StatusFilter ACK' });
      const closedAlert = await createAlert({ status: AlertStatus.CLOSED, title: 'StatusFilter CLOSED' });

      // Filter by ACKNOWLEDGED
      const resAck = await fetch(`${baseUrl}/api/alerts?search=StatusFilter&status=ACKNOWLEDGED`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(resAck.status, 200);
      const bodyAck = await resAck.json();
      assert.equal(bodyAck.data.length, 1);
      assert.equal(bodyAck.data[0].id, ackAlert.id);
      assert.equal(bodyAck.data[0].status, 'ACKNOWLEDGED');

      // Filter by CLOSED
      const resClosed = await fetch(`${baseUrl}/api/alerts?search=StatusFilter&status=CLOSED`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(resClosed.status, 200);
      const bodyClosed = await resClosed.json();
      assert.equal(bodyClosed.data.length, 1);
      assert.equal(bodyClosed.data[0].id, closedAlert.id);
    });

    it('filters alerts by severity (CRITICAL, HIGH, MEDIUM, LOW)', async () => {
      const crit = await createAlert({ severity: Severity.CRITICAL, title: 'SevFilter CRIT' });
      const low = await createAlert({ severity: Severity.LOW, title: 'SevFilter LOW' });

      const res = await fetch(`${baseUrl}/api/alerts?search=SevFilter&severity=CRITICAL`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.length, 1);
      assert.equal(body.data[0].id, crit.id);
      assert.equal(body.data[0].severity, 'CRITICAL');
    });

    it('filters alerts by ruleId', async () => {
      const alertA = await createAlert({ ruleId: testRuleA.id, title: 'RuleFilter RuleA' });
      const alertB = await createAlert({ ruleId: testRuleB.id, title: 'RuleFilter RuleB' });

      const res = await fetch(`${baseUrl}/api/alerts?search=RuleFilter&ruleId=${testRuleA.id}`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.length, 1);
      assert.equal(body.data[0].id, alertA.id);
      assert.equal(body.data[0].rule.id, testRuleA.id);
    });

    it('searches across both title and description case-insensitively', async () => {
      const matchInTitle = await createAlert({
        title: 'Detecting CobaltStrike Beacon',
        description: 'Standard event analysis',
      });
      const matchInDesc = await createAlert({
        title: 'Generic Anomaly',
        description: 'Evidence matches cobaltstrike command pattern',
      });

      const res = await fetch(`${baseUrl}/api/alerts?search=cobaltstrike`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.ok(body.data.some((a) => a.id === matchInTitle.id));
      assert.ok(body.data.some((a) => a.id === matchInDesc.id));
    });

    it('filters accurately by date range (startDate and endDate)', async () => {
      const tInside = new Date('2026-05-15T12:00:00.000Z');
      const tBefore = new Date('2026-05-10T12:00:00.000Z');
      const tAfter = new Date('2026-05-20T12:00:00.000Z');

      const insideAlert = await createAlert({ title: 'DateFilter Inside', firedAt: tInside });
      await createAlert({ title: 'DateFilter Before', firedAt: tBefore });
      await createAlert({ title: 'DateFilter After', firedAt: tAfter });

      const start = '2026-05-14T00:00:00.000Z';
      const end = '2026-05-16T00:00:00.000Z';
      const res = await fetch(`${baseUrl}/api/alerts?search=DateFilter&startDate=${start}&endDate=${end}`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.length, 1);
      assert.equal(body.data[0].id, insideAlert.id);
    });

    it('returns empty result set when filters match nothing', async () => {
      const res = await fetch(`${baseUrl}/api/alerts?search=NonExistentSearchStringXYZ123456`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.deepEqual(body.data, []);
      assert.equal(body.pagination.total, 0);
      assert.equal(body.pagination.totalPages, 1);
    });

    it('rejects invalid startDate > endDate with 400', async () => {
      const start = '2026-10-25T00:00:00.000Z';
      const end = '2026-10-24T00:00:00.000Z';
      const res = await fetch(`${baseUrl}/api/alerts?startDate=${start}&endDate=${end}`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('startDate'));
    });

    it('rejects unparseable date strings with 400', async () => {
      const res = await fetch(`${baseUrl}/api/alerts?startDate=invalid-date-format`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('date string'));
    });

    it('rejects invalid query values (page, limit, status, severity, ruleId, search length) with 400', async () => {
      const testCases = [
        ['page=0', 'page'],
        ['page=-5', 'page'],
        ['page=abc', 'page'],
        ['limit=0', 'limit'],
        ['limit=101', 'limit'],
        ['status=UNKNOWN_STATUS', 'status'],
        ['severity=EXTREME', 'severity'],
        ['ruleId=not-a-uuid', 'ruleId'],
        [`search=${'a'.repeat(205)}`, 'search'],
      ];

      for (const [qs, expectedField] of testCases) {
        const res = await fetch(`${baseUrl}/api/alerts?${qs}`, {
          headers: { Authorization: `Bearer ${analystToken}` },
        });
        assert.equal(res.status, 400, `Expected 400 for query: ${qs}`);
        const body = await res.json();
        assert.equal(body.success, false);
        assert.ok(body.error.toLowerCase().includes(expectedField.toLowerCase()));
      }
    });
  });

  // ── 2. Statistics ──────────────────────────────────────────────────────────

  describe('Statistics Aggregation (GET /api/alerts/stats)', () => {
    it('returns consistent status and severity counts matching database records', async () => {
      // Create known alert breakdown
      await createAlert({ status: AlertStatus.OPEN, severity: Severity.CRITICAL });
      await createAlert({ status: AlertStatus.OPEN, severity: Severity.HIGH });
      await createAlert({ status: AlertStatus.ACKNOWLEDGED, severity: Severity.MEDIUM });
      await createAlert({ status: AlertStatus.CLOSED, severity: Severity.LOW });

      const res = await fetch(`${baseUrl}/api/alerts/stats`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      const stats = body.data;

      assert.ok(typeof stats.total === 'number');
      assert.ok(stats.total >= 4);

      // Verify mathematical identity: total === sum(byStatus) === sum(bySeverity)
      const statusSum = stats.byStatus.OPEN + stats.byStatus.ACKNOWLEDGED + stats.byStatus.CLOSED;
      const severitySum = stats.bySeverity.CRITICAL + stats.bySeverity.HIGH + stats.bySeverity.MEDIUM + stats.bySeverity.LOW;

      assert.equal(stats.total, statusSum, 'Total must equal sum of status counts');
      assert.equal(stats.total, severitySum, 'Total must equal sum of severity counts');

      // Verify against real database count
      const realCount = await prisma.alert.count();
      assert.equal(stats.total, realCount);
    });

    it('includes all enum keys initialized to numbers even if zero', async () => {
      const res = await fetch(`${baseUrl}/api/alerts/stats`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      assert.ok('OPEN' in data.byStatus);
      assert.ok('ACKNOWLEDGED' in data.byStatus);
      assert.ok('CLOSED' in data.byStatus);

      assert.ok('CRITICAL' in data.bySeverity);
      assert.ok('HIGH' in data.bySeverity);
      assert.ok('MEDIUM' in data.bySeverity);
      assert.ok('LOW' in data.bySeverity);
    });
  });

  // ── 3. Alert Details and Evidence ──────────────────────────────────────────

  describe('Alert Details and Evidence (GET /api/alerts/:id)', () => {
    it('returns complete alert with detection rule and linked evidence chain (Event -> RawLog)', async () => {
      const alert = await createAlert({ title: 'Evidence Chain Test' });
      const { event, rawLogId } = await createRawLogAndEvent({
        source: 'firewall.log',
        rawContent: 'DROP TCP 192.168.1.50 -> 10.0.0.1:445',
      });
      await linkAlertEvent(alert.id, event.id);

      const res = await fetch(`${baseUrl}/api/alerts/${alert.id}`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);

      const alertData = body.data;
      assert.equal(alertData.id, alert.id);
      assert.equal(alertData.evidenceCount, 1);
      assert.ok(Array.isArray(alertData.evidence));
      assert.equal(alertData.evidence.length, 1);

      const evidenceItem = alertData.evidence[0];
      assert.equal(evidenceItem.alertId, alert.id);
      assert.equal(evidenceItem.eventId, event.id);
      assert.equal(evidenceItem.event.eventType, 'ssh_login_failed');

      // Verify RawLog is included and only intended safe fields are exposed
      assert.ok(evidenceItem.event.rawLog);
      assert.equal(evidenceItem.event.rawLog.id, rawLogId);
      assert.equal(evidenceItem.event.rawLog.source, 'firewall.log');
      assert.equal(evidenceItem.event.rawLog.rawContent, 'DROP TCP 192.168.1.50 -> 10.0.0.1:445');
      assert.ok(evidenceItem.event.rawLog.receivedAt);

      // Verify no unexpected/secret properties leaked
      const rawLogKeys = Object.keys(evidenceItem.event.rawLog);
      assert.deepEqual(rawLogKeys.sort(), ['id', 'rawContent', 'receivedAt', 'source'].sort());
    });

    it('safely handles alerts without any evidence linked (evidenceCount: 0, evidence: [])', async () => {
      const alertWithoutEvidence = await createAlert({ title: 'No Evidence Alert' });

      const res = await fetch(`${baseUrl}/api/alerts/${alertWithoutEvidence.id}`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.evidenceCount, 0);
      assert.deepEqual(body.data.evidence, []);
    });

    it('safely handles events that have null rawLogId without null reference crashes', async () => {
      const alert = await createAlert({ title: 'Event Without RawLog Alert' });
      const { event } = await createRawLogAndEvent({ includeRawLog: false });
      await linkAlertEvent(alert.id, event.id);

      const res = await fetch(`${baseUrl}/api/alerts/${alert.id}`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.evidenceCount, 1);
      assert.equal(body.data.evidence[0].event.rawLog, null);
    });

    it('returns 404 for non-existent alert UUID', async () => {
      const nonExistentUuid = 'ffffffff-ffff-4fff-bfff-ffffffffffff';
      const res = await fetch(`${baseUrl}/api/alerts/${nonExistentUuid}`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 404);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('not found'));
    });

    it('returns 400 for malformed alert ID path parameter', async () => {
      const res = await fetch(`${baseUrl}/api/alerts/not-a-valid-uuid-123`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('UUID'));
    });
  });

  // ── 4. Status Lifecycle and Audit Logging ───────────────────────────────────

  describe('Status Lifecycle & Audit Logging (PATCH /api/alerts/:id/status)', () => {
    it('transitions OPEN alert to ACKNOWLEDGED, setting server context metadata and audit record', async () => {
      const alert = await createAlert({ status: AlertStatus.OPEN, title: 'Lifecycle Transition 1' });

      const beforeTime = Date.now();
      const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
      });
      const afterTime = Date.now();

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.status, 'ACKNOWLEDGED');

      // Verify timestamp is approximately current
      const ackTime = new Date(body.data.acknowledgedAt).getTime();
      assert.ok(ackTime >= beforeTime - 5000 && ackTime <= afterTime + 5000);

      // Verify acknowledgedBy was set from authenticated user (NOT client input)
      assert.equal(body.data.acknowledgedBy, analystUser.name);

      // Verify AuditLog record in DB
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Alert', targetId: alert.id, action: 'ALERT_ACK' },
      });
      assert.ok(audit, 'Audit log entry must exist for ALERT_ACK');
      assert.equal(audit.userId, analystUser.id);
      assert.equal(audit.details.previous.status, 'OPEN');
      assert.equal(audit.details.updated.status, 'ACKNOWLEDGED');
      assert.equal(audit.details.actionBy, analystUser.name);
    });

    it('transitions OPEN alert directly to CLOSED with ALERT_CLOSE audit log', async () => {
      const alert = await createAlert({ status: AlertStatus.OPEN, title: 'Direct Close Alert' });

      const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: 'CLOSED' }),
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.status, 'CLOSED');
      assert.equal(body.data.acknowledgedAt, null);
      assert.equal(body.data.acknowledgedBy, null);

      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Alert', targetId: alert.id, action: 'ALERT_CLOSE' },
      });
      assert.ok(audit);
      assert.equal(audit.details.previous.status, 'OPEN');
      assert.equal(audit.details.updated.status, 'CLOSED');
    });

    it('transitions ACKNOWLEDGED alert to CLOSED while strictly preserving prior acknowledgement metadata', async () => {
      const priorAckTime = new Date('2026-03-01T08:00:00.000Z');
      const priorAckBy = 'Senior Analyst Smith';

      const alert = await createAlert({
        status: AlertStatus.ACKNOWLEDGED,
        acknowledgedAt: priorAckTime,
        acknowledgedBy: priorAckBy,
        title: 'Preserve Ack Metadata Alert',
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

      // Crucial: acknowledgement metadata preserved!
      assert.equal(new Date(body.data.acknowledgedAt).getTime(), priorAckTime.getTime());
      assert.equal(body.data.acknowledgedBy, priorAckBy);

      // Verify AuditLog
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Alert', targetId: alert.id, action: 'ALERT_CLOSE' },
      });
      assert.ok(audit);
      assert.equal(audit.userId, adminUser.id);
      assert.equal(audit.details.previous.status, 'ACKNOWLEDGED');
      assert.equal(audit.details.updated.status, 'CLOSED');
    });

    it('rejects transitioning a CLOSED alert back to ACKNOWLEDGED with 400', async () => {
      const alert = await createAlert({ status: AlertStatus.CLOSED, title: 'Already Closed Alert' });

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

      // Ensure no audit log entry was created
      const audits = await prisma.auditLog.findMany({
        where: { targetType: 'Alert', targetId: alert.id },
      });
      assert.equal(audits.length, 0);
    });

    it('rejects repeated same-status updates without creating duplicate audit records', async () => {
      const alert = await createAlert({ status: AlertStatus.OPEN });

      // First transition -> ACKNOWLEDGED
      const firstRes = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
      });
      assert.equal(firstRes.status, 200);

      // Second identical transition
      const secondRes = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
      });
      assert.equal(secondRes.status, 400);
      const body = await secondRes.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('already in ACKNOWLEDGED'));

      // Verify audit log count is exactly 1 (no duplicate logged!)
      const auditCount = await prisma.auditLog.count({
        where: { targetType: 'Alert', targetId: alert.id, action: 'ALERT_ACK' },
      });
      assert.equal(auditCount, 1);
    });

    it('rejects client attempting to set status to OPEN or invalid status', async () => {
      const alert = await createAlert({ status: AlertStatus.CLOSED });

      for (const badStatus of ['OPEN', 'RESOLVED', 'DISMISSED', 'PENDING']) {
        const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: badStatus }),
        });
        assert.equal(res.status, 400);
        const body = await res.json();
        assert.equal(body.success, false);
      }
    });

    it('rejects invalid or client-spoofed payload fields with 400', async () => {
      const alert = await createAlert({ status: AlertStatus.OPEN });

      const spoofedPayloads = [
        {}, // Empty
        null, // Non-object
        { status: 'ACKNOWLEDGED', userId: 'spoofed-id' },
        { status: 'ACKNOWLEDGED', acknowledgedBy: 'Attacker' },
        { status: 'ACKNOWLEDGED', acknowledgedAt: '2020-01-01T00:00:00Z' },
        { status: 'ACKNOWLEDGED', arbitraryField: 'malicious' },
      ];

      for (const payload of spoofedPayloads) {
        const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        assert.equal(res.status, 400);
        const body = await res.json();
        assert.equal(body.success, false);
      }
    });
  });

  // ── 5. Authorization & RBAC ────────────────────────────────────────────────

  describe('Authorization and RBAC Enforcement', () => {
    it('rejects unauthenticated requests to all endpoints with 401', async () => {
      const dummyId = '00000000-0000-0000-0000-000000000000';
      const endpoints = [
        { url: `${baseUrl}/api/alerts`, method: 'GET' },
        { url: `${baseUrl}/api/alerts/stats`, method: 'GET' },
        { url: `${baseUrl}/api/alerts/${dummyId}`, method: 'GET' },
        { url: `${baseUrl}/api/alerts/${dummyId}/status`, method: 'PATCH', body: { status: 'ACKNOWLEDGED' } },
      ];

      for (const ep of endpoints) {
        const res = await fetch(ep.url, {
          method: ep.method,
          headers: ep.body ? { 'Content-Type': 'application/json' } : undefined,
          body: ep.body ? JSON.stringify(ep.body) : undefined,
        });
        assert.equal(res.status, 401, `Endpoint ${ep.method} ${ep.url} must return 401`);
        const body = await res.json();
        assert.equal(body.success, false);
      }
    });

    it('allows VIEWER to read alerts, stats, and alert details', async () => {
      const alert = await createAlert({ title: 'Viewer Read Test' });

      const resList = await fetch(`${baseUrl}/api/alerts`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(resList.status, 200);

      const resStats = await fetch(`${baseUrl}/api/alerts/stats`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(resStats.status, 200);

      const resDetail = await fetch(`${baseUrl}/api/alerts/${alert.id}`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(resDetail.status, 200);
    });

    it('forbids VIEWER from updating alert status with 403 Forbidden', async () => {
      const alert = await createAlert({ status: AlertStatus.OPEN });

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

    it('allows both ANALYST and ADMIN to update alert status', async () => {
      const alert1 = await createAlert({ status: AlertStatus.OPEN });
      const resAnalyst = await fetch(`${baseUrl}/api/alerts/${alert1.id}/status`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
      });
      assert.equal(resAnalyst.status, 200);

      const alert2 = await createAlert({ status: AlertStatus.OPEN });
      const resAdmin = await fetch(`${baseUrl}/api/alerts/${alert2.id}/status`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'CLOSED' }),
      });
      assert.equal(resAdmin.status, 200);
    });
  });

  // ── 6. Reliability, Rollback, and Concurrency ──────────────────────────────

  describe('Reliability, Atomic Rollback, and Concurrency', () => {
    it('rolls back database status change atomically if audit log creation fails', async () => {
      const alert = await createAlert({ status: AlertStatus.OPEN, title: 'Rollback Test Alert' });

      // Intercept prisma.$transaction to simulate an unexpected audit log write failure inside the transaction
      const originalTransaction = prisma.$transaction;
      prisma.$transaction = async function (arg, ...rest) {
        if (typeof arg === 'function') {
          return originalTransaction.call(prisma, async (tx) => {
            // Mock tx.auditLog.create to throw a database write error
            const interceptedTx = Object.create(tx);
            interceptedTx.auditLog = {
              ...tx.auditLog,
              create: async () => {
                throw new Error('Simulated atomic transaction failure on audit log write');
              },
            };
            return arg(interceptedTx);
          }, ...rest);
        }
        return originalTransaction.call(prisma, arg, ...rest);
      };

      try {
        const res = await fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${analystToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
        });

        // Request must fail due to transaction abort
        assert.equal(res.status, 500);

        // Verify PostgreSQL transaction rollback: Alert status remains OPEN in DB!
        const refreshedAlert = await prisma.alert.findUnique({ where: { id: alert.id } });
        assert.equal(refreshedAlert.status, 'OPEN', 'Status must roll back to OPEN when transaction fails');
        assert.equal(refreshedAlert.acknowledgedAt, null);
        assert.equal(refreshedAlert.acknowledgedBy, null);

        // Verify no orphaned audit log entry
        const orphanedAudit = await prisma.auditLog.findFirst({
          where: { targetType: 'Alert', targetId: alert.id },
        });
        assert.equal(orphanedAudit, null, 'No audit log must exist following rollback');
      } finally {
        // Restore prisma.$transaction immediately
        prisma.$transaction = originalTransaction;
      }
    });

    it('safely coordinates concurrent status update requests without corrupting state or audit log', async () => {
      const alert = await createAlert({ status: AlertStatus.OPEN, title: 'Concurrency Test Alert' });

      // Send two concurrent acknowledge requests simultaneously
      const [res1, res2] = await Promise.all([
        fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
        }),
        fetch(`${baseUrl}/api/alerts/${alert.id}/status`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
        }),
      ]);

      const statuses = [res1.status, res2.status].sort();
      // Exactly one succeeds (200), and one is rejected (400) because alert is already acknowledged
      assert.deepEqual(statuses, [200, 400], 'One concurrent request must succeed and one must be rejected');

      // Verify DB final state
      const refreshedAlert = await prisma.alert.findUnique({ where: { id: alert.id } });
      assert.equal(refreshedAlert.status, 'ACKNOWLEDGED');

      // Verify audit logs: exactly 1 audit entry for this alert
      const auditCount = await prisma.auditLog.count({
        where: { targetType: 'Alert', targetId: alert.id, action: 'ALERT_ACK' },
      });
      assert.equal(auditCount, 1, 'Exactly one audit log entry must be created');
    });

    it('verifies all API error responses follow the centralized { success: false, error: ... } format', async () => {
      const badRequests = [
        fetch(`${baseUrl}/api/alerts/non-uuid`),
        fetch(`${baseUrl}/api/alerts?page=-1`),
        fetch(`${baseUrl}/api/alerts?severity=INVALID`),
        fetch(`${baseUrl}/api/alerts/00000000-0000-0000-0000-000000000000/status`, {
          method: 'PATCH',
          headers: { Authorization: `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'INVALID' }),
        }),
      ];

      for (const reqPromise of badRequests) {
        const res = await reqPromise;
        assert.ok(res.status >= 400 && res.status < 500);
        const body = await res.json();
        assert.equal(body.success, false);
        assert.ok(typeof body.error === 'string' && body.error.length > 0);
      }
    });
  });
});
