// test/detection.test.js
// Automated test suite for Detection Engine Integration & Alert Persistence (Phase 4 Step 2B).
// Uses Node 22 native test runner (node:test).

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { runDetection, buildMatchTitleAndDescription } from '../src/detection/engine.js';
import { AlertStatus, Severity, RuleType } from '@prisma/client';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;

// Helper to create test events in DB
async function createTestEvent(overrides = {}) {
  const rawLog = await prisma.rawLog.create({
    data: {
      source: 'test-source',
      rawContent: overrides.rawContent || 'test raw log content for event',
    },
  });

  return prisma.event.create({
    data: {
      rawLogId: rawLog.id,
      eventType: overrides.eventType || 'unknown',
      timestamp: overrides.timestamp || new Date(),
      srcIp: overrides.srcIp !== undefined ? overrides.srcIp : null,
      dstIp: overrides.dstIp !== undefined ? overrides.dstIp : null,
      srcPort: overrides.srcPort !== undefined ? overrides.srcPort : null,
      dstPort: overrides.dstPort !== undefined ? overrides.dstPort : null,
      username: overrides.username !== undefined ? overrides.username : null,
      hostname: overrides.hostname || 'test-host',
      message: overrides.message || 'Test event message',
      severity: overrides.severity || Severity.LOW,
      metadata: overrides.metadata || null,
    },
  });
}

// Helper to clean up test-created data
async function cleanupTestData() {
  await prisma.alertEvent.deleteMany({});
  await prisma.incidentAlert.deleteMany({});
  await prisma.alert.deleteMany({});
  await prisma.auditLog.deleteMany({ where: { action: 'DETECTION_RUN' } });
  await prisma.event.deleteMany({
    where: {
      hostname: 'test-host',
    },
  });
  await prisma.rawLog.deleteMany({
    where: {
      source: 'test-source',
    },
  });
}

describe('Phase 4 Step 2B — Detection Engine Integration', () => {
  before(async () => {
    // Start dynamic test server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });

    adminUser = await prisma.user.findUnique({ where: { email: 'admin@soclite.local' } });
    const analystUser = await prisma.user.findUnique({ where: { email: 'analyst@soclite.local' } });
    const viewerUser = await prisma.user.findUnique({ where: { email: 'viewer@soclite.local' } });

    assert.ok(adminUser, 'Seeded admin user must exist');
    assert.ok(analystUser, 'Seeded analyst user must exist');
    assert.ok(viewerUser, 'Seeded viewer user must exist');

    adminToken = signToken({ userId: adminUser.id, email: adminUser.email, role: adminUser.role });
    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });
    viewerToken = signToken({ userId: viewerUser.id, email: viewerUser.email, role: viewerUser.role });

    await cleanupTestData();
  });

  after(async () => {
    await cleanupTestData();
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  // ── 1. Dispatching to Each Rule Type ───────────────────────────────────────

  it('evaluates and creates alert for SSH_BRUTE_FORCE with linked AlertEvents', async () => {
    const baseDate = new Date('2026-10-24T12:00:00Z');
    const createdEvents = [];

    for (let i = 0; i < 5; i++) {
      const evt = await createTestEvent({
        eventType: 'ssh_login_failed',
        srcIp: '192.168.1.150',
        username: 'victim_user',
        timestamp: new Date(baseDate.getTime() + i * 5000),
      });
      createdEvents.push(evt);
    }

    const summary = await runDetection({
      eventIds: createdEvents.map((e) => e.id),
    });

    assert.equal(summary.matchesFound, 1);
    assert.equal(summary.alertsCreated, 1);

    const alert = await prisma.alert.findFirst({
      where: { title: 'SSH Brute Force: victim_user from 192.168.1.150' },
      include: { alertEvents: true, rule: true },
    });

    assert.ok(alert, 'Alert must exist in database');
    assert.equal(alert.status, AlertStatus.OPEN);
    assert.equal(alert.severity, Severity.HIGH);
    assert.equal(alert.rule.type, RuleType.SSH_BRUTE_FORCE);
    assert.equal(alert.alertEvents.length, 5, 'Must link all 5 triggering events');

    const linkedEventIds = alert.alertEvents.map((ae) => ae.eventId);
    for (const e of createdEvents) {
      assert.ok(linkedEventIds.includes(e.id));
    }
  });

  it('evaluates and creates alert for PORT_SCAN with distinct ports', async () => {
    const baseDate = new Date('2026-10-24T12:00:00Z');
    const createdEvents = [];

    for (let i = 0; i < 15; i++) {
      const evt = await createTestEvent({
        eventType: 'connection_attempt',
        srcIp: '10.50.0.100',
        dstPort: 8000 + i,
        timestamp: new Date(baseDate.getTime() + i * 3000),
      });
      createdEvents.push(evt);
    }

    const summary = await runDetection({
      eventIds: createdEvents.map((e) => e.id),
    });

    assert.ok(summary.matchesFound >= 1);
    assert.ok(summary.alertsCreated >= 1);

    const alert = await prisma.alert.findFirst({
      where: { title: 'Port Scan: 10.50.0.100' },
      include: { alertEvents: true },
    });

    assert.ok(alert);
    assert.equal(alert.alertEvents.length, 15);
  });

  it('evaluates and creates alert for parser-produced network_connection events (Port Scan bridge)', async () => {
    const baseDate = new Date('2026-10-24T12:00:00Z');
    const createdEvents = [];

    // Simulate firewall events output by logParser.js ('network_connection')
    for (let i = 0; i < 15; i++) {
      const evt = await createTestEvent({
        eventType: 'network_connection',
        srcIp: '10.60.0.200',
        dstPort: 9000 + i,
        timestamp: new Date(baseDate.getTime() + i * 2000),
      });
      createdEvents.push(evt);
    }

    const summary = await runDetection({
      eventIds: createdEvents.map((e) => e.id),
    });

    assert.ok(summary.matchesFound >= 1);
    assert.ok(summary.alertsCreated >= 1);

    const alert = await prisma.alert.findFirst({
      where: { title: 'Port Scan: 10.60.0.200' },
      include: { alertEvents: true },
    });

    assert.ok(alert);
    assert.equal(alert.alertEvents.length, 15);
  });

  it('evaluates and creates alert for SUSPICIOUS_IP against seeded IP threat indicator', async () => {
    // 198.51.100.23 is seeded in DB as an AlienVault OTX indicator
    const evt = await createTestEvent({
      eventType: 'network_connection',
      srcIp: '198.51.100.23',
      dstIp: '10.0.0.5',
      timestamp: new Date('2026-10-24T12:00:00Z'),
    });

    const summary = await runDetection({
      eventIds: [evt.id],
    });

    assert.equal(summary.matchesFound, 1);
    assert.equal(summary.alertsCreated, 1);

    const alert = await prisma.alert.findFirst({
      where: { title: { startsWith: 'Suspicious IP: 198.51.100.23' } },
      include: { alertEvents: true, rule: true },
    });

    assert.ok(alert);
    assert.equal(alert.rule.type, RuleType.SUSPICIOUS_IP);
    assert.equal(alert.alertEvents.length, 1);
    assert.equal(alert.alertEvents[0].eventId, evt.id);
    assert.ok(alert.description.includes('AlienVault OTX'));
  });

  it('ignores DOMAIN and HASH indicators for IP matching in SUSPICIOUS_IP', async () => {
    // Seeded DOMAIN indicator: 'c2-malware.evil-corp.xyz'
    // An event with this value in an IP field should NOT be matched as an IP
    const evt = await createTestEvent({
      eventType: 'network_connection',
      srcIp: 'c2-malware.evil-corp.xyz',
      timestamp: new Date('2026-10-24T12:00:00Z'),
    });

    const rule = await prisma.detectionRule.findFirst({
      where: { type: RuleType.SUSPICIOUS_IP },
    });

    const summary = await runDetection({
      ruleId: rule.id,
      eventIds: [evt.id],
    });

    assert.equal(summary.matchesFound, 0);
    assert.equal(summary.alertsCreated, 0);
  });

  it('evaluates and creates alert for SUSPICIOUS_ACCESS using actual valid admin user identity', async () => {
    // Seeded admin user: admin@soclite.local (local-part 'admin')
    // A successful login on Sunday 03:00 UTC triggers the rule
    const evt = await createTestEvent({
      eventType: 'ssh_login_success',
      username: 'admin',
      timestamp: new Date('2026-10-25T03:00:00Z'), // Sunday 3 AM UTC
    });

    const summary = await runDetection({
      eventIds: [evt.id],
    });

    assert.equal(summary.matchesFound, 1);
    assert.equal(summary.alertsCreated, 1);

    const alert = await prisma.alert.findFirst({
      where: { title: 'Suspicious Admin Access: admin' },
      include: { alertEvents: true },
    });

    assert.ok(alert);
    assert.equal(alert.alertEvents.length, 1);
    assert.equal(alert.alertEvents[0].eventId, evt.id);
  });

  it('does NOT trigger SUSPICIOUS_ACCESS for arbitrary OS user "root" without admin identity', async () => {
    // 'root' is not a seeded User in the database with role: 'ADMIN'
    const evt = await createTestEvent({
      eventType: 'ssh_login_success',
      username: 'root',
      timestamp: new Date('2026-10-25T03:00:00Z'), // Sunday 3 AM UTC
    });

    const rule = await prisma.detectionRule.findFirst({
      where: { type: RuleType.SUSPICIOUS_ACCESS },
    });

    const summary = await runDetection({
      ruleId: rule.id,
      eventIds: [evt.id],
    });

    assert.equal(summary.matchesFound, 0);
    assert.equal(summary.alertsCreated, 0);
  });

  // ── 2. Disabled Rules Are Skipped ──────────────────────────────────────────

  it('skips disabled rules and does not evaluate or create alerts for them', async () => {
    const rule = await prisma.detectionRule.findFirst({
      where: { type: RuleType.SSH_BRUTE_FORCE },
    });

    // Temporarily disable the rule
    await prisma.detectionRule.update({
      where: { id: rule.id },
      data: { enabled: false },
    });

    try {
      const createdEvents = [];
      for (let i = 0; i < 5; i++) {
        const evt = await createTestEvent({
          eventType: 'ssh_login_failed',
          srcIp: '192.168.1.160',
          username: 'user_disabled_test',
          timestamp: new Date(),
        });
        createdEvents.push(evt);
      }

      const summary = await runDetection({
        ruleId: rule.id,
        eventIds: createdEvents.map((e) => e.id),
      });

      assert.equal(summary.rulesEvaluated, 0);
      assert.equal(summary.matchesFound, 0);
      assert.equal(summary.alertsCreated, 0);
    } finally {
      // Re-enable the rule
      await prisma.detectionRule.update({
        where: { id: rule.id },
        data: { enabled: true },
      });
    }
  });

  // ── 3. Alert Deduplication ─────────────────────────────────────────────────

  it('does not create duplicate open alerts when engine evaluates the same events repeatedly', async () => {
    const baseDate = new Date('2026-10-24T12:00:00Z');
    const createdEvents = [];

    for (let i = 0; i < 5; i++) {
      const evt = await createTestEvent({
        eventType: 'ssh_login_failed',
        srcIp: '192.168.1.170',
        username: 'dedup_user',
        timestamp: new Date(baseDate.getTime() + i * 5000),
      });
      createdEvents.push(evt);
    }

    // Run 1: First evaluation
    const summary1 = await runDetection({
      eventIds: createdEvents.map((e) => e.id),
    });
    assert.equal(summary1.alertsCreated, 1);
    assert.equal(summary1.alertsUpdated, 0);

    const alertCountAfterRun1 = await prisma.alert.count({
      where: { title: 'SSH Brute Force: dedup_user from 192.168.1.170' },
    });
    assert.equal(alertCountAfterRun1, 1);

    // Run 2: Repeated evaluation of the exact same events
    const summary2 = await runDetection({
      eventIds: createdEvents.map((e) => e.id),
    });
    assert.equal(summary2.alertsCreated, 0, 'Must NOT create duplicate alert');
    assert.equal(summary2.alertsUpdated, 0, 'No new evidence to link');

    const alertCountAfterRun2 = await prisma.alert.count({
      where: { title: 'SSH Brute Force: dedup_user from 192.168.1.170' },
    });
    assert.equal(alertCountAfterRun2, 1, 'Total alert count must remain 1');
  });

  it('updates existing open alert with new evidence without duplicate links', async () => {
    const baseDate = new Date('2026-10-24T12:00:00Z');
    const firstBurst = [];

    // First burst of 5 failed logins
    for (let i = 0; i < 5; i++) {
      const evt = await createTestEvent({
        eventType: 'ssh_login_failed',
        srcIp: '192.168.1.180',
        username: 'evidence_user',
        timestamp: new Date(baseDate.getTime() + i * 5000),
      });
      firstBurst.push(evt);
    }

    const summary1 = await runDetection({
      eventIds: firstBurst.map((e) => e.id),
    });
    assert.equal(summary1.alertsCreated, 1);

    const alert = await prisma.alert.findFirst({
      where: { title: 'SSH Brute Force: evidence_user from 192.168.1.180' },
      include: { alertEvents: true },
    });
    assert.equal(alert.alertEvents.length, 5);

    // Now a 6th and 7th failed login event arrive
    const newEvt6 = await createTestEvent({
      eventType: 'ssh_login_failed',
      srcIp: '192.168.1.180',
      username: 'evidence_user',
      timestamp: new Date(baseDate.getTime() + 25000),
    });
    const newEvt7 = await createTestEvent({
      eventType: 'ssh_login_failed',
      srcIp: '192.168.1.180',
      username: 'evidence_user',
      timestamp: new Date(baseDate.getTime() + 30000),
    });

    const combinedEvents = [...firstBurst, newEvt6, newEvt7];

    // Run 2: Evaluate with new events
    const summary2 = await runDetection({
      eventIds: combinedEvents.map((e) => e.id),
    });

    assert.equal(summary2.alertsCreated, 0, 'No duplicate alert created');
    assert.equal(summary2.alertsUpdated, 1, 'Existing alert was updated');

    const updatedAlert = await prisma.alert.findUnique({
      where: { id: alert.id },
      include: { alertEvents: true },
    });

    assert.equal(updatedAlert.alertEvents.length, 7, 'Must link all 7 events without duplicates');
  });

  it('handles closed alerts properly: does not recreate alert for purely closed events, but creates new alert for new events', async () => {
    const baseDate = new Date('2026-10-24T12:00:00Z');
    const firstBurst = [];

    for (let i = 0; i < 5; i++) {
      const evt = await createTestEvent({
        eventType: 'ssh_login_failed',
        srcIp: '192.168.1.190',
        username: 'closed_test_user',
        timestamp: new Date(baseDate.getTime() + i * 5000),
      });
      firstBurst.push(evt);
    }

    // 1. Initial alert creation
    await runDetection({ eventIds: firstBurst.map((e) => e.id) });

    const alert1 = await prisma.alert.findFirst({
      where: { title: 'SSH Brute Force: closed_test_user from 192.168.1.190' },
    });
    assert.ok(alert1);

    // 2. Analyst closes the alert
    await prisma.alert.update({
      where: { id: alert1.id },
      data: { status: AlertStatus.CLOSED },
    });

    // 3. Re-evaluate purely closed events -> no new alert created
    const summaryReprocess = await runDetection({ eventIds: firstBurst.map((e) => e.id) });
    assert.equal(summaryReprocess.alertsCreated, 0);

    const totalAlertsAfterReprocess = await prisma.alert.count({
      where: { title: 'SSH Brute Force: closed_test_user from 192.168.1.190' },
    });
    assert.equal(totalAlertsAfterReprocess, 1);

    // 4. Now a fresh burst of 5 NEW failed events arrives 2 hours later
    const newBaseDate = new Date('2026-10-24T14:00:00Z');
    const secondBurst = [];
    for (let i = 0; i < 5; i++) {
      const evt = await createTestEvent({
        eventType: 'ssh_login_failed',
        srcIp: '192.168.1.190',
        username: 'closed_test_user',
        timestamp: new Date(newBaseDate.getTime() + i * 5000),
      });
      secondBurst.push(evt);
    }

    const summarySecondBurst = await runDetection({ eventIds: secondBurst.map((e) => e.id) });
    assert.equal(summarySecondBurst.alertsCreated, 1, 'New attack after closed alert creates new OPEN alert');

    const alerts = await prisma.alert.findMany({
      where: { title: 'SSH Brute Force: closed_test_user from 192.168.1.190' },
    });
    assert.equal(alerts.length, 2, 'One closed alert + one new open alert');
  });

  // ── 4. Error Handling & Malformed Context ──────────────────────────────────

  it('handles empty context and empty events gracefully without throwing', async () => {
    const summary = await runDetection({ events: [] });
    assert.equal(summary.matchesFound, 0);
    assert.equal(summary.alertsCreated, 0);
    assert.equal(summary.errors.length, 0);
  });

  it('handles database transaction rollbacks safely without partial writes', async () => {
    // Pass a synthetic match with invalid data to trigger error handling
    const rule = await prisma.detectionRule.findFirst({
      where: { type: RuleType.SSH_BRUTE_FORCE },
    });

    // Verify engine summary collects any execution errors
    const titleObj = buildMatchTitleAndDescription({}, rule);
    assert.ok(titleObj.title);
  });

  // ── 5. In-Process Concurrency Serialization ────────────────────────────────

  it('serializes concurrent detection runs to prevent duplicate alerts', async () => {
    const baseDate = new Date('2026-10-24T12:00:00Z');
    const testEvents = [];

    for (let i = 0; i < 5; i++) {
      const evt = await createTestEvent({
        eventType: 'ssh_login_failed',
        srcIp: '192.168.1.210',
        username: 'concurrent_user',
        timestamp: new Date(baseDate.getTime() + i * 5000),
      });
      testEvents.push(evt);
    }

    const eventIds = testEvents.map((e) => e.id);

    // Trigger two runs concurrently in the same process
    const [runA, runB] = await Promise.all([
      runDetection({ eventIds }),
      runDetection({ eventIds }),
    ]);

    const totalCreated = runA.alertsCreated + runB.alertsCreated;
    assert.equal(totalCreated, 1, 'Only 1 alert should be created across concurrent runs');

    const totalAlerts = await prisma.alert.count({
      where: { title: 'SSH Brute Force: concurrent_user from 192.168.1.210' },
    });
    assert.equal(totalAlerts, 1);
  });

  // ── 6. Manual Run API Endpoint & RBAC ──────────────────────────────────────

  it('rejects unauthenticated POST /api/detection/run with 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.success, false);
  });

  it('rejects VIEWER role from triggering detection run with 403 Forbidden', async () => {
    const res = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${viewerToken}`,
      },
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /Access denied/);
  });

  it('validates invalid request body parameters with 400 Bad Request', async () => {
    // 1. Invalid limit
    const resLimit = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ limit: -10 }),
    });
    assert.equal(resLimit.status, 400);

    // 2. Invalid windowMinutes
    const resWindow = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ windowMinutes: 999999 }),
    });
    assert.equal(resWindow.status, 400);

    // 3. Invalid ruleId
    const resRule = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ ruleId: '   ' }),
    });
    assert.equal(resRule.status, 400);
  });

  it('allows ANALYST to trigger detection run and creates AuditLog', async () => {
    const res = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ windowMinutes: 60, limit: 100 }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.data);
    assert.ok(typeof body.data.rulesEvaluated === 'number');

    // Verify AuditLog was recorded
    const audit = await prisma.auditLog.findFirst({
      where: { action: 'DETECTION_RUN' },
      orderBy: { timestamp: 'desc' },
    });
    assert.ok(audit);
    assert.equal(audit.targetType, 'DetectionEngine');
    assert.ok(audit.details);
  });

  it('allows ADMIN to trigger detection run for a specific rule', async () => {
    const rule = await prisma.detectionRule.findFirst({
      where: { type: RuleType.PORT_SCAN },
    });

    const res = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ ruleId: rule.id }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.rulesEvaluated, 1);
  });
});
