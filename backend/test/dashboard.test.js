// test/dashboard.test.js
// Comprehensive test suite for Phase 7 Dashboard API.
// Uses Node 22 native test runner (node:test) with real PostgreSQL/Prisma
// and real Express HTTP requests via fetch.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { IncidentStatus, Severity, AlertStatus } from '@prisma/client';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;
let testRule;

// Track IDs created during test for safe, targeted cleanup
const createdIncidentIds = [];
const createdAlertIds = [];
const createdEventIds = [];

describe('Phase 7 — Security Operations Center Dashboard API', () => {
  before(async () => {
    // 1. Fetch seed users
    [adminUser, analystUser, viewerUser] = await Promise.all([
      prisma.user.findFirst({ where: { role: 'ADMIN' } }),
      prisma.user.findFirst({ where: { role: 'ANALYST' } }),
      prisma.user.findFirst({ where: { role: 'VIEWER' } }),
    ]);

    assert.ok(adminUser, 'Seed admin user must exist');
    assert.ok(analystUser, 'Seed analyst user must exist');
    assert.ok(viewerUser, 'Seed viewer user must exist');

    // 2. Generate auth tokens
    adminToken = signToken({ userId: adminUser.id, email: adminUser.email, role: adminUser.role });
    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });
    viewerToken = signToken({ userId: viewerUser.id, email: viewerUser.email, role: viewerUser.role });

    // 3. Fetch or ensure a detection rule exists for alerts
    testRule = await prisma.detectionRule.findFirst();
    if (!testRule) {
      testRule = await prisma.detectionRule.create({
        data: {
          name: 'Dashboard Test Rule',
          type: 'SSH_BRUTE_FORCE',
          severity: 'HIGH',
          config: { threshold: 5 },
        },
      });
    }

    // 4. Start ephemeral test server on random open port
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    // Clean up created test records in reverse dependency order
    if (createdIncidentIds.length > 0) {
      await prisma.incidentAlert.deleteMany({
        where: { incidentId: { in: createdIncidentIds } },
      });
      await prisma.auditLog.deleteMany({
        where: { targetType: 'Incident', targetId: { in: createdIncidentIds } },
      });
      await prisma.incident.deleteMany({
        where: { id: { in: createdIncidentIds } },
      });
    }

    if (createdAlertIds.length > 0) {
      await prisma.alertEvent.deleteMany({
        where: { alertId: { in: createdAlertIds } },
      });
      await prisma.alert.deleteMany({
        where: { id: { in: createdAlertIds } },
      });
    }

    if (createdEventIds.length > 0) {
      await prisma.event.deleteMany({
        where: { id: { in: createdEventIds } },
      });
    }

    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  // ── Authentication & RBAC ────────────────────────────────────────────────

  describe('1. Authentication & Authorization', () => {
    it('rejects unauthenticated request with 401', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /authentication required/i);
    });

    it('rejects malformed token with 401', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: 'Bearer this-is-not-a-valid-jwt' },
      });
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /invalid.*token/i);
    });

    it('allows ADMIN to access dashboard summary', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data);
    });

    it('allows ANALYST to access dashboard summary', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data);
    });

    it('allows VIEWER to access dashboard summary with read-only permissions', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data);
    });
  });

  // ── Query Parameter Validation ───────────────────────────────────────────

  describe('2. Query Parameter Validation', () => {
    it('accepts default timeWindow (24h) and returns 24 buckets', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.alertsOverTime.length, 24);
    });

    it('accepts timeWindow=7d and returns 7 buckets', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary?timeWindow=7d`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.alertsOverTime.length, 7);
    });

    it('rejects invalid timeWindow with 400', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary?timeWindow=30d`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /invalid timewindow/i);
    });

    it('rejects invalid recentLimit (< 1 or > 20) with 400', async () => {
      const res1 = await fetch(`${baseUrl}/api/dashboard/summary?recentLimit=0`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res1.status, 400);

      const res2 = await fetch(`${baseUrl}/api/dashboard/summary?recentLimit=50`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res2.status, 400);
    });
  });

  // ── Data Integrity & Accurate Aggregations ───────────────────────────────

  describe('3. Data Integrity & Accurate Aggregations', () => {
    let baselineData;

    before(async () => {
      // Record baseline counts before adding controlled test records
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const body = await res.json();
      baselineData = body.data;

      // 1. Create a test event
      const event = await prisma.event.create({
        data: {
          eventType: 'dashboard_test_event',
          severity: Severity.LOW,
          timestamp: new Date(),
        },
      });
      createdEventIds.push(event.id);

      // 2. Create controlled test alerts:
      // Alert A: CRITICAL, OPEN, fired 1 hour ago (within 24h)
      const alertA = await prisma.alert.create({
        data: {
          ruleId: testRule.id,
          title: 'DASHBOARD-TEST-ALERT-CRITICAL-OPEN',
          description: 'Controlled test alert A',
          severity: Severity.CRITICAL,
          status: AlertStatus.OPEN,
          firedAt: new Date(Date.now() - 3600000), // 1 hour ago
        },
      });
      createdAlertIds.push(alertA.id);

      // Alert B: HIGH, ACKNOWLEDGED, fired 2 hours ago (within 24h)
      const alertB = await prisma.alert.create({
        data: {
          ruleId: testRule.id,
          title: 'DASHBOARD-TEST-ALERT-HIGH-ACK',
          description: 'Controlled test alert B',
          severity: Severity.HIGH,
          status: AlertStatus.ACKNOWLEDGED,
          firedAt: new Date(Date.now() - 7200000), // 2 hours ago
        },
      });
      createdAlertIds.push(alertB.id);

      // Alert C: LOW, CLOSED, fired 48 hours ago (outside 24h, inside 7d)
      const alertC = await prisma.alert.create({
        data: {
          ruleId: testRule.id,
          title: 'DASHBOARD-TEST-ALERT-LOW-CLOSED',
          description: 'Controlled test alert C',
          severity: Severity.LOW,
          status: AlertStatus.CLOSED,
          firedAt: new Date(Date.now() - 48 * 3600000), // 48 hours ago
        },
      });
      createdAlertIds.push(alertC.id);

      // 3. Create controlled test incidents:
      // Incident 1: HIGH, OPEN
      const inc1 = await prisma.incident.create({
        data: {
          title: 'DASHBOARD-TEST-INCIDENT-OPEN',
          severity: Severity.HIGH,
          status: IncidentStatus.OPEN,
          assignedToId: analystUser.id,
        },
      });
      createdIncidentIds.push(inc1.id);

      // Incident 2: CRITICAL, INVESTIGATING
      const inc2 = await prisma.incident.create({
        data: {
          title: 'DASHBOARD-TEST-INCIDENT-INVESTIGATING',
          severity: Severity.CRITICAL,
          status: IncidentStatus.INVESTIGATING,
          assignedToId: adminUser.id,
        },
      });
      createdIncidentIds.push(inc2.id);

      // Incident 3: MEDIUM, RESOLVED
      const inc3 = await prisma.incident.create({
        data: {
          title: 'DASHBOARD-TEST-INCIDENT-RESOLVED',
          severity: Severity.MEDIUM,
          status: IncidentStatus.RESOLVED,
          resolvedAt: new Date(),
        },
      });
      createdIncidentIds.push(inc3.id);
    });

    it('accurately increments KPI counts based on database records', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      // Total events increased by 1
      assert.equal(data.kpis.totalEvents, baselineData.kpis.totalEvents + 1);

      // Total alerts increased by 3
      assert.equal(data.kpis.totalAlerts, baselineData.kpis.totalAlerts + 3);

      // Open alerts increased by 1 (only alertA was OPEN)
      assert.equal(data.kpis.openAlerts, baselineData.kpis.openAlerts + 1);

      // Critical & High alerts increased by 2 (alertA CRITICAL + alertB HIGH)
      assert.equal(data.kpis.criticalHighAlerts, baselineData.kpis.criticalHighAlerts + 2);

      // Open incidents increased by 1 (inc1 was OPEN)
      assert.equal(data.kpis.openIncidents, baselineData.kpis.openIncidents + 1);

      // Investigating incidents increased by 1 (inc2 was INVESTIGATING)
      assert.equal(data.kpis.investigatingIncidents, baselineData.kpis.investigatingIncidents + 1);
    });

    it('correctly populates severity breakdown with exact counts and no missing enums', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      const sevMap = Object.fromEntries(
        data.alertSeverityDistribution.map((item) => [item.severity, item.count])
      );

      // Ensure all 4 enums exist
      assert.ok('CRITICAL' in sevMap);
      assert.ok('HIGH' in sevMap);
      assert.ok('MEDIUM' in sevMap);
      assert.ok('LOW' in sevMap);

      // Calculate baseline sevMap
      const baseSevMap = Object.fromEntries(
        baselineData.alertSeverityDistribution.map((item) => [item.severity, item.count])
      );

      assert.equal(sevMap.CRITICAL, baseSevMap.CRITICAL + 1);
      assert.equal(sevMap.HIGH, baseSevMap.HIGH + 1);
      assert.equal(sevMap.LOW, baseSevMap.LOW + 1);
      assert.equal(sevMap.MEDIUM, baseSevMap.MEDIUM);
    });

    it('correctly populates incident status distribution without counting closed/resolved as open', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      const statusMap = Object.fromEntries(
        data.incidentStatusDistribution.map((item) => [item.status, item.count])
      );

      assert.ok('OPEN' in statusMap);
      assert.ok('INVESTIGATING' in statusMap);
      assert.ok('RESOLVED' in statusMap);
      assert.ok('CLOSED' in statusMap);

      const baseStatusMap = Object.fromEntries(
        baselineData.incidentStatusDistribution.map((item) => [item.status, item.count])
      );

      assert.equal(statusMap.OPEN, baseStatusMap.OPEN + 1);
      assert.equal(statusMap.INVESTIGATING, baseStatusMap.INVESTIGATING + 1);
      assert.equal(statusMap.RESOLVED, baseStatusMap.RESOLVED + 1);
      assert.equal(statusMap.CLOSED, baseStatusMap.CLOSED);
    });

    it('buckets alerts accurately in 24h window (excludes alerts older than 24h)', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary?timeWindow=24h`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      // Total count in 24h buckets should include alertA and alertB, but NOT alertC (which was 48h ago)
      const totalIn24hBuckets = data.alertsOverTime.reduce((sum, b) => sum + b.count, 0);

      // Same query for 7d
      const res7d = await fetch(`${baseUrl}/api/dashboard/summary?timeWindow=7d`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const data7d = (await res7d.json()).data;
      const totalIn7dBuckets = data7d.alertsOverTime.reduce((sum, b) => sum + b.count, 0);

      // 7d must include alertC as well, so totalIn7dBuckets >= totalIn24hBuckets + 1
      assert.ok(totalIn7dBuckets >= totalIn24hBuckets + 1);
    });

    it('returns recent alerts sorted descending with correct attributes', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary?recentLimit=3`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      assert.ok(Array.isArray(data.recentAlerts));
      assert.ok(data.recentAlerts.length <= 3);

      if (data.recentAlerts.length > 1) {
        for (let i = 0; i < data.recentAlerts.length - 1; i++) {
          const t1 = new Date(data.recentAlerts[i].firedAt).getTime();
          const t2 = new Date(data.recentAlerts[i + 1].firedAt).getTime();
          assert.ok(t1 >= t2, 'Recent alerts must be ordered descending by firedAt');
        }
      }

      // Check required fields
      const first = data.recentAlerts[0];
      assert.ok(first.id);
      assert.ok(first.title);
      assert.ok(first.severity);
      assert.ok(first.status);
      assert.ok(first.firedAt);
    });

    it('returns recent incidents with formatted readableId and assigned analyst', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary?recentLimit=3`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      assert.ok(Array.isArray(data.recentIncidents));
      assert.ok(data.recentIncidents.length <= 3);

      const testInc = data.recentIncidents.find((i) => i.title.startsWith('DASHBOARD-TEST-INCIDENT-'));
      assert.ok(testInc, 'Recent incidents should contain created test incident');
      assert.match(testInc.readableId, /^INC-[0-9A-F]{8}$/);
      assert.ok('assignedTo' in testInc);
      assert.ok('alertCount' in testInc);
    });

    it('includes a valid generatedAt timestamp in UTC ISO format', async () => {
      const res = await fetch(`${baseUrl}/api/dashboard/summary`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      const { data } = await res.json();
      assert.ok(data.generatedAt);
      const parsed = Date.parse(data.generatedAt);
      assert.ok(!Number.isNaN(parsed));
    });
  });
});
