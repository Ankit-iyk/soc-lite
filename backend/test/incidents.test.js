// test/incidents.test.js
// Comprehensive integration test suite for Phase 6 Incident Tracking API.
// Uses Node 22 native test runner (node:test) against the real PostgreSQL
// database via Prisma and actual HTTP requests via Express.
//
// Coverage:
//   1. Authentication and authorization (401/403 for all endpoints)
//   2. Incident CRUD with filtering, search, pagination, stats
//   3. Alert linking and unlinking (idempotency, duplicates, concurrency)
//   4. Status lifecycle (resolvedAt semantics, audit actions, transition policy)
//   5. Investigation notes via AuditLog (persistence, timeline order)
//   6. Atomic transactions and optimistic concurrency (409 conflict detection)

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { IncidentStatus, Severity, AlertStatus } from '@prisma/client';

// ── Module-level state ─────────────────────────────────────────────────────

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;
let testRule;

// Track created IDs for targeted cleanup (avoids wiping shared seed data)
const createdIncidentIds = [];
const createdAlertIds = [];

// ── Test helpers ───────────────────────────────────────────────────────────

async function createIncidentDirect(overrides = {}) {
  const inc = await prisma.incident.create({
    data: {
      title: overrides.title || `Test Incident ${Date.now()}_${Math.random().toString(36).slice(7)}`,
      description: overrides.description || null,
      severity: overrides.severity || Severity.MEDIUM,
      status: overrides.status || IncidentStatus.OPEN,
      assignedToId: overrides.assignedToId || null,
      resolvedAt: overrides.resolvedAt || null,
    },
  });
  createdIncidentIds.push(inc.id);
  return inc;
}

async function createAlertDirect(overrides = {}) {
  const alert = await prisma.alert.create({
    data: {
      ruleId: overrides.ruleId !== undefined ? overrides.ruleId : testRule.id,
      title: overrides.title || `Test Alert ${Date.now()}_${Math.random().toString(36).slice(7)}`,
      description: overrides.description || 'Integration test alert',
      severity: overrides.severity || Severity.MEDIUM,
      status: overrides.status || AlertStatus.OPEN,
      firedAt: overrides.firedAt || new Date(),
    },
  });
  createdAlertIds.push(alert.id);
  return alert;
}

async function linkIncidentAlert(incidentId, alertId) {
  return prisma.incidentAlert.create({ data: { incidentId, alertId } });
}

function post(url, body, token) {
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

function patch(url, body, token) {
  return fetch(url, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
}

function del(url, token) {
  return fetch(url, {
    method: 'DELETE',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

function get(url, token) {
  return fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
}

// ── Suite ──────────────────────────────────────────────────────────────────

describe('Phase 6 — Incident Tracking Integration Tests', () => {
  // ── Lifecycle ────────────────────────────────────────────────────────────

  before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        baseUrl = `http://localhost:${server.address().port}`;
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
    assert.ok(testRule, 'At least one detection rule must be seeded');
  });

  after(async () => {
    // Remove test incidents and their relationships and audit entries
    if (createdIncidentIds.length > 0) {
      await prisma.incidentAlert.deleteMany({ where: { incidentId: { in: createdIncidentIds } } });
      await prisma.auditLog.deleteMany({ where: { targetType: 'Incident', targetId: { in: createdIncidentIds } } });
      await prisma.incident.deleteMany({ where: { id: { in: createdIncidentIds } } });
    }
    // Remove test alerts (after removing incidentAlert links above)
    if (createdAlertIds.length > 0) {
      await prisma.incidentAlert.deleteMany({ where: { alertId: { in: createdAlertIds } } });
      await prisma.alertEvent.deleteMany({ where: { alertId: { in: createdAlertIds } } });
      await prisma.alert.deleteMany({ where: { id: { in: createdAlertIds } } });
    }
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  // ── 1. Authentication & Authorization ────────────────────────────────────

  describe('1. Authentication and Authorization', () => {
    it('returns 401 for unauthenticated GET /api/incidents', async () => {
      const res = await get(`${baseUrl}/api/incidents`);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.equal(body.success, false);
    });

    it('returns 401 for unauthenticated GET /api/incidents/stats', async () => {
      const res = await get(`${baseUrl}/api/incidents/stats`);
      assert.equal(res.status, 401);
    });

    it('returns 401 for unauthenticated GET /api/incidents/:id', async () => {
      const res = await get(`${baseUrl}/api/incidents/00000000-0000-0000-0000-000000000000`);
      assert.equal(res.status, 401);
    });

    it('returns 401 for unauthenticated POST /api/incidents', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: 'unauth' });
      assert.equal(res.status, 401);
    });

    it('returns 401 for unauthenticated PATCH /api/incidents/:id', async () => {
      const res = await patch(`${baseUrl}/api/incidents/00000000-0000-0000-0000-000000000000`, { title: 'x' });
      assert.equal(res.status, 401);
    });

    it('returns 401 for unauthenticated POST /api/incidents/:id/alerts', async () => {
      const res = await post(`${baseUrl}/api/incidents/00000000-0000-0000-0000-000000000000/alerts`, { alertIds: [] });
      assert.equal(res.status, 401);
    });

    it('returns 401 for unauthenticated DELETE /api/incidents/:id/alerts/:alertId', async () => {
      const res = await del(
        `${baseUrl}/api/incidents/00000000-0000-0000-0000-000000000000/alerts/00000000-0000-0000-0000-000000000001`,
      );
      assert.equal(res.status, 401);
    });

    it('returns 401 for unauthenticated POST /api/incidents/:id/notes', async () => {
      const res = await post(`${baseUrl}/api/incidents/00000000-0000-0000-0000-000000000000/notes`, { note: 'hi' });
      assert.equal(res.status, 401);
    });

    it('allows VIEWER to read incident list', async () => {
      const res = await get(`${baseUrl}/api/incidents`, viewerToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
    });

    it('allows VIEWER to read incident stats', async () => {
      const res = await get(`${baseUrl}/api/incidents/stats`, viewerToken);
      assert.equal(res.status, 200);
    });

    it('allows VIEWER to read incident details', async () => {
      const inc = await createIncidentDirect({ title: 'VIEWER Read Test' });
      const res = await get(`${baseUrl}/api/incidents/${inc.id}`, viewerToken);
      assert.equal(res.status, 200);
    });

    it('returns 403 when VIEWER attempts to create an incident', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: 'Viewer Create Attempt' }, viewerToken);
      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('Access denied'));
    });

    it('returns 403 when VIEWER attempts to update an incident', async () => {
      const inc = await createIncidentDirect({ title: 'VIEWER Update Test' });
      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { title: 'Altered' }, viewerToken);
      assert.equal(res.status, 403);
    });

    it('returns 403 when VIEWER attempts to link alerts', async () => {
      const inc = await createIncidentDirect({ title: 'VIEWER Link Test' });
      const alert = await createAlertDirect();
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [alert.id] }, viewerToken);
      assert.equal(res.status, 403);
    });

    it('returns 403 when VIEWER attempts to unlink an alert', async () => {
      const inc = await createIncidentDirect({ title: 'VIEWER Unlink Test' });
      const alert = await createAlertDirect();
      await linkIncidentAlert(inc.id, alert.id);
      const res = await del(`${baseUrl}/api/incidents/${inc.id}/alerts/${alert.id}`, viewerToken);
      assert.equal(res.status, 403);
    });

    it('returns 403 when VIEWER attempts to add a note', async () => {
      const inc = await createIncidentDirect({ title: 'VIEWER Note Test' });
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { note: 'secret note' }, viewerToken);
      assert.equal(res.status, 403);
    });

    it('allows ANALYST to create an incident', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: 'ANALYST Created Incident' }, analystToken);
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.success, true);
      if (body.data?.id) createdIncidentIds.push(body.data.id);
    });
  });

  // ── 2. Incident Creation ──────────────────────────────────────────────────

  describe('2. Incident Creation (POST /api/incidents)', () => {
    it('creates an incident with only required title and returns 201 with defaults', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: 'Minimal Incident' }, analystToken);
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data.id);
      assert.equal(body.data.title, 'Minimal Incident');
      assert.equal(body.data.status, 'OPEN');
      assert.equal(body.data.severity, 'MEDIUM');
      assert.equal(body.data.assignedTo, null);
      assert.equal(body.data.resolvedAt, null);
      assert.ok(body.data.readableId.startsWith('INC-'));
      createdIncidentIds.push(body.data.id);
    });

    it('creates an incident with all optional fields', async () => {
      const res = await post(
        `${baseUrl}/api/incidents`,
        {
          title: 'Full Incident',
          description: 'A detailed description',
          severity: 'HIGH',
          status: 'INVESTIGATING',
          assignedToId: analystUser.id,
        },
        adminToken,
      );
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.data.severity, 'HIGH');
      assert.equal(body.data.status, 'INVESTIGATING');
      assert.equal(body.data.assignedTo.id, analystUser.id);
      createdIncidentIds.push(body.data.id);
    });

    it('creates an incident with initial alertIds and links them atomically', async () => {
      const alert1 = await createAlertDirect({ title: 'Init Link Alert 1' });
      const alert2 = await createAlertDirect({ title: 'Init Link Alert 2' });

      const res = await post(
        `${baseUrl}/api/incidents`,
        { title: 'Incident With Initial Alerts', alertIds: [alert1.id, alert2.id] },
        analystToken,
      );
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.data.alertCount, 2);
      createdIncidentIds.push(body.data.id);

      // Verify links actually exist in DB
      const links = await prisma.incidentAlert.count({ where: { incidentId: body.data.id } });
      assert.equal(links, 2);
    });

    it('returns 400 for empty title', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: '' }, analystToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('title'));
    });

    it('returns 400 for missing title', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { description: 'No title here' }, analystToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
    });

    it('returns 400 for unsupported payload fields', async () => {
      const res = await post(
        `${baseUrl}/api/incidents`,
        { title: 'T', id: 'injected-uuid', createdAt: new Date().toISOString() },
        analystToken,
      );
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('Unsupported'));
    });

    it('returns 400 for invalid severity value', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: 'Bad Sev', severity: 'EXTREME' }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for invalid status value', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: 'Bad Status', status: 'DELETED' }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 when assignedToId does not correspond to an existing user', async () => {
      const res = await post(
        `${baseUrl}/api/incidents`,
        { title: 'Bad Assignee', assignedToId: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa' },
        adminToken,
      );
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('not found'));
    });

    it('returns 400 when alertIds contains a non-existent alert UUID', async () => {
      const res = await post(
        `${baseUrl}/api/incidents`,
        { title: 'Bad Alert Refs', alertIds: ['bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb'] },
        analystToken,
      );
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('do not exist'));
    });

    it('returns 400 for malformed UUID in alertIds array', async () => {
      const res = await post(`${baseUrl}/api/incidents`, { title: 'T', alertIds: ['not-a-uuid'] }, analystToken);
      assert.equal(res.status, 400);
    });

    it('rejects client-supplied id field in create payload', async () => {
      const res = await post(
        `${baseUrl}/api/incidents`,
        { title: 'ID Inject Test', id: 'cccccccc-cccc-4ccc-cccc-cccccccccccc' },
        adminToken,
      );
      assert.equal(res.status, 400);
    });

    it('sets resolvedAt when creating with initial status RESOLVED', async () => {
      const res = await post(
        `${baseUrl}/api/incidents`,
        { title: 'Resolved On Create', status: 'RESOLVED' },
        adminToken,
      );
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.ok(body.data.resolvedAt, 'resolvedAt must be set when initial status is RESOLVED');
      createdIncidentIds.push(body.data.id);
    });
  });

  // ── 3. Incident Listing & Filtering ──────────────────────────────────────

  describe('3. Incident Listing and Filtering (GET /api/incidents)', () => {
    it('returns paginated results with correct structure', async () => {
      const res = await get(`${baseUrl}/api/incidents?page=1&limit=5`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(Array.isArray(body.data));
      assert.ok(body.data.length <= 5);
      assert.equal(body.pagination.page, 1);
      assert.equal(body.pagination.limit, 5);
      assert.ok(typeof body.pagination.total === 'number');
      assert.ok(typeof body.pagination.totalPages === 'number');
    });

    it('filters by status', async () => {
      const open = await createIncidentDirect({ title: 'StatusFilter OPEN Inc', status: IncidentStatus.OPEN });
      await createIncidentDirect({ title: 'StatusFilter INV Inc', status: IncidentStatus.INVESTIGATING });

      const res = await get(`${baseUrl}/api/incidents?search=StatusFilter+OPEN+Inc&status=OPEN`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.length, 1);
      assert.equal(body.data[0].id, open.id);
    });

    it('filters by severity', async () => {
      const crit = await createIncidentDirect({ title: 'SevFilter CRIT Inc', severity: Severity.CRITICAL });
      await createIncidentDirect({ title: 'SevFilter LOW Inc', severity: Severity.LOW });

      const res = await get(`${baseUrl}/api/incidents?search=SevFilter+CRIT+Inc&severity=CRITICAL`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.length, 1);
      assert.equal(body.data[0].id, crit.id);
    });

    it('filters by assignedToId', async () => {
      const assigned = await createIncidentDirect({
        title: 'AssigneeFilter Inc Assigned',
        assignedToId: analystUser.id,
      });
      await createIncidentDirect({ title: 'AssigneeFilter Inc Unassigned' });

      const res = await get(
        `${baseUrl}/api/incidents?search=AssigneeFilter+Inc&assignedToId=${analystUser.id}`,
        analystToken,
      );
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.length, 1);
      assert.equal(body.data[0].id, assigned.id);
    });

    it('searches across title and description case-insensitively', async () => {
      const t = `SearchKw_${Date.now()}`;
      const byTitle = await createIncidentDirect({ title: `${t} in title`, description: 'unrelated' });
      const byDesc = await createIncidentDirect({ title: 'Generic Inc', description: `something ${t} in desc` });

      const res = await get(`${baseUrl}/api/incidents?search=${t}`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.ok(body.data.some((i) => i.id === byTitle.id));
      assert.ok(body.data.some((i) => i.id === byDesc.id));
    });

    it('returns empty array when no incidents match', async () => {
      const res = await get(`${baseUrl}/api/incidents?search=NonExistentKwXYZ999`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.deepEqual(body.data, []);
      assert.equal(body.pagination.total, 0);
    });

    it('returns 400 for invalid pagination (page=0)', async () => {
      const res = await get(`${baseUrl}/api/incidents?page=0`, analystToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('page'));
    });

    it('returns 400 for limit exceeding max (limit=101)', async () => {
      const res = await get(`${baseUrl}/api/incidents?limit=101`, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for invalid status filter', async () => {
      const res = await get(`${baseUrl}/api/incidents?status=UNKNOWN`, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for invalid severity filter', async () => {
      const res = await get(`${baseUrl}/api/incidents?severity=EXTREME`, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for non-UUID assignedToId filter', async () => {
      const res = await get(`${baseUrl}/api/incidents?assignedToId=not-a-uuid`, analystToken);
      assert.equal(res.status, 400);
    });

    it('filters by startDate and endDate (date range)', async () => {
      const kw = `DateRange_${Date.now()}`;
      const insideInc = await prisma.incident.create({
        data: {
          title: `${kw} inside`,
          severity: Severity.MEDIUM,
          status: IncidentStatus.OPEN,
          createdAt: new Date('2025-06-15T12:00:00.000Z'),
        },
      });
      const beforeInc = await prisma.incident.create({
        data: {
          title: `${kw} before`,
          severity: Severity.MEDIUM,
          status: IncidentStatus.OPEN,
          createdAt: new Date('2025-06-10T12:00:00.000Z'),
        },
      });
      const afterInc = await prisma.incident.create({
        data: {
          title: `${kw} after`,
          severity: Severity.MEDIUM,
          status: IncidentStatus.OPEN,
          createdAt: new Date('2025-06-20T12:00:00.000Z'),
        },
      });
      createdIncidentIds.push(insideInc.id, beforeInc.id, afterInc.id);

      const res = await get(
        `${baseUrl}/api/incidents?search=${kw}&startDate=2025-06-14T00:00:00.000Z&endDate=2025-06-16T00:00:00.000Z`,
        analystToken,
      );
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.length, 1);
      assert.equal(body.data[0].id, insideInc.id);
    });

    it('response includes alertCount and assignedTo fields', async () => {
      const inc = await createIncidentDirect({ title: 'Includes Fields Inc', assignedToId: adminUser.id });
      const alert = await createAlertDirect();
      await linkIncidentAlert(inc.id, alert.id);

      const res = await get(`${baseUrl}/api/incidents?search=Includes+Fields+Inc`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      const found = body.data.find((i) => i.id === inc.id);
      assert.ok(found, 'Created incident must appear in list');
      assert.equal(found.alertCount, 1);
      assert.ok(found.assignedTo);
      assert.equal(found.assignedTo.id, adminUser.id);
    });
  });

  // ── 4. Statistics ─────────────────────────────────────────────────────────

  describe('4. Incident Statistics (GET /api/incidents/stats)', () => {
    it('returns stats with byStatus and bySeverity breakdowns', async () => {
      const res = await get(`${baseUrl}/api/incidents/stats`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      const { total, byStatus, bySeverity } = body.data;

      assert.ok(typeof total === 'number');
      for (const k of ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED']) {
        assert.ok(k in byStatus, `byStatus must contain key ${k}`);
      }
      for (const k of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
        assert.ok(k in bySeverity, `bySeverity must contain key ${k}`);
      }
    });

    it('stats total equals sum of byStatus and sum of bySeverity', async () => {
      const res = await get(`${baseUrl}/api/incidents/stats`, analystToken);
      const { total, byStatus, bySeverity } = (await res.json()).data;

      const statusSum = Object.values(byStatus).reduce((a, b) => a + b, 0);
      const severitySum = Object.values(bySeverity).reduce((a, b) => a + b, 0);
      assert.equal(total, statusSum, 'Total must equal sum of status counts');
      assert.equal(total, severitySum, 'Total must equal sum of severity counts');
    });

    it('stats total matches real PostgreSQL count', async () => {
      const res = await get(`${baseUrl}/api/incidents/stats`, analystToken);
      const { total } = (await res.json()).data;
      const realCount = await prisma.incident.count();
      assert.equal(total, realCount);
    });

    it('all enum keys are initialized to numbers (not undefined)', async () => {
      const res = await get(`${baseUrl}/api/incidents/stats`, analystToken);
      const { byStatus, bySeverity } = (await res.json()).data;
      for (const key of ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED']) {
        assert.equal(typeof byStatus[key], 'number', `byStatus.${key} must be a number`);
      }
      for (const key of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
        assert.equal(typeof bySeverity[key], 'number', `bySeverity.${key} must be a number`);
      }
    });
  });

  // ── 5. Incident Detail ────────────────────────────────────────────────────

  describe('5. Incident Detail (GET /api/incidents/:id)', () => {
    it('returns full incident with assignedTo and empty alerts/timeline when none exist', async () => {
      const inc = await createIncidentDirect({ title: 'Detail Test No Links', assignedToId: analystUser.id });

      const res = await get(`${baseUrl}/api/incidents/${inc.id}`, adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.id, inc.id);
      assert.ok(body.data.readableId.startsWith('INC-'));
      assert.equal(body.data.assignedTo.id, analystUser.id);
      assert.deepEqual(body.data.alerts, []);
      assert.deepEqual(body.data.timeline, []);
      assert.equal(body.data.alertCount, 0);
    });

    it('returns linked alerts with detection rule information', async () => {
      const inc = await createIncidentDirect({ title: 'Detail With Alerts' });
      const alert = await createAlertDirect({ title: 'Linked Detail Alert' });
      await linkIncidentAlert(inc.id, alert.id);

      const res = await get(`${baseUrl}/api/incidents/${inc.id}`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.alertCount, 1);
      assert.equal(body.data.alerts.length, 1);

      const linkedAlert = body.data.alerts[0];
      assert.equal(linkedAlert.id, alert.id);
      assert.ok(linkedAlert.rule, 'Linked alert must expose its detection rule');
      assert.equal(linkedAlert.rule.id, testRule.id);
    });

    it('returns 400 for a malformed (non-UUID) incident ID', async () => {
      const res = await get(`${baseUrl}/api/incidents/not-a-uuid`, analystToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('UUID'));
    });

    it('returns 404 for a well-formed UUID that does not exist', async () => {
      const res = await get(`${baseUrl}/api/incidents/ffffffff-ffff-4fff-bfff-ffffffffffff`, analystToken);
      assert.equal(res.status, 404);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.ok(body.error.includes('not found'));
    });
  });

  // ── 6. Incident Update ────────────────────────────────────────────────────

  describe('6. Incident Update (PATCH /api/incidents/:id)', () => {
    it('updates title and description, returns updated incident', async () => {
      const inc = await createIncidentDirect({ title: 'Update Title Original' });

      const res = await patch(
        `${baseUrl}/api/incidents/${inc.id}`,
        { title: 'Update Title Changed', description: 'Now has a description' },
        adminToken,
      );
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.title, 'Update Title Changed');
      assert.equal(body.data.description, 'Now has a description');
    });

    it('returns 400 for empty update body', async () => {
      const inc = await createIncidentDirect({ title: 'Empty Update Test' });
      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, {}, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for unsupported fields in update body', async () => {
      const inc = await createIncidentDirect({ title: 'Bad Fields Update' });
      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { title: 'OK', id: 'injected' }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for a malformed incident ID in path', async () => {
      const res = await patch(`${baseUrl}/api/incidents/not-uuid`, { title: 'x' }, adminToken);
      assert.equal(res.status, 400);
    });

    it('returns 404 for a non-existent incident UUID', async () => {
      const res = await patch(
        `${baseUrl}/api/incidents/eeeeeeee-eeee-4eee-aeee-eeeeeeeeeeee`,
        { title: 'Ghost' },
        adminToken,
      );
      assert.equal(res.status, 404);
    });

    it('returns 400 when assignedToId does not exist', async () => {
      const inc = await createIncidentDirect({ title: 'Update Bad Assignee' });
      const res = await patch(
        `${baseUrl}/api/incidents/${inc.id}`,
        { assignedToId: 'dddddddd-dddd-4ddd-addd-dddddddddddd' },
        adminToken,
      );
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('not found'));
    });

    it('allows clearing assignedToId to null', async () => {
      const inc = await createIncidentDirect({ title: 'Clear Assignee', assignedToId: adminUser.id });
      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { assignedToId: null }, adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.assignedToId, null);
      assert.equal(body.data.assignedTo, null);
    });

    it('creates an INCIDENT_UPDATE audit log entry', async () => {
      const inc = await createIncidentDirect({ title: 'Audit Update Check' });
      await patch(`${baseUrl}/api/incidents/${inc.id}`, { description: 'Updated desc' }, analystToken);

      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Incident', targetId: inc.id, action: 'INCIDENT_UPDATE' },
      });
      assert.ok(audit, 'INCIDENT_UPDATE audit record must exist');
      assert.equal(audit.userId, analystUser.id);
      assert.ok('description' in audit.details.previous);
    });
  });

  // ── 7. Status Lifecycle ───────────────────────────────────────────────────

  describe('7. Status Lifecycle and resolvedAt Semantics', () => {
    it('transitions OPEN to INVESTIGATING and creates INCIDENT_STATUS_CHANGE audit', async () => {
      const inc = await createIncidentDirect({ title: 'Lifecycle OPEN to INV' });

      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { status: 'INVESTIGATING' }, analystToken);
      assert.equal(res.status, 200);
      assert.equal((await res.json()).data.status, 'INVESTIGATING');

      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Incident', targetId: inc.id, action: 'INCIDENT_STATUS_CHANGE' },
      });
      assert.ok(audit);
      assert.equal(audit.details.previous.status, 'OPEN');
      assert.equal(audit.details.updated.status, 'INVESTIGATING');
    });

    it('transitions OPEN to RESOLVED and sets resolvedAt', async () => {
      const inc = await createIncidentDirect({ title: 'Lifecycle OPEN to RESOLVED' });
      const beforeMs = Date.now();

      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { status: 'RESOLVED' }, adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.status, 'RESOLVED');
      assert.ok(body.data.resolvedAt, 'resolvedAt must be set when transitioning to RESOLVED');
      const resolvedMs = new Date(body.data.resolvedAt).getTime();
      assert.ok(resolvedMs >= beforeMs - 5000 && resolvedMs <= Date.now() + 5000);
    });

    it('transitions RESOLVED to CLOSED and preserves resolvedAt', async () => {
      const resolvedAt = new Date('2025-01-10T10:00:00.000Z');
      const inc = await prisma.incident.create({
        data: {
          title: 'Lifecycle RESOLVED to CLOSED',
          severity: Severity.HIGH,
          status: IncidentStatus.RESOLVED,
          resolvedAt,
        },
      });
      createdIncidentIds.push(inc.id);

      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { status: 'CLOSED' }, adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.status, 'CLOSED');
      assert.ok(body.data.resolvedAt, 'resolvedAt must be preserved when transitioning RESOLVED to CLOSED');
      assert.equal(new Date(body.data.resolvedAt).getTime(), resolvedAt.getTime());
    });

    it('reopening RESOLVED to OPEN clears resolvedAt', async () => {
      const inc = await prisma.incident.create({
        data: {
          title: 'Lifecycle RESOLVED to OPEN',
          severity: Severity.MEDIUM,
          status: IncidentStatus.RESOLVED,
          resolvedAt: new Date(),
        },
      });
      createdIncidentIds.push(inc.id);

      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { status: 'OPEN' }, adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.status, 'OPEN');
      assert.equal(body.data.resolvedAt, null, 'resolvedAt must be cleared when reopening to OPEN');
    });

    it('reopening RESOLVED to INVESTIGATING clears resolvedAt', async () => {
      const inc = await prisma.incident.create({
        data: {
          title: 'Lifecycle RESOLVED to INV',
          severity: Severity.MEDIUM,
          status: IncidentStatus.RESOLVED,
          resolvedAt: new Date(),
        },
      });
      createdIncidentIds.push(inc.id);

      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { status: 'INVESTIGATING' }, adminToken);
      assert.equal(res.status, 200);
      assert.equal(
        (await res.json()).data.resolvedAt,
        null,
        'resolvedAt must be cleared on reopen to INVESTIGATING',
      );
    });

    it('returns 400 for an invalid status value in update', async () => {
      const inc = await createIncidentDirect({ title: 'Bad Status Update' });
      const res = await patch(`${baseUrl}/api/incidents/${inc.id}`, { status: 'NONSENSE' }, adminToken);
      assert.equal(res.status, 400);
    });
  });

  // ── 8. Alert Linking ──────────────────────────────────────────────────────

  describe('8. Alert Linking (POST /api/incidents/:id/alerts)', () => {
    it('links a single alert to an incident and records INCIDENT_ALERT_LINK audit', async () => {
      const inc = await createIncidentDirect({ title: 'Link Single Alert' });
      const alert = await createAlertDirect({ title: 'Alert To Link' });

      const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [alert.id] }, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.deepEqual(body.data.newlyLinkedAlertIds, [alert.id]);
      assert.equal(body.data.totalAlerts, 1);

      // Verify DB link
      const link = await prisma.incidentAlert.findUnique({
        where: { incidentId_alertId: { incidentId: inc.id, alertId: alert.id } },
      });
      assert.ok(link, 'IncidentAlert record must exist in DB');

      // Verify audit
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Incident', targetId: inc.id, action: 'INCIDENT_ALERT_LINK' },
      });
      assert.ok(audit);
      assert.equal(audit.userId, analystUser.id);
      assert.ok(audit.details.newlyLinkedAlertIds.includes(alert.id));
    });

    it('accepts single alertId string as well as alertIds array', async () => {
      const inc = await createIncidentDirect({ title: 'Link Via alertId String' });
      const alert = await createAlertDirect();

      const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertId: alert.id }, adminToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.data.newlyLinkedAlertIds.length, 1);
    });

    it('linking an already-linked alert returns 200 no-op without creating duplicate DB record', async () => {
      const inc = await createIncidentDirect({ title: 'Duplicate Link Test' });
      const alert = await createAlertDirect();

      // First link
      await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [alert.id] }, analystToken);

      // Second link (same alert)
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [alert.id] }, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.ok(body.message.includes('already linked'));

      // Verify no duplicate in DB
      const count = await prisma.incidentAlert.count({ where: { incidentId: inc.id, alertId: alert.id } });
      assert.equal(count, 1, 'Exactly one IncidentAlert record must exist (no duplicates)');
    });

    it('linking a mix of new and already-linked alerts only adds the new ones', async () => {
      const inc = await createIncidentDirect({ title: 'Mixed Link Test' });
      const a1 = await createAlertDirect();
      const a2 = await createAlertDirect();

      // Link a1 first
      await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [a1.id] }, analystToken);

      // Link both (a1 already linked, a2 is new)
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [a1.id, a2.id] }, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.deepEqual(body.data.newlyLinkedAlertIds, [a2.id]);
      assert.equal(body.data.totalAlerts, 2);
    });

    it('returns 404 for a non-existent incident UUID', async () => {
      const alert = await createAlertDirect();
      const res = await post(
        `${baseUrl}/api/incidents/ffffffff-ffff-4fff-bfff-000000000001/alerts`,
        { alertIds: [alert.id] },
        adminToken,
      );
      assert.equal(res.status, 404);
    });

    it('returns 400 for a non-existent alert UUID in alertIds', async () => {
      const inc = await createIncidentDirect({ title: 'Link Non-Existent Alert' });
      const res = await post(
        `${baseUrl}/api/incidents/${inc.id}/alerts`,
        { alertIds: ['aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaab'] },
        adminToken,
      );
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('do not exist'));
    });

    it('returns 400 for empty alertIds array', async () => {
      const inc = await createIncidentDirect({ title: 'Link Empty Array' });
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [] }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for malformed UUID in alertIds', async () => {
      const inc = await createIncidentDirect({ title: 'Link Malformed UUID' });
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: ['not-a-uuid'] }, adminToken);
      assert.equal(res.status, 400);
    });
  });

  // ── 9. Alert Unlinking ────────────────────────────────────────────────────

  describe('9. Alert Unlinking (DELETE /api/incidents/:id/alerts/:alertId)', () => {
    it('unlinks a linked alert, returns 200, records INCIDENT_ALERT_UNLINK audit', async () => {
      const inc = await createIncidentDirect({ title: 'Unlink Alert Test' });
      const alert = await createAlertDirect();
      await linkIncidentAlert(inc.id, alert.id);

      const res = await del(`${baseUrl}/api/incidents/${inc.id}/alerts/${alert.id}`, analystToken);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.unlinkedAlertId, alert.id);
      assert.equal(body.data.remainingAlertCount, 0);

      // Verify DB row removed
      const link = await prisma.incidentAlert.findUnique({
        where: { incidentId_alertId: { incidentId: inc.id, alertId: alert.id } },
      });
      assert.equal(link, null, 'IncidentAlert record must be deleted');

      // Verify audit
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Incident', targetId: inc.id, action: 'INCIDENT_ALERT_UNLINK' },
      });
      assert.ok(audit);
      assert.equal(audit.details.unlinkedAlertId, alert.id);
    });

    it('returns 404 if the alert is not linked to the incident', async () => {
      const inc = await createIncidentDirect({ title: 'Unlink Non-Linked' });
      const alert = await createAlertDirect();

      const res = await del(`${baseUrl}/api/incidents/${inc.id}/alerts/${alert.id}`, adminToken);
      assert.equal(res.status, 404);
      const body = await res.json();
      assert.ok(body.error.includes('not linked'));
    });

    it('returns 404 for a non-existent incident UUID', async () => {
      const alert = await createAlertDirect();
      const res = await del(
        `${baseUrl}/api/incidents/ffffffff-ffff-4fff-bfff-000000000002/alerts/${alert.id}`,
        adminToken,
      );
      assert.equal(res.status, 404);
    });

    it('returns 400 for a malformed incident ID in path', async () => {
      const alert = await createAlertDirect();
      const res = await del(`${baseUrl}/api/incidents/not-uuid/alerts/${alert.id}`, adminToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for a malformed alertId in path', async () => {
      const inc = await createIncidentDirect({ title: 'Unlink Bad alertId' });
      const res = await del(`${baseUrl}/api/incidents/${inc.id}/alerts/not-a-uuid`, adminToken);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.ok(body.error.includes('UUID'));
    });

    it('remainingAlertCount is accurate after unlinking one of two alerts', async () => {
      const inc = await createIncidentDirect({ title: 'Unlink Count Check' });
      const a1 = await createAlertDirect();
      const a2 = await createAlertDirect();
      await linkIncidentAlert(inc.id, a1.id);
      await linkIncidentAlert(inc.id, a2.id);

      const res = await del(`${baseUrl}/api/incidents/${inc.id}/alerts/${a1.id}`, analystToken);
      assert.equal(res.status, 200);
      assert.equal((await res.json()).data.remainingAlertCount, 1);
    });
  });

  // ── 10. Investigation Notes ───────────────────────────────────────────────

  describe('10. Investigation Notes (POST /api/incidents/:id/notes)', () => {
    it('adds a note, returns 201 with author attribution from authenticated user', async () => {
      const inc = await createIncidentDirect({ title: 'Notes Attribution Test' });

      const res = await post(
        `${baseUrl}/api/incidents/${inc.id}/notes`,
        { note: 'Investigated source IP.' },
        analystToken,
      );
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.note, 'Investigated source IP.');
      assert.equal(body.data.author.id, analystUser.id);
      assert.equal(body.data.author.name, analystUser.name);
      assert.equal(body.data.author.role, 'ANALYST');
      assert.ok(body.data.id, 'Note must have an AuditLog ID');
      assert.ok(body.data.timestamp);
    });

    it('persists note in AuditLog with INCIDENT_NOTE_ADD action', async () => {
      const inc = await createIncidentDirect({ title: 'Notes DB Persistence' });
      await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { note: 'Confirmed lateral movement.' }, adminToken);

      const auditEntry = await prisma.auditLog.findFirst({
        where: { targetType: 'Incident', targetId: inc.id, action: 'INCIDENT_NOTE_ADD' },
      });
      assert.ok(auditEntry, 'AuditLog entry must exist for note');
      assert.equal(auditEntry.userId, adminUser.id);
      assert.equal(auditEntry.details.note, 'Confirmed lateral movement.');
    });

    it('notes appear in GET /api/incidents/:id timeline ordered newest-first', async () => {
      const inc = await createIncidentDirect({ title: 'Notes Timeline Order' });

      await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { note: 'First note.' }, analystToken);
      await new Promise((r) => setTimeout(r, 20));
      await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { note: 'Second note.' }, adminToken);

      const res = await get(`${baseUrl}/api/incidents/${inc.id}`, adminToken);
      assert.equal(res.status, 200);
      const { timeline } = (await res.json()).data;

      const noteEntries = timeline.filter((e) => e.action === 'INCIDENT_NOTE_ADD');
      assert.equal(noteEntries.length, 2);
      // Timeline ordered descending: newest first
      const [first, second] = noteEntries;
      assert.ok(
        new Date(first.timestamp).getTime() >= new Date(second.timestamp).getTime(),
        'Timeline must be ordered newest first',
      );
      assert.equal(first.details.note, 'Second note.');
      assert.equal(second.details.note, 'First note.');
    });

    it('returns 400 for empty note string', async () => {
      const inc = await createIncidentDirect({ title: 'Empty Note Test' });
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { note: '' }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for whitespace-only note', async () => {
      const inc = await createIncidentDirect({ title: 'Whitespace Note Test' });
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { note: '   ' }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for note exceeding 2000 characters', async () => {
      const inc = await createIncidentDirect({ title: 'Long Note Test' });
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { note: 'x'.repeat(2001) }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 400 for missing note field', async () => {
      const inc = await createIncidentDirect({ title: 'Missing Note Field' });
      const res = await post(`${baseUrl}/api/incidents/${inc.id}/notes`, { content: 'wrong field' }, analystToken);
      assert.equal(res.status, 400);
    });

    it('returns 404 when adding a note to a non-existent incident', async () => {
      const res = await post(
        `${baseUrl}/api/incidents/ffffffff-ffff-4fff-bfff-000000000003/notes`,
        { note: 'ghost note' },
        adminToken,
      );
      assert.equal(res.status, 404);
    });

    it('server ignores or rejects client-supplied author fields; DB reflects authenticated user', async () => {
      const inc = await createIncidentDirect({ title: 'Note Attribution Spoof Test' });

      // Attempt to inject extra author fields — notes payload only accepts { note }
      // Extra fields in a minimal validation context may either be ignored or rejected.
      const res = await post(
        `${baseUrl}/api/incidents/${inc.id}/notes`,
        { note: 'Legit note', authorName: 'SPOOFED', userId: 'fake-id' },
        analystToken,
      );

      if (res.status === 201) {
        // If server accepted the request, the DB record must attribute to real user
        const audit = await prisma.auditLog.findFirst({
          where: { targetType: 'Incident', targetId: inc.id, action: 'INCIDENT_NOTE_ADD' },
        });
        assert.equal(audit.userId, analystUser.id, 'AuditLog must attribute to real authenticated user');
        assert.equal(audit.details.authorName, analystUser.name);
      } else {
        // Server correctly rejected extra fields
        assert.equal(res.status, 400);
      }
    });
  });

  // ── 11. Transaction Integrity & Concurrency ───────────────────────────────

  describe('11. Transaction Integrity and Optimistic Concurrency', () => {
    it('rolls back incident creation if audit log fails (atomicity)', async () => {
      const countBefore = await prisma.incident.count();
      const originalTransaction = prisma.$transaction;

      prisma.$transaction = async function (arg, ...rest) {
        if (typeof arg === 'function') {
          return originalTransaction.call(prisma, async (tx) => {
            const interceptedTx = Object.create(tx);
            interceptedTx.auditLog = {
              ...tx.auditLog,
              create: async () => {
                throw new Error('Simulated audit log write failure');
              },
            };
            return arg(interceptedTx);
          }, ...rest);
        }
        return originalTransaction.call(prisma, arg, ...rest);
      };

      try {
        const res = await post(`${baseUrl}/api/incidents`, { title: 'Rollback Atomicity Test' }, analystToken);
        assert.equal(res.status, 500);

        const countAfter = await prisma.incident.count();
        assert.equal(countAfter, countBefore, 'Incident count must not increase when transaction rolls back');
      } finally {
        prisma.$transaction = originalTransaction;
      }
    });

    it('concurrent PATCH requests both succeed or one gets 409 — DB remains coherent', async () => {
      const inc = await createIncidentDirect({ title: 'Concurrent Race Test' });

      const [res1, res2] = await Promise.all([
        patch(`${baseUrl}/api/incidents/${inc.id}`, { title: 'Race Winner A' }, adminToken),
        patch(`${baseUrl}/api/incidents/${inc.id}`, { title: 'Race Winner B' }, adminToken),
      ]);

      const statuses = [res1.status, res2.status];
      assert.ok(
        statuses.every((s) => s === 200 || s === 409),
        `Expected 200 or 409, got: ${statuses}`,
      );

      // DB must be coherent regardless
      const final = await prisma.incident.findUnique({ where: { id: inc.id } });
      assert.ok(final, 'Incident must still exist after concurrent updates');
    });

    it('duplicate concurrent alert linking does not create duplicate IncidentAlert records', async () => {
      const inc = await createIncidentDirect({ title: 'Concurrent Link Dedup' });
      const alert = await createAlertDirect();

      const [res1, res2] = await Promise.all([
        post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [alert.id] }, analystToken),
        post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [alert.id] }, analystToken),
      ]);

      // Both must be 200 (the link-dedup logic skips already-linked alerts rather than throwing)
      assert.ok(
        [res1.status, res2.status].every((s) => s === 200),
        `Both link requests must return 200, got ${res1.status} and ${res2.status}`,
      );

      // DB must have exactly one IncidentAlert record
      const count = await prisma.incidentAlert.count({ where: { incidentId: inc.id, alertId: alert.id } });
      assert.equal(count, 1, 'Exactly one IncidentAlert record must exist (no duplicates from concurrent linking)');
    });

    it('failed alert-link operation (audit error) leaves no partial records in DB', async () => {
      const inc = await createIncidentDirect({ title: 'Link Rollback Test' });
      const linkCountBefore = await prisma.incidentAlert.count({ where: { incidentId: inc.id } });
      const auditCountBefore = await prisma.auditLog.count({
        where: { targetType: 'Incident', targetId: inc.id },
      });

      const originalTransaction = prisma.$transaction;
      prisma.$transaction = async function (arg, ...rest) {
        if (typeof arg === 'function') {
          return originalTransaction.call(prisma, async (tx) => {
            const interceptedTx = Object.create(tx);
            interceptedTx.auditLog = {
              ...tx.auditLog,
              create: async () => {
                throw new Error('Simulated link audit failure');
              },
            };
            return arg(interceptedTx);
          }, ...rest);
        }
        return originalTransaction.call(prisma, arg, ...rest);
      };

      try {
        const alert = await createAlertDirect();
        const res = await post(`${baseUrl}/api/incidents/${inc.id}/alerts`, { alertIds: [alert.id] }, analystToken);
        assert.equal(res.status, 500);

        const linkCountAfter = await prisma.incidentAlert.count({ where: { incidentId: inc.id } });
        const auditCountAfter = await prisma.auditLog.count({
          where: { targetType: 'Incident', targetId: inc.id },
        });

        assert.equal(linkCountAfter, linkCountBefore, 'No IncidentAlert records must be created on rollback');
        assert.equal(auditCountAfter, auditCountBefore, 'No orphaned audit log entries on rollback');
      } finally {
        prisma.$transaction = originalTransaction;
      }
    });
  });

  // ── 12. Error response format ─────────────────────────────────────────────

  describe('12. Error Response Format Consistency', () => {
    it('all error responses follow { success: false, error: string } convention', async () => {
      const badRequests = [
        // 400 errors
        get(`${baseUrl}/api/incidents?page=0`, analystToken),
        get(`${baseUrl}/api/incidents/not-a-uuid`, analystToken),
        post(`${baseUrl}/api/incidents`, {}, analystToken),
        // 401 errors
        get(`${baseUrl}/api/incidents`),
        post(`${baseUrl}/api/incidents`, { title: 'Unauth' }),
        // 403 errors
        post(`${baseUrl}/api/incidents`, { title: 'Forbidden' }, viewerToken),
        // 404 errors
        get(`${baseUrl}/api/incidents/ffffffff-ffff-4fff-bfff-ffffffffffff`, analystToken),
      ];

      for (const reqPromise of badRequests) {
        const res = await reqPromise;
        assert.ok(res.status >= 400 && res.status < 600);
        const body = await res.json();
        assert.equal(body.success, false, `Expected success:false for status ${res.status}`);
        assert.ok(
          typeof body.error === 'string' && body.error.length > 0,
          `Error must be a non-empty string, got: ${JSON.stringify(body.error)}`,
        );
      }
    });
  });
});
