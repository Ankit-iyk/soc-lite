// test/rules.test.js
// Automated test suite for Detection Rules Management API (Phase 4 Step 3A).
// Uses Node 22 native test runner (node:test).

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { RuleType, Severity } from '@prisma/client';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;

// Track baseline seeded rules so we can restore them after testing
let baselineRules = [];

describe('Phase 4 Step 3A — Detection Rules Management API', () => {
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

    // Snapshot baseline rules
    baselineRules = await prisma.detectionRule.findMany();
    assert.ok(baselineRules.length >= 4, 'Must have at least 4 seeded detection rules');
  });

  after(async () => {
    // Restore baseline rules configuration and enabled status
    for (const r of baselineRules) {
      await prisma.detectionRule.update({
        where: { id: r.id },
        data: {
          enabled: r.enabled,
          description: r.description,
          severity: r.severity,
          config: r.config,
        },
      });
    }

    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  // ── 1. GET /api/rules (Read Operations & RBAC) ──────────────────────────────

  it('rejects unauthenticated GET /api/rules with 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/api/rules`);
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.success, false);
  });

  it('allows VIEWER role to read all detection rules', async () => {
    const res = await fetch(`${baseUrl}/api/rules`, {
      headers: { Authorization: `Bearer ${viewerToken}` },
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.data));
    assert.ok(body.data.length >= 4);

    const first = body.data[0];
    assert.ok(first.id);
    assert.ok(first.name);
    assert.ok(first.type);
    assert.ok(first.severity);
    assert.ok(typeof first.enabled === 'boolean');
    assert.ok(first.config);
    assert.ok(first.createdAt);
    assert.ok(first.updatedAt);
  });

  it('allows ANALYST role to read all detection rules', async () => {
    const res = await fetch(`${baseUrl}/api/rules`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.data));
  });

  it('allows ADMIN role to read all detection rules', async () => {
    const res = await fetch(`${baseUrl}/api/rules`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.data));
  });

  // ── 2. PUT /api/rules/:id (Modification Authorization & RBAC) ───────────────

  it('rejects unauthenticated PUT /api/rules/:id with 401 Unauthorized', async () => {
    const rule = baselineRules[0];
    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: false }),
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.success, false);
  });

  it('rejects VIEWER role from modifying detection rules with 403 Forbidden', async () => {
    const rule = baselineRules[0];
    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${viewerToken}`,
      },
      body: JSON.stringify({ enabled: false }),
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /Access denied/);
  });

  it('rejects ANALYST role from modifying detection rules with 403 Forbidden', async () => {
    const rule = baselineRules[0];
    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ enabled: false }),
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /Access denied/);
  });

  // ── 3. Rule Existence & Payload Validation ──────────────────────────────────

  it('returns 404 Not Found for non-existent rule ID', async () => {
    const res = await fetch(`${baseUrl}/api/rules/00000000-0000-0000-0000-000000000000`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ enabled: false }),
    });

    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /not found/i);
  });

  it('rejects empty request body with 400 Bad Request', async () => {
    const rule = baselineRules[0];
    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /No update fields provided/i);
  });

  it('rejects attempts to modify immutable or unsupported fields (id, name, type) with 400', async () => {
    const rule = baselineRules[0];
    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        name: 'Hacked Rule Name',
        type: 'CUSTOM_TYPE',
        id: 'new-id',
      }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /Unsupported or unmodifiable field/i);
  });

  it('rejects invalid data type for enabled with 400', async () => {
    const rule = baselineRules[0];
    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ enabled: 'yes' }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /must be a boolean/i);
  });

  it('rejects invalid severity value with 400', async () => {
    const rule = baselineRules[0];
    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ severity: 'ULTRA_HIGH' }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /Field "severity" must be one of/i);
  });

  // ── 4. Rule-Specific Configuration Validation & Bounds ──────────────────────

  describe('SSH_BRUTE_FORCE Configuration Validation', () => {
    let sshRule;
    before(async () => {
      sshRule = await prisma.detectionRule.findFirst({
        where: { type: RuleType.SSH_BRUTE_FORCE },
      });
    });

    it('rejects out-of-bounds threshold (< 1 or > 1000)', async () => {
      const resLow = await fetch(`${baseUrl}/api/rules/${sshRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { threshold: 0 } }),
      });
      assert.equal(resLow.status, 400);
      assert.match((await resLow.json()).error, /threshold must be an integer between 1 and 1000/);

      const resHigh = await fetch(`${baseUrl}/api/rules/${sshRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { threshold: 5000 } }),
      });
      assert.equal(resHigh.status, 400);
      assert.match((await resHigh.json()).error, /threshold must be an integer between 1 and 1000/);
    });

    it('rejects out-of-bounds windowSeconds (< 1 or > 86400)', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${sshRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { windowSeconds: -10 } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /windowSeconds must be an integer between 1 and 86400/);
    });

    it('rejects unsupported keys in SSH_BRUTE_FORCE config', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${sshRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { invalidKey: 99 } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /Unsupported config key/);
    });
  });

  describe('PORT_SCAN Configuration Validation', () => {
    let portRule;
    before(async () => {
      portRule = await prisma.detectionRule.findFirst({
        where: { type: RuleType.PORT_SCAN },
      });
    });

    it('rejects out-of-bounds portThreshold (< 1 or > 65535)', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${portRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { portThreshold: 70000 } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /portThreshold must be an integer between 1 and 65535/);
    });

    it('rejects invalid eventType format', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${portRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { eventType: '   ' } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /non-empty string/);
    });
  });

  describe('SUSPICIOUS_IP Configuration Validation', () => {
    let ipRule;
    before(async () => {
      ipRule = await prisma.detectionRule.findFirst({
        where: { type: RuleType.SUSPICIOUS_IP },
      });
    });

    it('rejects non-boolean matchSource or matchDestination', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${ipRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { matchSource: 'true' } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /must be a boolean/);
    });

    it('rejects disabling both matchSource and matchDestination simultaneously', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${ipRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { matchSource: false, matchDestination: false } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /at least one of matchSource or matchDestination enabled/);
    });
  });

  describe('SUSPICIOUS_ACCESS Configuration Validation', () => {
    let accessRule;
    before(async () => {
      accessRule = await prisma.detectionRule.findFirst({
        where: { type: RuleType.SUSPICIOUS_ACCESS },
      });
    });

    it('rejects invalid hours range (< 0 or > 24)', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${accessRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { allowedHoursStart: -1 } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /allowedHoursStart must be an integer between 0 and 23/);
    });

    it('rejects allowedHoursStart >= allowedHoursEnd', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${accessRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { allowedHoursStart: 20, allowedHoursEnd: 10 } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /must be strictly less than allowedHoursEnd/);
    });

    it('rejects invalid targetRole string', async () => {
      const res = await fetch(`${baseUrl}/api/rules/${accessRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ config: { targetRole: 'SUPER_ROOT' } }),
      });
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /targetRole must be one of/);
    });
  });

  // ── 5. Successful Updates & Audit Logging ────────────────────────────────────

  it('successfully updates enabled status and records AuditLog', async () => {
    const rule = baselineRules[0];

    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ enabled: false }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.enabled, false);

    // Verify in database
    const dbRule = await prisma.detectionRule.findUnique({ where: { id: rule.id } });
    assert.equal(dbRule.enabled, false);

    // Verify AuditLog record was created atomically
    const audit = await prisma.auditLog.findFirst({
      where: {
        action: 'RULE_UPDATE',
        targetId: rule.id,
      },
      orderBy: { timestamp: 'desc' },
    });

    assert.ok(audit);
    assert.equal(audit.userId, adminUser.id);
    assert.equal(audit.targetType, 'DetectionRule');
    assert.deepEqual(audit.details.changedFields, ['enabled']);
    assert.equal(audit.details.previous.enabled, true);
    assert.equal(audit.details.updated.enabled, false);
  });

  it('preserves existing config when only enabled, severity, or description are updated', async () => {
    const rule = baselineRules[0]; // SSH brute force
    const originalConfig = rule.config;

    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        enabled: true,
        severity: 'CRITICAL',
        description: 'Updated description for testing.',
      }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.severity, 'CRITICAL');
    assert.equal(body.data.description, 'Updated description for testing.');
    assert.deepEqual(body.data.config, originalConfig, 'Original config must remain unchanged');
  });

  it('partially updates configuration while preserving unchanged config keys', async () => {
    const sshRule = await prisma.detectionRule.findFirst({
      where: { type: RuleType.SSH_BRUTE_FORCE },
    });

    // Update only threshold to 8, leaving windowSeconds and eventType untouched
    const res = await fetch(`${baseUrl}/api/rules/${sshRule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        config: { threshold: 8 },
      }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.config.threshold, 8);
    assert.equal(body.data.config.windowSeconds, 60, 'Preserved from existing config');
    assert.equal(body.data.config.eventType, 'ssh_login_failed', 'Preserved from existing config');

    // Verify in database
    const updatedDbRule = await prisma.detectionRule.findUnique({ where: { id: sshRule.id } });
    assert.equal(updatedDbRule.config.threshold, 8);
  });

  it('does NOT create an AuditLog entry when a request is rejected with 400 Bad Request', async () => {
    const rule = baselineRules[0];
    const auditCountBefore = await prisma.auditLog.count({
      where: { action: 'RULE_UPDATE', targetId: rule.id },
    });

    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ severity: 'INVALID_SEVERITY_VALUE' }),
    });

    assert.equal(res.status, 400);

    const auditCountAfter = await prisma.auditLog.count({
      where: { action: 'RULE_UPDATE', targetId: rule.id },
    });
    assert.equal(auditCountAfter, auditCountBefore, 'No audit record should be created on failure');
  });

  it('does NOT create an AuditLog entry when a request is rejected with 403 Forbidden', async () => {
    const rule = baselineRules[0];
    const auditCountBefore = await prisma.auditLog.count({
      where: { action: 'RULE_UPDATE', targetId: rule.id },
    });

    const res = await fetch(`${baseUrl}/api/rules/${rule.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ enabled: false }),
    });

    assert.equal(res.status, 403);

    const auditCountAfter = await prisma.auditLog.count({
      where: { action: 'RULE_UPDATE', targetId: rule.id },
    });
    assert.equal(auditCountAfter, auditCountBefore);
  });
});
