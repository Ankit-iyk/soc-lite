// test/audit.test.js
// Automated test suite for Audit Logging & RBAC Hardening (Phase 12).
// Uses Node 22 native test runner (node:test).

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { sanitizeAuditDetails, writeAuditLog } from '../src/utils/audit.js';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;

describe('Phase 12 — Audit Logging & RBAC Hardening Tests', () => {
  before(async () => {
    // 1. Dynamic port HTTP server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });

    // 2. Fetch seeded test accounts
    adminUser = await prisma.user.findUnique({ where: { email: 'admin@soclite.local' } });
    analystUser = await prisma.user.findUnique({ where: { email: 'analyst@soclite.local' } });
    viewerUser = await prisma.user.findUnique({ where: { email: 'viewer@soclite.local' } });

    assert.ok(adminUser, 'Seeded admin user must exist');
    assert.ok(analystUser, 'Seeded analyst user must exist');
    assert.ok(viewerUser, 'Seeded viewer user must exist');

    adminToken = signToken({ userId: adminUser.id, email: adminUser.email, role: adminUser.role });
    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });
    viewerToken = signToken({ userId: viewerUser.id, email: viewerUser.email, role: viewerUser.role });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  // ── 1. Unit Tests for Audit Sanitizer ───────────────────────────────────────

  describe('1. Audit Sanitization & Bounding Unit Tests', () => {
    it('redacts sensitive fields like passwords, tokens, and apiKeys', () => {
      const input = {
        username: 'analyst1',
        password: 'SuperSecretPassword123!',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        apiKey: 'vt-api-key-998877',
        nested: {
          passwordHash: '$2b$10$abcdefg...',
          clientSecret: 'secret-val',
          regularField: 'keep this',
        },
      };

      const sanitized = sanitizeAuditDetails(input);

      assert.equal(sanitized.username, 'analyst1');
      assert.equal(sanitized.password, '[REDACTED]');
      assert.equal(sanitized.token, '[REDACTED]');
      assert.equal(sanitized.apiKey, '[REDACTED]');
      assert.equal(sanitized.nested.passwordHash, '[REDACTED]');
      assert.equal(sanitized.nested.clientSecret, '[REDACTED]');
      assert.equal(sanitized.nested.regularField, 'keep this');
    });

    it('bounds excessively long strings in audit details', () => {
      const hugeString = 'A'.repeat(2500);
      const sanitized = sanitizeAuditDetails({ payload: hugeString });
      assert.ok(sanitized.payload.length < 1100);
      assert.ok(sanitized.payload.includes('[TRUNCATED]'));
    });

    it('bounds large arrays in audit details', () => {
      const hugeArray = Array.from({ length: 100 }, (_, i) => `item-${i}`);
      const sanitized = sanitizeAuditDetails({ items: hugeArray });
      assert.equal(sanitized.items.length, 51); // 50 items + 1 truncation marker
      assert.ok(sanitized.items[50].includes('MORE ITEMS TRUNCATED'));
    });

    it('writeAuditLog helper creates DB entry with sanitized metadata', async () => {
      const log = await writeAuditLog({
        userId: adminUser.id,
        action: 'TEST_AUDIT_ACTION',
        targetType: 'TestTarget',
        targetId: 'target-123',
        ipAddress: '127.0.0.1',
        details: {
          safeKey: 'valid',
          bearerToken: 'secret-token-12345',
        },
      });

      assert.ok(log.id);
      assert.equal(log.action, 'TEST_AUDIT_ACTION');
      assert.equal(log.details.safeKey, 'valid');
      assert.equal(log.details.bearerToken, '[REDACTED]');

      // Cleanup
      await prisma.auditLog.delete({ where: { id: log.id } });
    });
  });

  // ── 2. RBAC & Access Control for Audit History ─────────────────────────────

  describe('2. Audit History RBAC Enforcement', () => {
    it('rejects unauthenticated requests to /api/audit-logs with 401', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs`);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.equal(body.success, false);
    });

    it('rejects VIEWER role with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /Access denied/);
    });

    it('allows ANALYST role to view audit history with 200', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(Array.isArray(body.data.logs));
      assert.ok(body.data.pagination);
    });

    it('allows ADMIN role to view audit history with 200', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(Array.isArray(body.data.logs));
    });
  });

  // ── 3. Query Validation & Filtering ────────────────────────────────────────

  describe('3. Audit Query Validation & Filtering', () => {
    it('validates limit ceiling (max 100) with 400 Bad Request', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs?limit=500`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /between 1 and 100/);
    });

    it('validates invalid date range with 400 Bad Request', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs?startDate=2026-12-01&endDate=2026-01-01`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /startDate cannot be later than endDate/);
    });

    it('filters audit logs by action type', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs?action=LOGS_INGESTED`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      for (const log of body.data.logs) {
        assert.equal(log.action, 'LOGS_INGESTED');
      }
    });

    it('fetches audit statistics via /api/audit-logs/stats', async () => {
      const res = await fetch(`${baseUrl}/api/audit-logs/stats`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(typeof body.data.total === 'number');
      assert.ok(typeof body.data.past24hCount === 'number');
      assert.ok(Array.isArray(body.data.topActions));
      assert.ok(Array.isArray(body.data.topTargetTypes));
    });
  });

  // ── 4. Audit Retention on Deletion ─────────────────────────────────────────

  describe('4. Historical Audit Retention Verification', () => {
    it('preserves audit logs after entity deletion (Asset lifecycle)', async () => {
      // 1. Create a test asset
      const createRes = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({
          name: 'Temporary Deletion Test Asset',
          ipAddress: '198.51.100.222',
          type: 'SERVER',
          criticality: 'LOW',
        }),
      });

      assert.equal(createRes.status, 201);
      const asset = (await createRes.json()).data;

      // 2. Delete the asset
      const delRes = await fetch(`${baseUrl}/api/assets/${asset.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(delRes.status, 200);

      // 3. Confirm asset is removed from inventory
      const getRes = await fetch(`${baseUrl}/api/assets/${asset.id}`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(getRes.status, 404);

      // 4. Verify audit log entry still exists and was not cascaded/destroyed
      const auditLog = await prisma.auditLog.findFirst({
        where: {
          targetId: asset.id,
          action: 'ASSET_DELETE',
        },
      });

      assert.ok(auditLog, 'AuditLog record must persist even after the entity is deleted');
      assert.equal(auditLog.targetId, asset.id);

      // Cleanup
      await prisma.auditLog.deleteMany({ where: { targetId: asset.id } });
    });
  });
});
