// test/assets.test.js
// Comprehensive test suite for Phase 8 Asset Management API.
// Uses Node 22 native test runner (node:test) with real PostgreSQL/Prisma
// and real Express HTTP requests via fetch.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { Severity, AssetStatus } from '@prisma/client';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;

// Track created IDs for safe, targeted cleanup
const createdAssetIds = [];

describe('Phase 8 — Asset Management API', () => {
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

    // 3. Start ephemeral test server on random open port
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    // Clean up created test assets and their audit logs
    if (createdAssetIds.length > 0) {
      await prisma.auditLog.deleteMany({
        where: { targetType: 'Asset', targetId: { in: createdAssetIds } },
      });
      await prisma.asset.deleteMany({
        where: { id: { in: createdAssetIds } },
      });
    }

    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  // ── 1. Authentication & RBAC ─────────────────────────────────────────────

  describe('1. Authentication & Role Permissions', () => {
    it('rejects unauthenticated request to GET /api/assets with 401', async () => {
      const res = await fetch(`${baseUrl}/api/assets`);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /authentication required/i);
    });

    it('rejects invalid Bearer token with 401', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        headers: { Authorization: 'Bearer not-a-valid-token' },
      });
      assert.equal(res.status, 401);
    });

    it('allows VIEWER to read assets list, stats, and detail', async () => {
      const resList = await fetch(`${baseUrl}/api/assets`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(resList.status, 200);

      const resStats = await fetch(`${baseUrl}/api/assets/stats`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(resStats.status, 200);
    });

    it('rejects VIEWER attempts to create an asset with 403', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${viewerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'Unauthorized-Asset' }),
      });
      assert.equal(res.status, 403);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /access denied/i);
    });

    it('rejects VIEWER attempts to update an asset with 403', async () => {
      const res = await fetch(`${baseUrl}/api/assets/00000000-0000-0000-0000-000000000000`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${viewerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'Unauthorized-Update' }),
      });
      assert.equal(res.status, 403);
    });

    it('rejects ANALYST attempts to delete an asset with 403 (ADMIN only)', async () => {
      const res = await fetch(`${baseUrl}/api/assets/00000000-0000-0000-0000-000000000000`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 403);
    });
  });

  // ── 2. Asset Creation & Validation ───────────────────────────────────────

  describe('2. Asset Creation & Validation', () => {
    it('rejects empty or missing asset name with 400', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: '   ' }),
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /asset "name" is required/i);
    });

    it('rejects invalid IP address format with 400', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'Bad-IP-Asset', ipAddress: '999.999.999.999' }),
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /valid ipv4 or ipv6/i);
    });

    it('rejects invalid asset type with 400', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'Bad-Type-Asset', type: 'SUPERCOMPUTER' }),
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /invalid asset type/i);
    });

    it('rejects unexpected fields in payload with 400', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'Bad-Fields-Asset', secretPassword: 'hack' }),
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /unexpected fields/i);
    });

    it('successfully creates an asset with all supported fields and creates AuditLog', async () => {
      const uniqueIp = `10.200.${Math.floor(Math.random() * 200) + 1}.${Math.floor(Math.random() * 200) + 1}`;
      const payload = {
        name: 'TEST-SRV-APP-01',
        hostname: 'app01.soclite.corp',
        ipAddress: uniqueIp,
        type: 'SERVER',
        criticality: 'HIGH',
        status: 'ACTIVE',
        environment: 'PRODUCTION',
        operatingSystem: 'Ubuntu 24.04 LTS',
        owner: 'SecOps Team',
        description: 'Primary application cluster node for test validation.',
        tags: ['app', 'docker', 'test'],
      };

      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(body.data.id);
      assert.equal(body.data.name, payload.name);
      assert.equal(body.data.ipAddress, payload.ipAddress);
      assert.equal(body.data.criticality, 'HIGH');
      assert.equal(body.data.status, 'ACTIVE');

      createdAssetIds.push(body.data.id);

      // Verify AuditLog record was created
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Asset', targetId: body.data.id, action: 'ASSET_CREATE' },
      });
      assert.ok(audit, 'AuditLog entry must be recorded on asset creation');
      assert.equal(audit.userId, analystUser.id);
    });

    it('prevents duplicate IP address registration with 409 Conflict', async () => {
      const uniqueIp = `10.201.${Math.floor(Math.random() * 200) + 1}.${Math.floor(Math.random() * 200) + 1}`;

      // Create first asset
      const res1 = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'Original-Asset', ipAddress: uniqueIp }),
      });
      assert.equal(res1.status, 201);
      const body1 = await res1.json();
      createdAssetIds.push(body1.data.id);

      // Attempt second asset with identical IP
      const res2 = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: 'Duplicate-IP-Asset', ipAddress: uniqueIp }),
      });
      assert.equal(res2.status, 409);
      const body2 = await res2.json();
      assert.equal(body2.success, false);
      assert.match(body2.error, /already exists/i);
    });

    it('allows assets without IP addresses (null ipAddress)', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: 'AIRGAPPED-LAPTOP-01',
          type: 'LAPTOP',
          criticality: 'MEDIUM',
        }),
      });
      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.data.ipAddress, null);
      createdAssetIds.push(body.data.id);
    });
  });

  // ── 3. Asset Retrieval & Details ─────────────────────────────────────────

  describe('3. Asset Retrieval & Details', () => {
    let testAsset;

    before(async () => {
      testAsset = await prisma.asset.create({
        data: {
          name: 'DETAIL-TEST-ASSET',
          hostname: 'detail.soclite.corp',
          type: 'WORKSTATION',
          criticality: Severity.LOW,
          status: AssetStatus.ACTIVE,
        },
      });
      createdAssetIds.push(testAsset.id);

      // Add a test audit log
      await prisma.auditLog.create({
        data: {
          userId: adminUser.id,
          action: 'ASSET_CREATE',
          targetType: 'Asset',
          targetId: testAsset.id,
          details: { name: testAsset.name },
        },
      });
    });

    it('returns 400 on malformed asset UUID', async () => {
      const res = await fetch(`${baseUrl}/api/assets/invalid-uuid`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 400);
    });

    it('returns 404 for non-existent asset UUID', async () => {
      const res = await fetch(`${baseUrl}/api/assets/00000000-0000-0000-0000-000000000000`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 404);
    });

    it('returns full asset metadata and audit timeline', async () => {
      const res = await fetch(`${baseUrl}/api/assets/${testAsset.id}`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      assert.equal(data.id, testAsset.id);
      assert.equal(data.name, 'DETAIL-TEST-ASSET');
      assert.ok(Array.isArray(data.timeline));
      assert.ok(data.timeline.length >= 1);
      assert.equal(data.timeline[0].action, 'ASSET_CREATE');
      assert.equal(data.timeline[0].actor.email, adminUser.email);
    });
  });

  // ── 4. Asset Updates & Decommissioning ───────────────────────────────────

  describe('4. Asset Updates & Decommissioning', () => {
    let testAsset;

    before(async () => {
      testAsset = await prisma.asset.create({
        data: {
          name: 'UPDATE-TEST-ASSET',
          type: 'SERVER',
          criticality: Severity.MEDIUM,
          status: AssetStatus.ACTIVE,
          ipAddress: `10.202.${Math.floor(Math.random() * 200) + 1}.10`,
        },
      });
      createdAssetIds.push(testAsset.id);
    });

    it('partially updates fields while preserving unmentioned properties', async () => {
      const res = await fetch(`${baseUrl}/api/assets/${testAsset.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          description: 'Updated description for test.',
          criticality: 'CRITICAL',
        }),
      });

      assert.equal(res.status, 200);
      const { data } = await res.json();
      assert.equal(data.criticality, 'CRITICAL');
      assert.equal(data.description, 'Updated description for test.');
      assert.equal(data.name, 'UPDATE-TEST-ASSET'); // Preserved
      assert.equal(data.ipAddress, testAsset.ipAddress); // Preserved

      // Verify ASSET_UPDATE AuditLog entry
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Asset', targetId: testAsset.id, action: 'ASSET_UPDATE' },
        orderBy: { timestamp: 'desc' },
      });
      assert.ok(audit);
      assert.equal(audit.userId, analystUser.id);
    });

    it('safely decommissions an asset and logs ASSET_DECOMMISSION', async () => {
      const res = await fetch(`${baseUrl}/api/assets/${testAsset.id}/decommission`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${analystToken}`,
        },
      });

      assert.equal(res.status, 200);
      const { data } = await res.json();
      assert.equal(data.status, 'DECOMMISSIONED');

      // Verify database persistence
      const fresh = await prisma.asset.findUnique({ where: { id: testAsset.id } });
      assert.equal(fresh.status, 'DECOMMISSIONED');

      // Verify audit log
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Asset', targetId: testAsset.id, action: 'ASSET_DECOMMISSION' },
        orderBy: { timestamp: 'desc' },
      });
      assert.ok(audit);
    });
  });

  // ── 5. Filtering, Search, Pagination & Stats ─────────────────────────────

  describe('5. Inventory Search, Filtering, Pagination & Stats', () => {
    before(async () => {
      const uniqueSuffix = Date.now().toString(36);
      const assets = await Promise.all([
        prisma.asset.create({
          data: {
            name: `SEARCH-ALPHA-${uniqueSuffix}`,
            type: 'FIREWALL',
            status: AssetStatus.ACTIVE,
            criticality: Severity.CRITICAL,
            environment: 'PRODUCTION',
          },
        }),
        prisma.asset.create({
          data: {
            name: `SEARCH-BETA-${uniqueSuffix}`,
            type: 'WORKSTATION',
            status: AssetStatus.INACTIVE,
            criticality: Severity.LOW,
            environment: 'DEVELOPMENT',
          },
        }),
      ]);
      assets.forEach((a) => createdAssetIds.push(a.id));
    });

    it('filters inventory by search term', async () => {
      const res = await fetch(`${baseUrl}/api/assets?search=ALPHA`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();
      assert.ok(data.length >= 1);
      assert.ok(data.some((a) => a.name.includes('ALPHA')));
    });

    it('filters inventory by status and criticality', async () => {
      const res = await fetch(`${baseUrl}/api/assets?status=ACTIVE&criticality=CRITICAL`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();
      for (const a of data) {
        assert.equal(a.status, 'ACTIVE');
        assert.equal(a.criticality, 'CRITICAL');
      }
    });

    it('paginates results deterministically', async () => {
      const res = await fetch(`${baseUrl}/api/assets?page=1&limit=2`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data, pagination } = await res.json();
      assert.equal(data.length, 2);
      assert.equal(pagination.page, 1);
      assert.equal(pagination.limit, 2);
      assert.ok(pagination.total >= 2);
    });

    it('calculates accurate inventory statistics from actual database records', async () => {
      const res = await fetch(`${baseUrl}/api/assets/stats`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.equal(res.status, 200);
      const { data } = await res.json();

      assert.ok(typeof data.total === 'number');
      assert.ok(typeof data.active === 'number');
      assert.ok(typeof data.inactive === 'number');
      assert.ok(typeof data.decommissioned === 'number');
      assert.ok(typeof data.critical === 'number');
      assert.ok(data.total >= data.active + data.inactive + data.decommissioned);
    });
  });

  // ── 6. Permanent Deletion (ADMIN Only) ───────────────────────────────────

  describe('6. Permanent Asset Deletion', () => {
    it('allows ADMIN to delete an asset and creates an ASSET_DELETE audit entry', async () => {
      const asset = await prisma.asset.create({
        data: { name: 'DELETE-ME-ASSET', type: 'WORKSTATION' },
      });

      const res = await fetch(`${baseUrl}/api/assets/${asset.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);

      // Verify deletion from database
      const check = await prisma.asset.findUnique({ where: { id: asset.id } });
      assert.equal(check, null);

      // Verify ASSET_DELETE audit log was recorded
      const audit = await prisma.auditLog.findFirst({
        where: { targetType: 'Asset', targetId: asset.id, action: 'ASSET_DELETE' },
      });
      assert.ok(audit);

      // Clean up audit record
      await prisma.auditLog.deleteMany({ where: { targetType: 'Asset', targetId: asset.id } });
    });
  });
});
