// test/threatIntel.test.js
// Integration test suite for Phase 9: Threat Intelligence & IOC Integration API.
// Uses Node 22 native test runner (node:test).

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';
import { AbuseIpDbAdapter } from '../src/modules/threat-intelligence/providers/abuseipdb.adapter.js';
import { VirusTotalAdapter } from '../src/modules/threat-intelligence/providers/virustotal.adapter.js';
import { AlienVaultOtxAdapter } from '../src/modules/threat-intelligence/providers/otx.adapter.js';
import {
  validateAndNormalizeIocValue,
  normalizeIocType,
} from '../src/modules/threat-intelligence/threatIntel.validation.js';

let server;
let baseUrl;
let adminToken;
let analystToken;
let viewerToken;
let adminUser;
let analystUser;
let viewerUser;

// Track created test IOC IDs for clean teardown
const createdIocIds = [];

describe('Phase 9 — Threat Intelligence & IOC Integration API', () => {
  before(async () => {
    // 1. Start dynamic test server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });

    // 2. Fetch seeded users
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
    // Teardown created test enrichments and test-only IOCs
    if (createdIocIds.length > 0) {
      await prisma.iocEnrichment.deleteMany({
        where: { indicatorId: { in: createdIocIds } },
      });
      await prisma.threatIndicator.deleteMany({
        where: {
          id: { in: createdIocIds },
          value: { notIn: ['198.51.100.23', '203.0.113.88', 'c2-malware.evil-corp.xyz', '10.0.0.1'] },
        },
      });
    }

    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  // ── 1. Unit & Normalization Tests ──────────────────────────────────────────

  describe('Validation & Normalization Unit Tests', () => {
    it('normalizes type aliases correctly', () => {
      assert.equal(normalizeIocType('IP_ADDRESS'), 'IP');
      assert.equal(normalizeIocType('ip'), 'IP');
      assert.equal(normalizeIocType('domain'), 'DOMAIN');
      assert.equal(normalizeIocType('FILE_HASH'), 'HASH');
      assert.equal(normalizeIocType('hash'), 'HASH');
      assert.equal(normalizeIocType('url'), 'URL');
      assert.equal(normalizeIocType('UNKNOWN_TYPE'), null);
    });

    it('validates and trims valid IPv4 and IPv6', () => {
      const v4 = validateAndNormalizeIocValue('IP', '  192.168.1.100  ');
      assert.equal(v4.valid, true);
      assert.equal(v4.value, '192.168.1.100');

      const v6 = validateAndNormalizeIocValue('IP', '2001:0DB8:85A3:0000:0000:8A2E:0370:7334');
      assert.equal(v6.valid, true);
      assert.equal(v6.value, '2001:0db8:85a3:0000:0000:8a2e:0370:7334');

      const invalidIp = validateAndNormalizeIocValue('IP', '999.999.999.999');
      assert.equal(invalidIp.valid, false);
    });

    it('validates and normalizes domains', () => {
      const d1 = validateAndNormalizeIocValue('DOMAIN', '  Malware-Site.COM/  ');
      assert.equal(d1.valid, true);
      assert.equal(d1.value, 'malware-site.com');

      const d2 = validateAndNormalizeIocValue('DOMAIN', 'https://c2.evil-corp.net/');
      assert.equal(d2.valid, true);
      assert.equal(d2.value, 'c2.evil-corp.net');

      const invalid = validateAndNormalizeIocValue('DOMAIN', 'not-a-domain');
      assert.equal(invalid.valid, false);
    });

    it('validates MD5, SHA-1, and SHA-256 hashes and lowercases them', () => {
      const md5 = validateAndNormalizeIocValue('HASH', 'E4D909C290D0FB1CA068FFADD0F0EB30');
      assert.equal(md5.valid, true);
      assert.equal(md5.value, 'e4d909c290d0fb1ca068ffadd0f0eb30');
      assert.equal(md5.hashType, 'MD5');

      const sha1 = validateAndNormalizeIocValue('HASH', '2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12');
      assert.equal(sha1.valid, true);
      assert.equal(sha1.hashType, 'SHA-1');

      const sha256 = validateAndNormalizeIocValue('HASH', '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae');
      assert.equal(sha256.valid, true);
      assert.equal(sha256.hashType, 'SHA-256');

      const invalidHash = validateAndNormalizeIocValue('HASH', 'ZZZZ1234');
      assert.equal(invalidHash.valid, false);
    });

    it('validates URLs and rejects unsafe protocols', () => {
      const validUrl = validateAndNormalizeIocValue('URL', 'HTTPS://EVIL.COM/payload.exe?download=1');
      assert.equal(validUrl.valid, true);
      assert.equal(validUrl.value, 'https://evil.com/payload.exe?download=1');

      const xss = validateAndNormalizeIocValue('URL', 'javascript:alert(1)');
      assert.equal(xss.valid, false);
      assert.match(xss.error, /protocol/i);

      const file = validateAndNormalizeIocValue('URL', 'file:///etc/passwd');
      assert.equal(file.valid, false);
    });
  });

  // ── 2. Provider Adapter Unit Tests ─────────────────────────────────────────

  describe('Provider Adapters Normalization & Safety', () => {
    it('AbuseIPDB adapter reports not-configured when key is absent', () => {
      const adapter = new AbuseIpDbAdapter();
      // Ensure key is not present for this test
      const originalKey = process.env.ABUSEIPDB_API_KEY;
      delete process.env.ABUSEIPDB_API_KEY;

      assert.equal(adapter.isConfigured(), false);
      const res = adapter.getNotConfiguredResult();
      assert.equal(res.status, 'NOT_CONFIGURED');
      assert.equal(res.verdict, null);
      assert.match(res.errorMessage, /not configured/i);

      if (originalKey) process.env.ABUSEIPDB_API_KEY = originalKey;
    });

    it('AbuseIPDB adapter normalizes response data into verdicts', () => {
      const adapter = new AbuseIpDbAdapter();

      // High confidence -> MALICIOUS
      const mal = adapter.normalizeResponse({
        data: {
          ipAddress: '198.51.100.99',
          abuseConfidenceScore: 85,
          totalReports: 120,
          countryCode: 'US',
          isp: 'Suspicious Cloud LLC',
        },
      });
      assert.equal(mal.status, 'SUCCESS');
      assert.equal(mal.verdict, 'MALICIOUS');
      assert.equal(mal.score, 85);
      assert.equal(mal.detectionCount, 120);

      // Clean -> BENIGN
      const benign = adapter.normalizeResponse({
        data: {
          ipAddress: '8.8.8.8',
          abuseConfidenceScore: 0,
          totalReports: 0,
        },
      });
      assert.equal(benign.verdict, 'BENIGN');
    });

    it('VirusTotal adapter normalizes analysis stats into verdicts', () => {
      const adapter = new VirusTotalAdapter();

      const mal = adapter.normalizeResponse({
        data: {
          attributes: {
            reputation: -50,
            last_analysis_stats: {
              malicious: 18,
              suspicious: 4,
              harmless: 5,
              undetected: 45,
            },
          },
        },
      });
      assert.equal(mal.status, 'SUCCESS');
      assert.equal(mal.verdict, 'MALICIOUS');
      assert.equal(mal.detectionCount, 18);
      assert.equal(mal.totalEngines, 72);

      const clean = adapter.normalizeResponse({
        data: {
          attributes: {
            reputation: 10,
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              harmless: 65,
              undetected: 5,
            },
          },
        },
      });
      assert.equal(clean.verdict, 'BENIGN');
    });

    it('AlienVault OTX adapter normalizes pulses into verdicts', () => {
      const adapter = new AlienVaultOtxAdapter();

      const mal = adapter.normalizeResponse({
        indicator: 'malware-c2.net',
        pulse_info: {
          count: 7,
          pulses: [{ name: 'Cobalt Strike Campaign', created: '2026-01-01' }],
        },
      });
      assert.equal(mal.status, 'SUCCESS');
      assert.equal(mal.verdict, 'MALICIOUS');
      assert.equal(mal.detectionCount, 7);
    });
  });

  // ── 3. Authentication & RBAC Integration Tests ─────────────────────────────

  describe('Authentication & RBAC Enforcement', () => {
    it('rejects unauthenticated requests to /api/threat-intel/iocs with 401', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs`);
      assert.equal(res.status, 401);
      const body = await res.json();
      assert.equal(body.success, false);
    });

    it('rejects invalid Bearer JWT with 401', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
        headers: { Authorization: 'Bearer invalid.token.value' },
      });
      assert.equal(res.status, 401);
    });

    it('allows VIEWER to list IOCs and fetch stats', async () => {
      const resList = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(resList.status, 200);
      const bodyList = await resList.json();
      assert.equal(bodyList.success, true);
      assert.ok(Array.isArray(bodyList.data));

      const resStats = await fetch(`${baseUrl}/api/threat-intel/stats`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(resStats.status, 200);
      const bodyStats = await resStats.json();
      assert.equal(bodyStats.success, true);
      assert.ok(bodyStats.data.total >= 3);
    });

    it('blocks VIEWER from creating an IOC with 403', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${viewerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'IP',
          value: '198.51.100.55',
          description: 'Blocked test',
        }),
      });
      assert.equal(res.status, 403);
    });

    it('blocks VIEWER from updating an IOC with 403', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/00000000-0000-0000-0000-000000000000`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${viewerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ description: 'Blocked update' }),
      });
      assert.equal(res.status, 403);
    });

    it('blocks VIEWER from triggering provider lookups with 403', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/00000000-0000-0000-0000-000000000000/lookup`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(res.status, 403);
    });

    it('blocks ANALYST from deleting an IOC with 403 (ADMIN only)', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/00000000-0000-0000-0000-000000000000`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.equal(res.status, 403);
    });
  });

  // ── 4. IOC Lifecycle & CRUD Integration Tests ──────────────────────────────

  describe('IOC Lifecycle: Registration, Details, Update, and Deletion', () => {
    let testIocId;

    it('allows ANALYST to register a valid new IP indicator with 201', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'IP_ADDRESS',
          value: '  192.0.2.145  ',
          severity: 'HIGH',
          confidence: 85,
          source: 'Internal Threat Hunt',
          description: 'Observed scanning internal gateway',
        }),
      });

      assert.equal(res.status, 201);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.type, 'IP');
      assert.equal(body.data.value, '192.0.2.145'); // Normalized trim
      assert.equal(body.data.severity, 'HIGH');
      assert.equal(body.data.confidence, 85);

      testIocId = body.data.id;
      createdIocIds.push(testIocId);

      // Verify Audit Log entry
      const audit = await prisma.auditLog.findFirst({
        where: {
          targetType: 'ThreatIndicator',
          targetId: testIocId,
          action: 'IOC_CREATE',
        },
      });
      assert.ok(audit, 'AuditLog entry must be created on IOC registration');
      assert.equal(audit.userId, analystUser.id);
    });

    it('rejects duplicate indicator value with 409 Conflict', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'IP',
          value: '192.0.2.145',
          description: 'Duplicate registration attempt',
        }),
      });

      assert.equal(res.status, 409);
      const body = await res.json();
      assert.equal(body.success, false);
      assert.match(body.error, /already registered/i);
    });

    it('rejects invalid indicator values with 400 Bad Request', async () => {
      // Invalid IP
      const res1 = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'IP',
          value: 'not-an-ip-address',
        }),
      });
      assert.equal(res1.status, 400);

      // Confidence out of bounds
      const res2 = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'DOMAIN',
          value: 'evil.example.com',
          confidence: 150,
        }),
      });
      assert.equal(res2.status, 400);
      const b2 = await res2.json();
      assert.match(b2.error, /confidence/i);
    });

    it('fetches indicator details with audit logs and correlation', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${testIocId}`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.id, testIocId);
      assert.ok(Array.isArray(body.data.auditLogs));
      assert.ok(body.data.correlations !== undefined);
    });

    it('allows ANALYST to update indicator metadata with 200', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${testIocId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          severity: 'CRITICAL',
          confidence: 99,
          description: 'Updated investigation note: confirmed active threat',
          status: 'INACTIVE',
        }),
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.severity, 'CRITICAL');
      assert.equal(body.data.confidence, 99);
      assert.equal(body.data.status, 'INACTIVE');

      // Verify Audit Log
      const audit = await prisma.auditLog.findFirst({
        where: {
          targetType: 'ThreatIndicator',
          targetId: testIocId,
          action: 'IOC_STATUS_CHANGE',
        },
      });
      assert.ok(audit, 'AuditLog status change must be recorded');
    });

    it('blocks attempting to mutate indicator value via PATCH with 400', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${testIocId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ value: '192.0.2.200' }),
      });
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.match(body.error, /immutable|cannot be modified/i);
    });

    it('allows ADMIN to permanently delete an indicator with 200', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${testIocId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);

      // Verify removed from database
      const check = await prisma.threatIndicator.findUnique({ where: { id: testIocId } });
      assert.equal(check, null);

      // Verify deletion audit record
      const audit = await prisma.auditLog.findFirst({
        where: {
          targetType: 'ThreatIndicator',
          targetId: testIocId,
          action: 'IOC_DELETE',
        },
      });
      assert.ok(audit, 'AuditLog entry for IOC_DELETE must exist');
    });
  });

  // ── 5. Provider Lookup, Persistence & Caching ──────────────────────────────

  describe('Threat Provider Lookups & Caching', () => {
    let lookupIoc;

    before(async () => {
      process.env.THREAT_INTEL_USE_MOCK = 'true';

      // Use upsert so existing seed indicator 198.51.100.23 is safely utilized
      lookupIoc = await prisma.threatIndicator.upsert({
        where: { value: '198.51.100.23' },
        update: {},
        create: {
          type: 'IP',
          value: '198.51.100.23', // Matches cobalt strike indicator in mock
          status: 'ACTIVE',
          severity: 'MEDIUM',
          confidence: 80,
          source: 'ThreatHunt',
        },
      });
      createdIocIds.push(lookupIoc.id);
    });

    after(() => {
      delete process.env.THREAT_INTEL_USE_MOCK;
    });

    it('returns NOT_CONFIGURED when querying unconfigured real provider without fake verdicts', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${lookupIoc.id}/lookup`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ provider: 'ABUSEIPDB', forceRefresh: true }),
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.data.status, 'NOT_CONFIGURED');
      assert.equal(body.data.verdict, null);
      assert.match(body.data.errorMessage, /not configured/i);
    });

    it('performs threat intelligence lookup, persists enrichment, and logs audit', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${lookupIoc.id}/lookup`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ provider: 'MOCK_THREAT_INTEL', forceRefresh: true }),
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.cached, false);
      assert.ok(body.data.id);
      assert.equal(body.data.indicatorId, lookupIoc.id);

      // Verify saved in PostgreSQL
      const saved = await prisma.iocEnrichment.findUnique({ where: { id: body.data.id } });
      assert.ok(saved);
      assert.equal(saved.status, 'SUCCESS');

      // Verify Audit Log
      const audit = await prisma.auditLog.findFirst({
        where: {
          targetType: 'ThreatIndicator',
          targetId: lookupIoc.id,
          action: 'IOC_LOOKUP',
        },
      });
      assert.ok(audit, 'AuditLog must record IOC_LOOKUP');
    });

    it('returns cached observation without hitting external provider when within TTL', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${lookupIoc.id}/lookup`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ provider: 'MOCK_THREAT_INTEL', forceRefresh: false }),
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.equal(body.cached, true);
      assert.match(body.message, /cached observation/i);
    });

    it('returns enrichment history for indicator', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${lookupIoc.id}/enrichment-history`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(Array.isArray(body.data));
      assert.ok(body.data.length >= 1);
    });
  });

  // ── 6. Correlation with Assets, Events, and Alerts ──────────────────────────

  describe('Asset & Event Correlation', () => {
    let correlatedIoc;

    before(async () => {
      // Create indicator matching seed asset DC-01 (10.0.0.1)
      correlatedIoc = await prisma.threatIndicator.upsert({
        where: { value: '10.0.0.1' },
        update: {},
        create: {
          type: 'IP',
          value: '10.0.0.1',
          status: 'ACTIVE',
          severity: 'HIGH',
          source: 'Internal Probe',
        },
      });
      createdIocIds.push(correlatedIoc.id);
    });

    it('correlates IP indicator with existing monitored asset DC-01', async () => {
      const res = await fetch(`${baseUrl}/api/threat-intel/iocs/${correlatedIoc.id}/correlation`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });

      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.success, true);
      assert.ok(Array.isArray(body.data.assets));
      const matched = body.data.assets.find((a) => a.name === 'DC-01');
      assert.ok(matched, 'Must match monitored asset DC-01 by IP address');
      assert.match(matched.matchReason, /matches indicator/i);
    });
  });
});
