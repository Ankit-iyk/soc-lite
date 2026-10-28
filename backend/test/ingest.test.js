// test/ingest.test.js
// Automated test suite for Log Ingestion & Parser (Phase 3 Step 2).
// Uses Node 22 native test runner (node:test).

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidIp,
  validatePort,
  parseLogTimestamp,
  parseSshAuthLog,
  parseFirewallLog,
  parseJsonLog,
  parseWindowsEventRecord,
  parseGenericFallback,
  normalizeLog,
} from '../src/modules/logs/logParser.js';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';

let server;
let baseUrl;
let analystToken;
let viewerToken;

describe('Phase 3 — Log Parser Unit Tests', () => {
  it('Validates IPv4 and IPv6 correctly', () => {
    assert.equal(isValidIp('192.168.1.1'), true);
    assert.equal(isValidIp('10.0.0.1'), true);
    assert.equal(isValidIp('::1'), true);
    assert.equal(isValidIp('2001:db8::1'), true);

    // Invalid IPs
    assert.equal(isValidIp('999.999.999.999'), false);
    assert.equal(isValidIp('not-an-ip'), false);
    assert.equal(isValidIp(''), false);
    assert.equal(isValidIp(null), false);
  });

  it('Validates TCP/UDP ports within 1-65535 and rejects invalid values', () => {
    assert.equal(validatePort(22), 22);
    assert.equal(validatePort('443'), 443);
    assert.equal(validatePort(65535), 65535);

    // Invalid ports
    assert.equal(validatePort(0), null);
    assert.equal(validatePort(70000), null);
    assert.equal(validatePort(-1), null);
    assert.equal(validatePort('abc'), null);
    assert.equal(validatePort(null), null);
  });

  it('Parses syslog timestamps and handles year-rollover edge case', () => {
    const ref = new Date('2026-10-24T12:00:00Z');
    const parsed = parseLogTimestamp('Oct 24 10:15:32', ref);
    assert.equal(parsed.getMonth(), 9); // October = 9 (0-indexed)
    assert.equal(parsed.getDate(), 24);
    assert.equal(parsed.getHours(), 10);
    assert.equal(parsed.getMinutes(), 15);
    assert.equal(parsed.getSeconds(), 32);

    // Year rollover test: reading Dec logs in Jan
    const janRef = new Date('2026-01-05T00:00:00Z');
    const decParsed = parseLogTimestamp('Dec 30 23:59:00', janRef);
    assert.equal(decParsed.getFullYear(), 2025); // Rolled back to previous year
  });

  it('Parses SSH failure log without fabricating dstPort (dstPort must be null)', () => {
    const logLine = 'Oct 24 10:15:32 host-01 sshd[28412]: Failed password for invalid user admin from 198.51.100.23 port 45231 ssh2';
    const res = parseSshAuthLog(logLine);

    assert.ok(res);
    assert.equal(res.eventType, 'ssh_login_failed');
    assert.equal(res.username, 'admin');
    assert.equal(res.srcIp, '198.51.100.23');
    assert.equal(res.srcPort, 45231);
    assert.equal(res.dstPort, null, 'dstPort MUST NOT be fabricated to 22');
    assert.equal(res.hostname, 'host-01');
    assert.equal(res.severity, 'HIGH');
  });

  it('Parses SSH success log correctly', () => {
    const logLine = 'Oct 24 10:16:01 host-01 sshd[28450]: Accepted publickey for analyst from 10.0.0.50 port 51234 ssh2';
    const res = parseSshAuthLog(logLine);

    assert.ok(res);
    assert.equal(res.eventType, 'ssh_login_success');
    assert.equal(res.username, 'analyst');
    assert.equal(res.srcIp, '10.0.0.50');
    assert.equal(res.srcPort, 51234);
    assert.equal(res.dstPort, null);
    assert.equal(res.severity, 'LOW');
  });

  it('Parses network firewall log with null username', () => {
    const logLine = 'FW-EDGE-01 filterlog: BLOCK,IN,4,TCP,203.0.113.88,10.0.0.1,58210,80';
    const res = parseFirewallLog(logLine);

    assert.ok(res);
    assert.equal(res.eventType, 'network_connection');
    assert.equal(res.srcIp, '203.0.113.88');
    assert.equal(res.dstIp, '10.0.0.1');
    assert.equal(res.srcPort, 58210);
    assert.equal(res.dstPort, 80);
    assert.equal(res.username, null, 'Firewall logs must have null username');
    assert.equal(res.severity, 'MEDIUM');
    assert.equal(res.metadata.action, 'BLOCK');
  });

  it('Parses structured JSON log and preserves unmapped keys in metadata', () => {
    const jsonStr = JSON.stringify({
      timestamp: '2026-10-24T10:20:00Z',
      eventType: 'custom_alert',
      srcIp: '10.0.0.15',
      dstPort: 443,
      severity: 'HIGH',
      customDetector: 'WAF-Rule-99',
      ruleScore: 88,
    });

    const res = parseJsonLog(jsonStr);
    assert.ok(res);
    assert.equal(res.eventType, 'custom_alert');
    assert.equal(res.srcIp, '10.0.0.15');
    assert.equal(res.dstPort, 443);
    assert.equal(res.severity, 'HIGH');
    assert.equal(res.metadata.customDetector, 'WAF-Rule-99');
    assert.equal(res.metadata.ruleScore, 88);
  });

  it('Normalizes a Windows 4625 fixture without inventing unavailable fields', () => {
    const record = {
      channel: 'Security',
      provider: 'Microsoft-Windows-Security-Auditing',
      eventId: 4625,
      eventRecordId: '8421',
      timeCreated: '2026-10-27T10:00:00Z',
      hostname: 'WS-01',
      details: {
        TargetUserName: 'analyst',
        IpAddress: '192.0.2.9',
        IpPort: '51422',
        Status: '0xc000006d',
      },
    };

    const result = parseWindowsEventRecord(record);

    assert.equal(result.eventType, 'windows_failed_logon');
    assert.equal(result.timestamp.toISOString(), new Date(record.timeCreated).toISOString());
    assert.equal(result.username, 'analyst');
    assert.equal(result.srcIp, '192.0.2.9');
    assert.equal(result.srcPort, 51422);
    assert.equal(result.dstIp, null);
    assert.equal(result.dstPort, null);
    assert.equal(result.hostname, 'WS-01');
    assert.equal(result.severity, 'HIGH');
    assert.equal(result.metadata.channel, 'Security');
    assert.equal(result.metadata.provider, 'Microsoft-Windows-Security-Auditing');
    assert.equal(result.metadata.eventRecordId, '8421');
    assert.equal(result.metadata.details.Status, '0xc000006d');
  });

  it('Normalizes a Windows 4624 fixture and keeps placeholder identity fields null', () => {
    const result = parseWindowsEventRecord({
      channel: 'Security',
      provider: 'Microsoft-Windows-Security-Auditing',
      eventId: 4624,
      eventRecordId: '8422',
      timeCreated: '2026-10-27T10:01:00Z',
      hostname: 'WS-01',
      details: { TargetUserName: '-', IpAddress: '-' },
    });

    assert.equal(result.eventType, 'windows_successful_logon');
    assert.equal(result.username, null);
    assert.equal(result.srcIp, null);
    assert.equal(result.severity, 'LOW');
    assert.equal(result.metadata.eventId, 4624);
  });

  it('Safely handles malformed JSON without crashing or losing data', () => {
    const malformed = '{ invalid json string with syntax error ::: }';
    const res = normalizeLog('json', malformed);

    assert.ok(res);
    assert.equal(res.eventType, 'unknown');
    assert.equal(res.srcIp, null);
    assert.equal(res.metadata.unparsed, true);
  });

  it('Generic fallback parser safely preserves unknown formats', () => {
    const unknownLog = 'RANDOM APPLICATION LOG LINE WITHOUT KNOWN PATTERN';
    const res = parseGenericFallback(unknownLog);

    assert.ok(res);
    assert.equal(res.eventType, 'unknown');
    assert.equal(res.srcIp, null);
    assert.equal(res.dstPort, null);
    assert.equal(res.username, null);
  });
});

describe('Phase 3 — Log Ingestion HTTP Integration Tests', () => {
  before(async () => {
    // Start test server on dynamic port
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });

    // Fetch existing seeded users for token generation
    const analystUser = await prisma.user.findUnique({ where: { email: 'analyst@soclite.local' } });
    const viewerUser = await prisma.user.findUnique({ where: { email: 'viewer@soclite.local' } });

    assert.ok(analystUser, 'Seeded analyst user should exist');
    assert.ok(viewerUser, 'Seeded viewer user should exist');

    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });
    viewerToken = signToken({ userId: viewerUser.id, email: viewerUser.email, role: viewerUser.role });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  it('Rejects unauthenticated POST /api/logs/ingest with 401', async () => {
    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'auth.log', content: 'test log' }),
    });

    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.success, false);
  });

  it('Rejects VIEWER role from ingesting logs with 403 Forbidden', async () => {
    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${viewerToken}`,
      },
      body: JSON.stringify({ source: 'auth.log', content: 'test log' }),
    });

    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /Access denied/);
  });

  it('Validates missing source or content with 400 Bad Request', async () => {
    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ source: '', content: '' }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
  });

  it('Rejects batches exceeding 100 logs with 400 Bad Request', async () => {
    const oversizedBatch = Array.from({ length: 101 }, (_, i) => ({
      source: 'auth.log',
      content: `Log line ${i}`,
    }));

    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ logs: oversizedBatch }),
    });

    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /exceeds maximum limit of 100 logs/);
  });

  it('Ingests single SSH failure log, creates RawLog + Event, and records AuditLog', async () => {
    const rawText = 'Oct 24 10:15:32 host-01 sshd[28412]: Failed password for invalid user admin from 198.51.100.23 port 45231 ssh2';

    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ source: 'auth.log', content: rawText }),
    });

    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.count, 1);

    const createdEvent = body.data.events[0];
    assert.equal(createdEvent.eventType, 'ssh_login_failed');
    assert.equal(createdEvent.srcIp, '198.51.100.23');
    assert.equal(createdEvent.username, 'admin');
    assert.equal(createdEvent.dstPort, null);

    // Verify database persistence and rawLog relation
    const dbEvent = await prisma.event.findUnique({
      where: { id: createdEvent.id },
      include: { rawLog: true },
    });
    assert.ok(dbEvent);
    assert.equal(dbEvent.rawLog.rawContent, rawText);

    // Verify AuditLog record was created in the transaction
    const audit = await prisma.auditLog.findFirst({
      where: { action: 'LOGS_INGESTED' },
      orderBy: { timestamp: 'desc' },
    });
    assert.ok(audit);
    assert.equal(audit.details.count, 1);
  });

  it('Preserves repeated submissions as separate evidence (no silent deduplication)', async () => {
    const rawText = 'Oct 24 10:15:32 host-01 sshd[28412]: Failed password for invalid user admin from 198.51.100.23 port 45231 ssh2';

    // Submit identical log again
    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ source: 'auth.log', content: rawText }),
    });

    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.data.count, 1);

    // Query RawLog for this content — both records must exist
    const matchingLogs = await prisma.rawLog.findMany({
      where: { rawContent: rawText },
    });
    assert.ok(matchingLogs.length >= 2, 'Repeated submissions must be preserved as distinct records');
  });

  it('Ingests batch of mixed logs (SSH + Firewall + JSON + Fallback)', async () => {
    const batch = [
      {
        source: 'auth.log',
        content: 'Oct 24 10:16:01 host-01 sshd[28450]: Accepted publickey for analyst from 10.0.0.50 port 51234 ssh2',
      },
      {
        source: 'firewall',
        content: 'FW-EDGE-01 filterlog: BLOCK,IN,4,TCP,203.0.113.88,10.0.0.1,58210,80',
      },
      {
        source: 'json',
        content: JSON.stringify({
          eventType: 'api_access',
          srcIp: '10.0.0.15',
          dstPort: 443,
          severity: 'LOW',
          message: 'Authenticated request',
        }),
      },
      {
        source: 'custom_daemon',
        content: 'SOME NON_PARSABLE APPLICATION OUTPUT',
      },
    ];

    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ logs: batch }),
    });

    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.data.count, 4);

    const types = body.data.events.map((e) => e.eventType);
    assert.ok(types.includes('ssh_login_success'));
    assert.ok(types.includes('network_connection'));
    assert.ok(types.includes('api_access'));
    assert.ok(types.includes('unknown'));
  });

  it('Queries paginated GET /api/logs with source filter', async () => {
    const res = await fetch(`${baseUrl}/api/logs?page=1&limit=5&source=auth.log`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(Array.isArray(body.data));
    assert.ok(body.pagination.total >= 1);
    assert.equal(body.pagination.page, 1);
  });

  it('Queries paginated GET /api/events with eventType and severity filters', async () => {
    const res = await fetch(`${baseUrl}/api/events?page=1&limit=5&eventType=ssh_login_failed&severity=HIGH`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.data.every((e) => e.eventType === 'ssh_login_failed' && e.severity === 'HIGH'));
  });

  it('Fetches single event via GET /api/events/:id including rawLog', async () => {
    const listRes = await fetch(`${baseUrl}/api/events?limit=1`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    const listBody = await listRes.json();
    const eventId = listBody.data[0].id;

    const detailRes = await fetch(`${baseUrl}/api/events/${eventId}`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });

    assert.equal(detailRes.status, 200);
    const detailBody = await detailRes.json();
    assert.equal(detailBody.success, true);
    assert.equal(detailBody.data.id, eventId);
    assert.ok(detailBody.data.rawLog, 'Event details must include rawLog');
    assert.ok(detailBody.data.rawLog.rawContent);
  });

  it('Returns 404 for non-existent event ID', async () => {
    const res = await fetch(`${baseUrl}/api/events/00000000-0000-0000-0000-000000000000`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });

    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.match(body.error, /Event not found/);
  });
});
