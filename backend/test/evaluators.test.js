// test/evaluators.test.js
// Unit tests for Phase 4 Step 2A — Pure Detection Evaluators.
// Uses Node 22 native test runner (node:test). No database access required.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { evaluate as evaluateSshBruteForce } from '../src/detection/evaluators/sshBruteForce.js';
import { evaluate as evaluatePortScan } from '../src/detection/evaluators/portScan.js';
import { evaluate as evaluateSuspiciousIp } from '../src/detection/evaluators/suspiciousIp.js';
import { evaluate as evaluateSuspiciousAccess } from '../src/detection/evaluators/suspiciousAccess.js';
import { evaluate as evaluateWindowsFailedLogon } from '../src/detection/evaluators/windowsFailedLogon.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Creates a minimal event-like object for testing. */
function makeEvent(overrides = {}) {
  return {
    id: overrides.id ?? crypto.randomUUID(),
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    eventType: overrides.eventType ?? 'unknown',
    srcIp: overrides.srcIp ?? null,
    dstIp: overrides.dstIp ?? null,
    srcPort: overrides.srcPort ?? null,
    dstPort: overrides.dstPort ?? null,
    username: overrides.username ?? null,
    hostname: overrides.hostname ?? null,
    message: overrides.message ?? null,
    severity: overrides.severity ?? 'LOW',
    metadata: overrides.metadata ?? null,
  };
}

/** Creates N ssh_login_failed events within a time span. */
function makeSshFailedBurst(count, srcIp, username, startMs, intervalMs) {
  return Array.from({ length: count }, (_, i) =>
    makeEvent({
      eventType: 'ssh_login_failed',
      srcIp,
      username,
      timestamp: new Date(startMs + i * intervalMs).toISOString(),
    })
  );
}

/** Creates N connection_attempt events with sequential dstPorts. */
function makePortScanBurst(count, srcIp, startMs, intervalMs, startPort = 1000) {
  return Array.from({ length: count }, (_, i) =>
    makeEvent({
      eventType: 'connection_attempt',
      srcIp,
      dstPort: startPort + i,
      timestamp: new Date(startMs + i * intervalMs).toISOString(),
    })
  );
}

// Default rule configs matching seed data
const sshBruteForceRule = {
  id: 'rule-ssh',
  type: 'SSH_BRUTE_FORCE',
  config: { threshold: 5, windowSeconds: 60, eventType: 'ssh_login_failed' },
};

const portScanRule = {
  id: 'rule-port',
  type: 'PORT_SCAN',
  config: { portThreshold: 15, windowSeconds: 120, eventType: 'connection_attempt' },
};

const suspiciousIpRule = {
  id: 'rule-ip',
  type: 'SUSPICIOUS_IP',
  config: { matchSource: true, matchDestination: true },
};

const suspiciousAccessRule = {
  id: 'rule-access',
  type: 'SUSPICIOUS_ACCESS',
  config: {
    allowedHoursStart: 6,
    allowedHoursEnd: 22,
    alertOnWeekend: true,
    targetRole: 'ADMIN',
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// SSH Brute Force Evaluator
// ═══════════════════════════════════════════════════════════════════════════

describe('SSH Brute Force Evaluator', () => {
  it('detects exactly 5 failures within 60s window', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = makeSshFailedBurst(5, '192.168.1.100', 'admin', baseMs, 10_000);
    const matches = evaluateSshBruteForce(events, sshBruteForceRule);

    assert.equal(matches.length, 1);
    assert.equal(matches[0].triggeringEvents.length, 5);
    assert.equal(matches[0].metadata.srcIp, '192.168.1.100');
    assert.equal(matches[0].metadata.username, 'admin');
  });

  it('does NOT fire with only 4 failures (below threshold)', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = makeSshFailedBurst(4, '192.168.1.100', 'admin', baseMs, 10_000);
    const matches = evaluateSshBruteForce(events, sshBruteForceRule);

    assert.equal(matches.length, 0);
  });

  it('does NOT fire when 5 failures are spread over > 60s', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    // 5 events spaced 20s apart → last event at T+80s → span exceeds 60s window
    const events = makeSshFailedBurst(5, '192.168.1.100', 'admin', baseMs, 20_000);
    const matches = evaluateSshBruteForce(events, sshBruteForceRule);

    assert.equal(matches.length, 0);
  });

  it('fires when the 5th failure lands exactly on the window boundary', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    // 5 events spaced exactly 15s apart → last at T+60s → inclusive boundary
    const events = makeSshFailedBurst(5, '192.168.1.100', 'admin', baseMs, 15_000);
    const matches = evaluateSshBruteForce(events, sshBruteForceRule);

    assert.equal(matches.length, 1);
    assert.equal(matches[0].triggeringEvents.length, 5);
  });

  it('keeps groups separate — different usernames do NOT cross-contaminate', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const eventsUser1 = makeSshFailedBurst(3, '192.168.1.100', 'alice', baseMs, 5_000);
    const eventsUser2 = makeSshFailedBurst(3, '192.168.1.100', 'bob', baseMs, 5_000);
    const combined = [...eventsUser1, ...eventsUser2];

    const matches = evaluateSshBruteForce(combined, sshBruteForceRule);
    assert.equal(matches.length, 0, 'Each username group has only 3 — should not fire');
  });

  it('keeps groups separate — different srcIps do NOT cross-contaminate', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const eventsIp1 = makeSshFailedBurst(3, '10.0.0.1', 'admin', baseMs, 5_000);
    const eventsIp2 = makeSshFailedBurst(3, '10.0.0.2', 'admin', baseMs, 5_000);
    const combined = [...eventsIp1, ...eventsIp2];

    const matches = evaluateSshBruteForce(combined, sshBruteForceRule);
    assert.equal(matches.length, 0);
  });

  it('ignores events with null srcIp or null username', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = [
      ...makeSshFailedBurst(3, '10.0.0.1', 'admin', baseMs, 5_000),
      makeEvent({ eventType: 'ssh_login_failed', srcIp: null, username: 'admin', timestamp: new Date(baseMs + 15_000).toISOString() }),
      makeEvent({ eventType: 'ssh_login_failed', srcIp: '10.0.0.1', username: null, timestamp: new Date(baseMs + 20_000).toISOString() }),
    ];

    const matches = evaluateSshBruteForce(events, sshBruteForceRule);
    assert.equal(matches.length, 0, 'Only 3 valid events for (10.0.0.1, admin)');
  });

  it('ignores non-ssh_login_failed event types', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = [
      ...makeSshFailedBurst(4, '10.0.0.1', 'admin', baseMs, 5_000),
      makeEvent({ eventType: 'ssh_login_success', srcIp: '10.0.0.1', username: 'admin', timestamp: new Date(baseMs + 20_000).toISOString() }),
    ];

    const matches = evaluateSshBruteForce(events, sshBruteForceRule);
    assert.equal(matches.length, 0, 'Only 4 ssh_login_failed events — success event is excluded');
  });

  it('returns empty matches for empty events array', () => {
    const matches = evaluateSshBruteForce([], sshBruteForceRule);
    assert.equal(matches.length, 0);
  });

  it('works with a custom threshold and windowSeconds', () => {
    const customRule = {
      ...sshBruteForceRule,
      config: { threshold: 3, windowSeconds: 30, eventType: 'ssh_login_failed' },
    };
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = makeSshFailedBurst(3, '10.0.0.5', 'root', baseMs, 10_000);
    const matches = evaluateSshBruteForce(events, customRule);

    assert.equal(matches.length, 1);
    assert.equal(matches[0].metadata.count, 3);
  });

  it('produces a dedup key containing srcIp and username', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = makeSshFailedBurst(5, '172.16.0.1', 'root', baseMs, 5_000);
    const matches = evaluateSshBruteForce(events, sshBruteForceRule);

    assert.equal(matches.length, 1);
    assert.ok(matches[0].dedupKey.includes('172.16.0.1'));
    assert.ok(matches[0].dedupKey.includes('root'));
    assert.ok(matches[0].dedupKey.startsWith('ssh_brute_force::'));
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Port Scan Evaluator
// ═══════════════════════════════════════════════════════════════════════════

describe('Port Scan Evaluator', () => {
  it('detects 15 distinct ports from one IP within 120s', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = makePortScanBurst(15, '10.0.0.99', baseMs, 5_000);
    const matches = evaluatePortScan(events, portScanRule);

    assert.equal(matches.length, 1);
    assert.equal(matches[0].metadata.distinctPortCount, 15);
    assert.equal(matches[0].metadata.srcIp, '10.0.0.99');
  });

  it('does NOT fire with 14 distinct ports (below threshold)', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = makePortScanBurst(14, '10.0.0.99', baseMs, 5_000);
    const matches = evaluatePortScan(events, portScanRule);

    assert.equal(matches.length, 0);
  });

  it('does NOT count duplicate ports as distinct', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    // 10 distinct ports + 5 duplicates of port 1000
    const events = [
      ...makePortScanBurst(10, '10.0.0.99', baseMs, 5_000, 1000),
      ...Array.from({ length: 5 }, (_, i) =>
        makeEvent({
          eventType: 'connection_attempt',
          srcIp: '10.0.0.99',
          dstPort: 1000, // duplicate
          timestamp: new Date(baseMs + (10 + i) * 5_000).toISOString(),
        })
      ),
    ];

    const matches = evaluatePortScan(events, portScanRule);
    assert.equal(matches.length, 0, 'Only 10 distinct ports, not 15');
  });

  it('does NOT fire when events span beyond the time window', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    // 15 events spaced 10s apart → last at T+140s, exceeds 120s window
    const events = makePortScanBurst(15, '10.0.0.99', baseMs, 10_000);
    const matches = evaluatePortScan(events, portScanRule);

    assert.equal(matches.length, 0);
  });

  it('keeps different source IPs separate', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const eventsIp1 = makePortScanBurst(10, '10.0.0.1', baseMs, 2_000, 1000);
    const eventsIp2 = makePortScanBurst(10, '10.0.0.2', baseMs, 2_000, 2000);
    const combined = [...eventsIp1, ...eventsIp2];

    const matches = evaluatePortScan(combined, portScanRule);
    assert.equal(matches.length, 0, 'Neither IP reaches 15 distinct ports');
  });

  it('ignores events with null dstPort', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = [
      ...makePortScanBurst(14, '10.0.0.99', baseMs, 2_000),
      makeEvent({
        eventType: 'connection_attempt',
        srcIp: '10.0.0.99',
        dstPort: null,
        timestamp: new Date(baseMs + 28_000).toISOString(),
      }),
    ];

    const matches = evaluatePortScan(events, portScanRule);
    assert.equal(matches.length, 0, 'Null dstPort event is excluded');
  });

  it('returns empty for empty events array', () => {
    const matches = evaluatePortScan([], portScanRule);
    assert.equal(matches.length, 0);
  });

  it('fires on the exact window boundary', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    // 15 events: first at T+0, last at T+120s exactly → inclusive boundary
    const events = Array.from({ length: 15 }, (_, i) =>
      makeEvent({
        eventType: 'connection_attempt',
        srcIp: '10.0.0.88',
        dstPort: 3000 + i,
        timestamp: new Date(baseMs + i * (120_000 / 14)).toISOString(),
      })
    );

    const matches = evaluatePortScan(events, portScanRule);
    assert.equal(matches.length, 1);
  });

  it('produces a dedup key containing srcIp', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    const events = makePortScanBurst(15, '172.16.0.50', baseMs, 2_000);
    const matches = evaluatePortScan(events, portScanRule);

    assert.equal(matches.length, 1);
    assert.ok(matches[0].dedupKey.includes('172.16.0.50'));
    assert.ok(matches[0].dedupKey.startsWith('port_scan::'));
  });

  it('regression: detects port scan from parser-produced network_connection events', () => {
    const baseMs = Date.parse('2026-10-24T10:00:00Z');
    // Parser outputs network_connection for firewall logs, while rule config specifies connection_attempt
    const events = Array.from({ length: 15 }, (_, i) =>
      makeEvent({
        eventType: 'network_connection', // Event type produced by logParser for firewall logs
        srcIp: '10.0.0.77',
        dstPort: 4000 + i,
        timestamp: new Date(baseMs + i * 2_000).toISOString(),
      })
    );

    const matches = evaluatePortScan(events, portScanRule);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].metadata.distinctPortCount, 15);
    assert.equal(matches[0].metadata.srcIp, '10.0.0.77');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Suspicious IP Evaluator
// ═══════════════════════════════════════════════════════════════════════════

describe('Suspicious IP Evaluator', () => {
  const indicators = [
    { type: 'IP', value: '198.51.100.23', confidence: 95, source: 'AlienVault OTX' },
    { type: 'IP', value: '203.0.113.88', confidence: 90, source: 'AbuseIPDB' },
    { type: 'DOMAIN', value: 'evil.example.com', confidence: 85, source: 'Test' }, // non-IP, should be ignored
  ];

  it('flags event with matching srcIp', () => {
    const events = [
      makeEvent({ srcIp: '198.51.100.23', eventType: 'ssh_login_failed' }),
    ];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, { indicators });

    assert.equal(matches.length, 1);
    assert.equal(matches[0].triggeringEvents.length, 1);
    const matched = matches[0].metadata.matchedIndicators;
    assert.equal(matched.length, 1);
    assert.equal(matched[0].field, 'srcIp');
    assert.equal(matched[0].ip, '198.51.100.23');
  });

  it('flags event with matching dstIp', () => {
    const events = [
      makeEvent({ dstIp: '203.0.113.88', eventType: 'network_connection' }),
    ];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, { indicators });

    assert.equal(matches.length, 1);
    assert.equal(matches[0].metadata.matchedIndicators[0].field, 'dstIp');
  });

  it('flags both srcIp and dstIp in the same event when both match', () => {
    const events = [
      makeEvent({ srcIp: '198.51.100.23', dstIp: '203.0.113.88', eventType: 'connection_attempt' }),
    ];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, { indicators });

    assert.equal(matches.length, 1);
    assert.equal(matches[0].metadata.matchedIndicators.length, 2);
  });

  it('does NOT flag events with benign IPs', () => {
    const events = [
      makeEvent({ srcIp: '10.0.0.1', dstIp: '192.168.1.1', eventType: 'ssh_login_success' }),
    ];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, { indicators });

    assert.equal(matches.length, 0);
  });

  it('respects matchSource=false config', () => {
    const rule = { ...suspiciousIpRule, config: { matchSource: false, matchDestination: true } };
    const events = [
      makeEvent({ srcIp: '198.51.100.23', eventType: 'ssh_login_failed' }),
    ];
    const matches = evaluateSuspiciousIp(events, rule, { indicators });

    assert.equal(matches.length, 0, 'matchSource is false, srcIp match should be ignored');
  });

  it('respects matchDestination=false config', () => {
    const rule = { ...suspiciousIpRule, config: { matchSource: true, matchDestination: false } };
    const events = [
      makeEvent({ dstIp: '203.0.113.88', eventType: 'network_connection' }),
    ];
    const matches = evaluateSuspiciousIp(events, rule, { indicators });

    assert.equal(matches.length, 0, 'matchDestination is false, dstIp match should be ignored');
  });

  it('ignores DOMAIN-type indicators (only matches IP type)', () => {
    const events = [
      makeEvent({ srcIp: 'evil.example.com', eventType: 'dns_query' }),
    ];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, { indicators });

    assert.equal(matches.length, 0);
  });

  it('returns empty when no indicators are provided', () => {
    const events = [
      makeEvent({ srcIp: '198.51.100.23', eventType: 'ssh_login_failed' }),
    ];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, { indicators: [] });

    assert.equal(matches.length, 0);
  });

  it('returns empty for empty events array', () => {
    const matches = evaluateSuspiciousIp([], suspiciousIpRule, { indicators });
    assert.equal(matches.length, 0);
  });

  it('handles null/undefined context gracefully', () => {
    const events = [makeEvent({ srcIp: '198.51.100.23' })];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, null);
    assert.equal(matches.length, 0);

    const matches2 = evaluateSuspiciousIp(events, suspiciousIpRule, undefined);
    assert.equal(matches2.length, 0);
  });

  it('includes indicator details in metadata', () => {
    const events = [
      makeEvent({ srcIp: '198.51.100.23', eventType: 'ssh_login_failed' }),
    ];
    const matches = evaluateSuspiciousIp(events, suspiciousIpRule, { indicators });

    assert.equal(matches[0].metadata.matchedIndicators[0].indicator.confidence, 95);
    assert.equal(matches[0].metadata.matchedIndicators[0].indicator.source, 'AlienVault OTX');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Suspicious Access Evaluator
// ═══════════════════════════════════════════════════════════════════════════

describe('Suspicious Access Evaluator', () => {
  const adminUsernames = ['admin', 'root'];

  it('flags admin login at 3 AM UTC (outside allowed hours 6-22)', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-22T03:00:00Z', // Thursday 3 AM UTC
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 1);
    assert.ok(matches[0].metadata.isOutsideHours);
    assert.equal(matches[0].metadata.isWeekend, false);
  });

  it('flags admin login at 23:00 UTC (past allowedHoursEnd of 22)', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'root',
        timestamp: '2026-10-22T23:30:00Z', // Thursday 11:30 PM UTC
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 1);
    assert.ok(matches[0].metadata.isOutsideHours);
  });

  it('flags admin login on Saturday within allowed hours (weekend alert)', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-24T10:00:00Z', // Saturday 10 AM UTC
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 1);
    assert.ok(matches[0].metadata.isWeekend);
    assert.equal(matches[0].metadata.isOutsideHours, false);
  });

  it('flags admin login on Sunday at 2 AM (both weekend AND outside hours)', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-25T02:00:00Z', // Sunday 2 AM UTC
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 1);
    assert.ok(matches[0].metadata.isOutsideHours);
    assert.ok(matches[0].metadata.isWeekend);
    assert.equal(matches[0].metadata.reasons.length, 2);
  });

  it('does NOT flag admin login on weekday within allowed hours', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-22T14:00:00Z', // Thursday 2 PM UTC
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 0);
  });

  it('does NOT flag non-admin usernames', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'analyst',
        timestamp: '2026-10-25T02:00:00Z', // Sunday 2 AM UTC — would trigger for admin
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 0, 'analyst is not in adminUsernames');
  });

  it('does NOT flag failed logins (only success)', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_failed', // not success
        username: 'admin',
        timestamp: '2026-10-25T02:00:00Z',
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 0);
  });

  it('handles case-insensitive admin username matching', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'Admin', // uppercase A
        timestamp: '2026-10-25T02:00:00Z',
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 1);
  });

  it('does NOT flag when alertOnWeekend is false and login is on weekend within hours', () => {
    const rule = {
      ...suspiciousAccessRule,
      config: { ...suspiciousAccessRule.config, alertOnWeekend: false },
    };
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-24T10:00:00Z', // Saturday 10 AM UTC — within hours
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, rule, { adminUsernames });

    assert.equal(matches.length, 0, 'Weekend alerting is disabled and time is within hours');
  });

  it('returns empty when no admin usernames are provided', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-25T02:00:00Z',
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames: [] });

    assert.equal(matches.length, 0);
  });

  it('handles null context gracefully', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-25T02:00:00Z',
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, null);
    assert.equal(matches.length, 0);
  });

  it('returns empty for empty events array', () => {
    const matches = evaluateSuspiciousAccess([], suspiciousAccessRule, { adminUsernames });
    assert.equal(matches.length, 0);
  });

  it('fires at hour boundary: 5:59 UTC triggers, 6:00 UTC does not', () => {
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-22T05:59:59Z', // Thursday, hour=5 → outside
      }),
      makeEvent({
        eventType: 'ssh_login_success',
        username: 'admin',
        timestamp: '2026-10-22T06:00:00Z', // Thursday, hour=6 → inside
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 1, 'Only the 5:59 event should fire');
    assert.equal(matches[0].metadata.utcHour, 5);
  });

  it('produces a dedup key containing username and event id', () => {
    const events = [
      makeEvent({
        id: 'evt-1234',
        eventType: 'ssh_login_success',
        username: 'root',
        timestamp: '2026-10-25T02:00:00Z',
      }),
    ];
    const matches = evaluateSuspiciousAccess(events, suspiciousAccessRule, { adminUsernames });

    assert.equal(matches.length, 1);
    assert.ok(matches[0].dedupKey.includes('root'));
    assert.ok(matches[0].dedupKey.includes('evt-1234'));
    assert.ok(matches[0].dedupKey.startsWith('suspicious_access::'));
  });
});

describe('Windows Failed Logon Evaluator', () => {
  const rule = { config: { threshold: 3, windowSeconds: 300 } };

  it('detects repeated 4625-normalized events and retains evidence', () => {
    const start = Date.parse('2026-10-27T10:00:00Z');
    const events = Array.from({ length: 3 }, (_, index) => makeEvent({
      id: `windows-${index}`,
      eventType: 'windows_failed_logon',
      hostname: 'WS-01',
      username: 'analyst',
      srcIp: null,
      timestamp: new Date(start + index * 30_000).toISOString(),
    }));

    const matches = evaluateWindowsFailedLogon(events, rule);

    assert.equal(matches.length, 1);
    assert.equal(matches[0].triggeringEvents.length, 3);
    assert.equal(matches[0].metadata.hostname, 'WS-01');
    assert.equal(matches[0].metadata.srcIp, null);
    assert.equal(matches[0].dedupKey.startsWith('windows_failed_logon::'), true);
  });

  it('does not group missing account data or unrelated event types', () => {
    const events = [
      makeEvent({ eventType: 'windows_failed_logon', hostname: 'WS-01', username: null }),
      makeEvent({ eventType: 'windows_successful_logon', hostname: 'WS-01', username: 'analyst' }),
    ];
    assert.equal(evaluateWindowsFailedLogon(events, rule).length, 0);
  });
});
