import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import {
  createSourceEventKey,
  isDuplicateAgentEvent,
  validateAgentLogBatch,
} from '../src/modules/collectors/collectors.controller.js';

let server;
let baseUrl;

describe('Collector authentication and event identity', () => {
  before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        baseUrl = `http://127.0.0.1:${server.address().port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
  });

  it('rejects collector ingestion without an agent credential before database access', async () => {
    const response = await fetch(`${baseUrl}/api/collectors/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs: [{}] }),
    });
    assert.equal(response.status, 401);
    assert.match((await response.json()).error, /Agent authentication required/);
  });

  it('uses stable machine and event identity rather than a replaceable token name', () => {
    const item = {
      source: 'Security',
      hostname: 'WS-01',
      eventRecordId: '8421',
      timeCreated: '2026-10-27T10:00:00Z',
      provider: 'Microsoft-Windows-Security-Auditing',
      eventId: 4625,
    };
    const first = createSourceEventKey('agent-old-token', item);
    assert.equal(createSourceEventKey('agent-new-token', item), first);
    assert.notEqual(createSourceEventKey('agent-old-token', { ...item, eventRecordId: '8422' }), first);
  });

  it('rejects invalid channel, event ID, timestamp, and detail payloads', () => {
    const valid = {
      source: 'Security',
      content: '<Event />',
      eventId: 4625,
      eventRecordId: '8421',
      timeCreated: '2026-10-27T10:00:00Z',
      details: { TargetUserName: 'analyst' },
    };
    assert.equal(validateAgentLogBatch([valid]), null);
    assert.match(validateAgentLogBatch([{ ...valid, source: 'Other' }]).error, /unsupported channel/);
    assert.match(validateAgentLogBatch([{ ...valid, eventId: '4625' }]).error, /invalid eventId/);
    assert.match(validateAgentLogBatch([{ ...valid, timeCreated: 'invalid' }]).error, /invalid timeCreated/);
    assert.match(validateAgentLogBatch([{ ...valid, details: [] }]).error, /invalid details/);
    assert.equal(validateAgentLogBatch([{ ...valid, content: 'x'.repeat(128_001) }]).status, 413);
  });

  it('acknowledges a repeated source event only once under the same advisory lock', async () => {
    const item = {
      source: 'System',
      hostname: 'WS-01',
      eventRecordId: '293537',
      timeCreated: '2026-10-27T11:56:49Z',
      provider: 'Netwtw14',
      eventId: 6062,
    };
    const key = createSourceEventKey('agent-01', item);
    const storedKeys = new Set();
    const lockKeys = [];
    const transaction = {
      $queryRaw: async (_query, lockKey) => { lockKeys.push(lockKey); },
      event: {
        findFirst: async ({ where }) => storedKeys.has(where.metadata.equals) ? { id: 'existing-event' } : null,
      },
    };

    assert.equal(await isDuplicateAgentEvent(transaction, key), false);
    storedKeys.add(key);
    assert.equal(await isDuplicateAgentEvent(transaction, key), true);
    assert.equal(lockKeys.length, 2);
    assert.equal(lockKeys[0], lockKeys[1]);
  });
});