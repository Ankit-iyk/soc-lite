import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  reclaimStaleJobs,
  runAnalysisBatch,
  processClaimedJob,
} from '../src/processing/analysis.worker.js';

describe('durable analysis processing', () => {
  it('reclaims only processing jobs whose lease expired', async () => {
    const now = new Date('2026-10-28T12:00:00Z');
    let updateArgs;
    const client = {
      processingJob: {
        updateMany: async (args) => {
          updateArgs = args;
          return { count: 2 };
        },
      },
    };

    const result = await reclaimStaleJobs(now, client);

    assert.deepEqual(result, { count: 2 });
    assert.equal(updateArgs.where.status, 'PROCESSING');
    assert.equal(updateArgs.where.startedAt.lt.toISOString(), '2026-10-28T11:50:00.000Z');
    assert.equal(updateArgs.data.status, 'PENDING');
    assert.equal(updateArgs.data.availableAt, now);
  });

  it('reclaims stale jobs before claiming pending work', async () => {
    const calls = [];
    const result = await runAnalysisBatch({
      reclaim: async () => calls.push('reclaim'),
      claim: async (limit) => {
        calls.push(['claim', limit]);
        return [];
      },
    });

    assert.deepEqual(result, []);
    assert.deepEqual(calls, ['reclaim', ['claim', 10]]);
  });

  it('retries detection summaries that contain rule errors', async () => {
    const updates = [];
    const prismaModule = await import('../src/config/prisma.js');
    const originalUpdate = prismaModule.default.processingJob.update;
    prismaModule.default.processingJob.update = async (args) => {
      updates.push(args);
      return args;
    };

    try {
      const result = await processClaimedJob(
        { id: 'job-2', eventId: 'event-2', attempts: 0 },
        { runDetection: async () => ({
          rulesEvaluated: 1,
          matchesFound: 0,
          alertsCreated: 0,
          alertsUpdated: 0,
          errors: ['Rule evaluation failed'],
        }) },
      );

      assert.equal(result.status, 'PENDING');
      assert.equal(updates[0].data.status, 'PENDING');
      assert.equal(updates[0].data.lastError, 'Analysis failed; retry scheduled.');
    } finally {
      prismaModule.default.processingJob.update = originalUpdate;
    }
  });

  it('marks exhausted detection failures as failed and schedules bounded retries', async () => {
    const updates = [];
    const prismaModule = await import('../src/config/prisma.js');
    const originalUpdate = prismaModule.default.processingJob.update;
    prismaModule.default.processingJob.update = async (args) => {
      updates.push(args);
      return args;
    };

    try {
      const result = await processClaimedJob(
        { id: 'job-1', eventId: 'event-1', attempts: 4 },
        { runDetection: async () => { throw new Error('detector unavailable'); } },
      );

      assert.equal(result.status, 'FAILED');
      assert.equal(updates.length, 1);
      assert.equal(updates[0].data.status, 'FAILED');
      assert.equal(updates[0].data.failedAt instanceof Date, true);
    } finally {
      prismaModule.default.processingJob.update = originalUpdate;
    }
  });
});
