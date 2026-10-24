// test/scheduler.test.js
// Unit tests for Phase 4 Step 5 — Automated Detection Scheduler.
// Uses Node 22 native test runner (node:test).
//
// These tests are pure unit tests — no real database connection is required.
// All engine functions (runDetection, isDetectionRunning) are replaced with
// simple in-memory stubs through the scheduler's injection seams.
// All timers are driven deterministically via the setIntervalFn/clearIntervalFn
// injection, so no real-time sleeps are used.

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  startDetectionScheduler,
  stopDetectionScheduler,
  isSchedulerRunning,
} from '../src/detection/scheduler.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Creates a fake setInterval / clearInterval pair.
 * Calling `tick()` synchronously fires all pending callbacks once, awaiting
 * any async callback completions.
 */
function makeFakeTimer() {
  const callbacks = new Map(); // id -> fn
  let nextId = 1;

  function fakeSetInterval(fn, _ms) {
    const id = nextId++;
    callbacks.set(id, fn);
    return id;
  }

  function fakeClearInterval(id) {
    callbacks.delete(id);
  }

  /** Fire all registered interval callbacks once and await them. */
  async function tick() {
    for (const fn of [...callbacks.values()]) {
      await fn();
    }
  }

  /** Returns number of active timers. */
  function count() {
    return callbacks.size;
  }

  return { fakeSetInterval, fakeClearInterval, tick, count };
}

/**
 * Creates a tracked stub for runDetection.
 * Returns an object with:
 *   - runStub: async function to pass as runDetectionFn
 *   - stub:    the tracking object (use stub.callCount and stub.calls)
 */
function makeRunStub(overrides = {}) {
  const stub = {
    callCount: 0,
    calls: [],
  };

  async function runStub(opts) {
    stub.callCount++;
    stub.calls.push({ opts, at: Date.now() });
    if (overrides.shouldThrow) {
      throw new Error('Simulated engine failure');
    }
    return {
      rulesEvaluated: 2,
      matchesFound: 0,
      alertsCreated: 0,
      alertsUpdated: 0,
      alerts: [],
      errors: [],
    };
  }

  return { runStub, stub };
}

/** Returns a stub isDetectionRunning function always returning `returnValue`. */
function makeIsRunningStub(returnValue) {
  return () => returnValue;
}

// ── Environment variable cleanup helpers ──────────────────────────────────────

let _savedEnv = {};

function saveEnv(...keys) {
  for (const k of keys) {
    _savedEnv[k] = process.env[k];
  }
}

function restoreEnv(...keys) {
  for (const k of keys) {
    if (_savedEnv[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = _savedEnv[k];
    }
  }
  _savedEnv = {};
}

// ── Test suite ────────────────────────────────────────────────────────────────

describe('Phase 4 Step 5 — Automated Detection Scheduler', () => {
  // Always stop the scheduler and restore env after each test.
  afterEach(() => {
    stopDetectionScheduler(); // safe no-op if not running
    restoreEnv(
      'DETECTION_INTERVAL_MS',
      'DETECTION_WINDOW_MINUTES',
      'DETECTION_SCHEDULER_ENABLED',
      'NODE_ENV'
    );
  });

  // ── Test 1: Scheduler starts with default settings ────────────────────────

  it('starts with default interval and window when no env vars are set', () => {
    saveEnv('DETECTION_INTERVAL_MS', 'DETECTION_WINDOW_MINUTES');
    delete process.env.DETECTION_INTERVAL_MS;
    delete process.env.DETECTION_WINDOW_MINUTES;

    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    const result = startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
    });

    assert.equal(result.intervalMs, 30_000, 'Default interval should be 30000ms');
    assert.equal(result.windowMinutes, 15, 'Default window should be 15 minutes');
    assert.ok(isSchedulerRunning(), 'Scheduler should report as running after start');
    assert.equal(timer.count(), 1, 'Exactly one interval timer should be active');
  });

  // ── Test 2: Configured interval and window are applied ───────────────────

  it('applies DETECTION_INTERVAL_MS and DETECTION_WINDOW_MINUTES from env', () => {
    saveEnv('DETECTION_INTERVAL_MS', 'DETECTION_WINDOW_MINUTES');
    process.env.DETECTION_INTERVAL_MS = '60000';
    process.env.DETECTION_WINDOW_MINUTES = '30';

    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    const result = startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
    });

    assert.equal(result.intervalMs, 60_000);
    assert.equal(result.windowMinutes, 30);
  });

  it('explicit options.intervalMs and options.windowMinutes override env', () => {
    saveEnv('DETECTION_INTERVAL_MS', 'DETECTION_WINDOW_MINUTES');
    process.env.DETECTION_INTERVAL_MS = '60000';
    process.env.DETECTION_WINDOW_MINUTES = '30';

    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    const result = startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 10_000,
      windowMinutes: 5,
    });

    assert.equal(result.intervalMs, 10_000, 'options.intervalMs must override env');
    assert.equal(result.windowMinutes, 5, 'options.windowMinutes must override env');
  });

  // ── Test 3: Scheduled evaluation occurs when interval elapses ────────────

  it('calls runDetection once when the interval timer fires', async () => {
    const timer = makeFakeTimer();
    const { runStub, stub } = makeRunStub();

    startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    });

    assert.equal(stub.callCount, 0, 'No run before tick');

    await timer.tick();

    assert.equal(stub.callCount, 1, 'runDetection must be called after one tick');
  });

  it('calls runDetection on each successive tick', async () => {
    const timer = makeFakeTimer();
    const { runStub, stub } = makeRunStub();

    startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    });

    await timer.tick();
    await timer.tick();
    await timer.tick();

    assert.equal(stub.callCount, 3, 'runDetection must be called on each tick');
  });

  // ── Test 4: Skip-if-busy — slow evaluations do not overlap ───────────────

  it('skips a tick when the engine reports it is already running', async () => {
    const timer = makeFakeTimer();
    const { runStub, stub } = makeRunStub();

    // isRunningFn always returns true — engine is permanently "busy"
    startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(true),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    });

    await timer.tick();
    await timer.tick();

    assert.equal(stub.callCount, 0, 'runDetection must not be called while engine is busy');
  });

  // ── Test 5: Coordination — windowMinutes and userId are passed correctly ──

  it('passes windowMinutes to runDetection so it uses the configured lookback', async () => {
    const timer = makeFakeTimer();
    const { runStub, stub } = makeRunStub();

    startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 45,
    });

    await timer.tick();

    assert.equal(stub.calls.length, 1);
    assert.equal(stub.calls[0].opts.windowMinutes, 45,
      'runDetection must receive the configured windowMinutes');
  });

  it('does not pass userId so scheduled runs do not create AuditLog entries', async () => {
    const timer = makeFakeTimer();
    const { runStub, stub } = makeRunStub();

    startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    });

    await timer.tick();

    assert.equal(stub.calls.length, 1);
    assert.equal(stub.calls[0].opts.userId, undefined,
      'Scheduled runs must not provide a userId (no audit log)');
  });

  // ── Test 6: Engine failure does not cause unhandled rejection ────────────

  it('catches engine failure and allows subsequent ticks to run', async () => {
    const timer = makeFakeTimer();
    let callCount = 0;
    const throwUntilCall = 1; // Throw on first call only

    async function flakyRunFn() {
      callCount++;
      if (callCount <= throwUntilCall) {
        throw new Error('Simulated DB failure');
      }
      return { rulesEvaluated: 1, matchesFound: 0, alertsCreated: 0, alertsUpdated: 0, alerts: [], errors: [] };
    }

    startDetectionScheduler({
      runDetectionFn: flakyRunFn,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    });

    // First tick — engine throws; must NOT produce an unhandled rejection
    await timer.tick();
    assert.equal(callCount, 1, 'First tick must have called runDetection');

    // Second tick — should still execute despite previous failure
    await timer.tick();
    assert.equal(callCount, 2, 'Subsequent ticks must still run after a failure');
  });

  // ── Test 7: stopDetectionScheduler prevents future runs ──────────────────

  it('stops scheduling after stopDetectionScheduler is called', async () => {
    const timer = makeFakeTimer();
    const { runStub, stub } = makeRunStub();

    startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    });

    await timer.tick();
    assert.equal(stub.callCount, 1, 'Should have run once before stop');

    stopDetectionScheduler();
    assert.ok(!isSchedulerRunning(), 'isSchedulerRunning() must be false after stop');
    assert.equal(timer.count(), 0, 'Timer must be cleared after stop');

    // Tick again — no callbacks registered, so runDetection must not be called
    await timer.tick();
    assert.equal(stub.callCount, 1, 'runDetection must not be called after stop');
  });

  // ── Test 8: Repeated start/stop calls do not create duplicate timers ──────

  it('throws if startDetectionScheduler is called while already running', () => {
    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    const opts = {
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    };

    startDetectionScheduler(opts);
    assert.equal(timer.count(), 1, 'One timer active');

    assert.throws(
      () => startDetectionScheduler(opts),
      /already running/i,
      'Second start must throw'
    );

    assert.equal(timer.count(), 1, 'Must still have only one timer after rejected second start');
  });

  it('can be restarted cleanly after stop', async () => {
    const timer = makeFakeTimer();
    const { runStub, stub } = makeRunStub();

    const opts = {
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    };

    startDetectionScheduler(opts);
    await timer.tick();
    assert.equal(stub.callCount, 1);
    stopDetectionScheduler();

    assert.equal(timer.count(), 0, 'Timer cleared after stop');

    // Restart with the same options
    startDetectionScheduler(opts);
    await timer.tick();

    assert.equal(stub.callCount, 2, 'Should have one run per active session');
    assert.equal(timer.count(), 1, 'Only one timer active after restart');

    stopDetectionScheduler(); // clean up — afterEach will also call this (no-op)
  });

  it('stopDetectionScheduler is a no-op when scheduler is not running', () => {
    // Should not throw — multiple calls are safe
    assert.doesNotThrow(() => stopDetectionScheduler());
    assert.doesNotThrow(() => stopDetectionScheduler());
  });

  // ── Test 9: Invalid configuration is handled safely ──────────────────────

  it('rejects DETECTION_INTERVAL_MS below minimum (5000ms)', () => {
    saveEnv('DETECTION_INTERVAL_MS');
    process.env.DETECTION_INTERVAL_MS = '100'; // below MIN_INTERVAL_MS

    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    assert.throws(
      () => startDetectionScheduler({
        runDetectionFn: runStub,
        isRunningFn: makeIsRunningStub(false),
        setIntervalFn: timer.fakeSetInterval,
        clearIntervalFn: timer.fakeClearInterval,
      }),
      /DETECTION_INTERVAL_MS/i
    );

    assert.ok(!isSchedulerRunning(), 'Scheduler must not start on invalid config');
  });

  it('rejects DETECTION_WINDOW_MINUTES above maximum (10080)', () => {
    saveEnv('DETECTION_WINDOW_MINUTES');
    process.env.DETECTION_WINDOW_MINUTES = '99999';

    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    assert.throws(
      () => startDetectionScheduler({
        runDetectionFn: runStub,
        isRunningFn: makeIsRunningStub(false),
        setIntervalFn: timer.fakeSetInterval,
        clearIntervalFn: timer.fakeClearInterval,
      }),
      /DETECTION_WINDOW_MINUTES/i
    );

    assert.ok(!isSchedulerRunning());
  });

  it('rejects non-integer DETECTION_INTERVAL_MS', () => {
    saveEnv('DETECTION_INTERVAL_MS');
    process.env.DETECTION_INTERVAL_MS = 'not-a-number';

    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    assert.throws(
      () => startDetectionScheduler({
        runDetectionFn: runStub,
        isRunningFn: makeIsRunningStub(false),
        setIntervalFn: timer.fakeSetInterval,
        clearIntervalFn: timer.fakeClearInterval,
      }),
      /DETECTION_INTERVAL_MS/i
    );

    assert.ok(!isSchedulerRunning());
  });

  it('rejects options.intervalMs below minimum', () => {
    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    assert.throws(
      () => startDetectionScheduler({
        runDetectionFn: runStub,
        isRunningFn: makeIsRunningStub(false),
        setIntervalFn: timer.fakeSetInterval,
        clearIntervalFn: timer.fakeClearInterval,
        intervalMs: 999, // below 5000 minimum
      }),
      /intervalMs/i
    );

    assert.ok(!isSchedulerRunning());
  });

  it('rejects options.windowMinutes above maximum', () => {
    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    assert.throws(
      () => startDetectionScheduler({
        runDetectionFn: runStub,
        isRunningFn: makeIsRunningStub(false),
        setIntervalFn: timer.fakeSetInterval,
        clearIntervalFn: timer.fakeClearInterval,
        windowMinutes: 99999, // above 10080 maximum
      }),
      /windowMinutes/i
    );

    assert.ok(!isSchedulerRunning());
  });

  // ── Test 10: NODE_ENV=test and DETECTION_SCHEDULER_ENABLED=false ──────────
  // The scheduler module itself does not check these env vars — that is
  // server.js's responsibility. We verify the module-level contracts here.

  it('does not auto-start when server.js is not invoked (module is passive)', () => {
    // The scheduler module must not register timers on import.
    assert.ok(!isSchedulerRunning(), 'Scheduler must not auto-start on module import');
  });

  it('DETECTION_SCHEDULER_ENABLED env var is a server.js responsibility; module start/stop still works', () => {
    saveEnv('DETECTION_SCHEDULER_ENABLED');
    process.env.DETECTION_SCHEDULER_ENABLED = 'false';

    // The scheduler module does not read DETECTION_SCHEDULER_ENABLED.
    // Calling startDetectionScheduler() directly still succeeds.
    const timer = makeFakeTimer();
    const { runStub } = makeRunStub();

    assert.doesNotThrow(() => startDetectionScheduler({
      runDetectionFn: runStub,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 15,
    }));

    assert.ok(isSchedulerRunning());
    stopDetectionScheduler();
  });

  // ── Bonus: summary fields and errors are handled without throwing ─────────

  it('handles non-empty errors array in summary without throwing', async () => {
    const timer = makeFakeTimer();
    const calls = [];

    async function detailedRunFn(opts) {
      calls.push(opts);
      return {
        rulesEvaluated: 4,
        matchesFound: 2,
        alertsCreated: 1,
        alertsUpdated: 1,
        alerts: [],
        errors: ['Evaluator error on rule X'],
      };
    }

    startDetectionScheduler({
      runDetectionFn: detailedRunFn,
      isRunningFn: makeIsRunningStub(false),
      setIntervalFn: timer.fakeSetInterval,
      clearIntervalFn: timer.fakeClearInterval,
      intervalMs: 5_000,
      windowMinutes: 20,
    });

    await assert.doesNotReject(timer.tick());
    assert.equal(calls.length, 1);
    assert.equal(calls[0].windowMinutes, 20);
  });
});
