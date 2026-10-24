// src/detection/scheduler.js
// Automated Detection Scheduler for SOC Lite.
//
// Periodically invokes the detection engine so that security analysts
// receive alerts even when no one manually triggers a run.
//
// Design constraints:
//   - Single Node.js process: in-memory state coordinates with manual runs
//     through the same `isDetectionRunning()` flag exported by engine.js.
//   - Skip-if-busy: if a detection pass is already executing, the scheduled
//     tick is skipped rather than queued, preventing unbounded work accumulation.
//   - Resilient: a failed run logs the error but does not crash the server and
//     does not prevent the next scheduled run.
//   - No external dependencies (no cron library, no worker threads).
//
// NOTE: This in-memory lock only coordinates within a single Node.js process.
// A multi-process or clustered deployment would require an external advisory
// lock (e.g., Redis or a PostgreSQL advisory lock) for full coordination.

import { runDetection, isDetectionRunning } from './engine.js';

// ── Configuration constants ───────────────────────────────────────────────────

const DEFAULT_INTERVAL_MS = 30_000;       // 30 seconds
const DEFAULT_WINDOW_MINUTES = 15;        // 15-minute lookback window

// Hard bounds to prevent misconfiguration causing tight loops or unreasonable loads.
const MIN_INTERVAL_MS = 5_000;            // 5 seconds minimum
const MAX_INTERVAL_MS = 24 * 60 * 60_000; // 24 hours maximum
const MIN_WINDOW_MINUTES = 1;
const MAX_WINDOW_MINUTES = 10_080;         // 7 days maximum (matches manual run)

// ── Module-level scheduler state ─────────────────────────────────────────────

/** @type {ReturnType<typeof setInterval> | null} */
let _timerId = null;

/** Whether the scheduler has been started (guards against double-start). */
let _started = false;

/** Resolved configuration used by the running scheduler. */
let _resolvedIntervalMs = DEFAULT_INTERVAL_MS;
let _resolvedWindowMinutes = DEFAULT_WINDOW_MINUTES;

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Parses an integer from `str`. Returns `defaultValue` if `str` is absent.
 * Throws with a descriptive message if the value is present but not a valid
 * integer within [min, max].
 *
 * @param {string|undefined} str
 * @param {string} name       - Human-readable variable name for error messages
 * @param {number} defaultValue
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function parseEnvInt(str, name, defaultValue, min, max) {
  if (str === undefined || str === '') return defaultValue;

  const n = Number(str);
  if (!Number.isInteger(n) || Number.isNaN(n)) {
    throw new Error(
      `[Scheduler] Invalid ${name}: "${str}" is not an integer. ` +
      `Using the scheduler default (${defaultValue}) is safer — unset ${name} to use the default.`
    );
  }
  if (n < min || n > max) {
    throw new Error(
      `[Scheduler] Invalid ${name}: ${n} is out of range [${min}, ${max}]. ` +
      `Using the scheduler default (${defaultValue}) is safer — unset ${name} to use the default.`
    );
  }
  return n;
}

// ── Core tick ─────────────────────────────────────────────────────────────────

/**
 * Executes one scheduled detection pass.
 * If the engine is already busy (manual run in progress or a slow previous
 * scheduled run), the tick is skipped to avoid queuing unlimited work.
 *
 * All errors are caught so that an unhandled promise rejection is never
 * produced inside a `setInterval` callback.
 *
 * @param {object} [_ctx] - Injected context (used by tests for clock control)
 * @param {Function} [_ctx.runDetectionFn] - Override for runDetection (test seam)
 * @param {Function} [_ctx.isRunningFn]    - Override for isDetectionRunning (test seam)
 */
async function scheduledTick(ctx = {}) {
  const runFn = ctx.runDetectionFn ?? runDetection;
  const isRunningFn = ctx.isRunningFn ?? isDetectionRunning;
  const windowMinutes = ctx.windowMinutes ?? _resolvedWindowMinutes;

  if (isRunningFn()) {
    console.log('[Scheduler] Skipping scheduled run — detection engine is already executing.');
    return;
  }

  const startedAt = Date.now();
  console.log(`[Scheduler] Starting scheduled detection run (window: ${windowMinutes}m)…`);

  try {
    const summary = await runFn({ windowMinutes });
    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
    console.log(
      `[Scheduler] Detection run completed in ${elapsed}s — ` +
      `rules: ${summary.rulesEvaluated}, matches: ${summary.matchesFound}, ` +
      `alerts created: ${summary.alertsCreated}, updated: ${summary.alertsUpdated}` +
      (summary.errors.length > 0 ? `, errors: ${summary.errors.length}` : '')
    );
  } catch (err) {
    // Log but do NOT re-throw: setInterval callbacks that produce unhandled
    // rejections can crash the Node.js process in some configurations.
    console.error(`[Scheduler] Scheduled detection run failed: ${err.message}`);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Starts the automated detection scheduler.
 *
 * @param {object} [options]
 * @param {Function} [options.runDetectionFn]   - Injection seam for tests (overrides runDetection)
 * @param {Function} [options.isRunningFn]      - Injection seam for tests (overrides isDetectionRunning)
 * @param {Function} [options.setIntervalFn]    - Injection seam for tests (overrides setInterval)
 * @param {Function} [options.clearIntervalFn]  - Injection seam for tests (overrides clearInterval)
 * @param {number}   [options.intervalMs]       - Override interval in ms (takes precedence over env)
 * @param {number}   [options.windowMinutes]    - Override window in minutes (takes precedence over env)
 * @returns {{ intervalMs: number, windowMinutes: number }}  Resolved configuration
 * @throws {Error} If called when scheduler is already running.
 * @throws {Error} If environment configuration is invalid.
 */
export function startDetectionScheduler(options = {}) {
  if (_started) {
    throw new Error('[Scheduler] startDetectionScheduler() called while scheduler is already running. Call stopDetectionScheduler() first.');
  }

  // Resolve interval — explicit option takes priority, then env, then default.
  let intervalMs;
  if (options.intervalMs !== undefined) {
    intervalMs = options.intervalMs;
    if (!Number.isInteger(intervalMs) || intervalMs < MIN_INTERVAL_MS || intervalMs > MAX_INTERVAL_MS) {
      throw new Error(
        `[Scheduler] Invalid options.intervalMs: ${intervalMs}. Must be an integer in [${MIN_INTERVAL_MS}, ${MAX_INTERVAL_MS}].`
      );
    }
  } else {
    intervalMs = parseEnvInt(
      process.env.DETECTION_INTERVAL_MS,
      'DETECTION_INTERVAL_MS',
      DEFAULT_INTERVAL_MS,
      MIN_INTERVAL_MS,
      MAX_INTERVAL_MS
    );
  }

  // Resolve window — explicit option takes priority, then env, then default.
  let windowMinutes;
  if (options.windowMinutes !== undefined) {
    windowMinutes = options.windowMinutes;
    if (!Number.isInteger(windowMinutes) || windowMinutes < MIN_WINDOW_MINUTES || windowMinutes > MAX_WINDOW_MINUTES) {
      throw new Error(
        `[Scheduler] Invalid options.windowMinutes: ${windowMinutes}. Must be an integer in [${MIN_WINDOW_MINUTES}, ${MAX_WINDOW_MINUTES}].`
      );
    }
  } else {
    windowMinutes = parseEnvInt(
      process.env.DETECTION_WINDOW_MINUTES,
      'DETECTION_WINDOW_MINUTES',
      DEFAULT_WINDOW_MINUTES,
      MIN_WINDOW_MINUTES,
      MAX_WINDOW_MINUTES
    );
  }

  _resolvedIntervalMs = intervalMs;
  _resolvedWindowMinutes = windowMinutes;

  const setIntervalFn = options.setIntervalFn ?? setInterval;
  const clearIntervalFn = options.clearIntervalFn ?? clearInterval;

  // Build the per-tick context for dependency injection.
  const tickCtx = {
    runDetectionFn: options.runDetectionFn,
    isRunningFn: options.isRunningFn,
    windowMinutes,
  };

  // Schedule recurring tick. The async function is wrapped so that any
  // unhandled rejection from scheduledTick cannot escape into setInterval.
  _timerId = setIntervalFn(() => {
    scheduledTick(tickCtx).catch((err) => {
      // Extra safety net: scheduledTick already catches internally, but
      // guarding here protects against any future refactoring.
      console.error(`[Scheduler] Unexpected error in scheduledTick wrapper: ${err.message}`);
    });
  }, intervalMs);

  // Store clearInterval function so stop() uses the same injected one.
  _clearIntervalFn = clearIntervalFn;

  _started = true;

  console.log(`[Scheduler] Detection scheduler started (interval: ${intervalMs}ms, window: ${windowMinutes}m).`);
  return { intervalMs, windowMinutes };
}

/**
 * Stops the automated detection scheduler.
 *
 * Cancels future timer-triggered runs. If a detection pass is currently
 * executing, it is allowed to complete normally — stopping the scheduler
 * does not cancel in-flight database transactions. This is the honest
 * shutdown policy: we stop scheduling NEW runs but do not forcibly
 * terminate any work already in progress.
 *
 * Safe to call when the scheduler is not running (no-op).
 */
export function stopDetectionScheduler() {
  if (!_started) {
    // No-op; not an error — allows safe unconditional calls in shutdown handlers.
    return;
  }

  if (_timerId !== null) {
    _clearIntervalFn(_timerId);
    _timerId = null;
  }

  _started = false;
  console.log('[Scheduler] Detection scheduler stopped. No further runs will be scheduled.');
}

/**
 * Returns whether the scheduler is currently active.
 * Useful for health checks and tests.
 * @returns {boolean}
 */
export function isSchedulerRunning() {
  return _started;
}

// Module-level variable to hold the clearInterval function used at start time.
// Stored so that stop() can call the injected version, not a global.
/** @type {Function} */
let _clearIntervalFn = clearInterval;
