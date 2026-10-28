import prisma from '../config/prisma.js';
import { runDetection } from '../detection/engine.js';
import { publishLiveUpdate } from '../live/eventBus.js';

const PENDING = 'PENDING';
const PROCESSING = 'PROCESSING';
const COMPLETED = 'COMPLETED';
const FAILED = 'FAILED';
const MAX_ATTEMPTS = 5;
const STALE_PROCESSING_MS = 10 * 60 * 1_000;

let timerId = null;
let processing = false;

function retryDelayMs(attempt) {
  return Math.min(60_000, 1_000 * (2 ** Math.max(0, attempt - 1)));
}

export async function reclaimStaleJobs(now = new Date(), client = prisma) {
  const staleBefore = new Date(now.getTime() - STALE_PROCESSING_MS);
  return client.processingJob.updateMany({
    where: {
      status: PROCESSING,
      startedAt: { lt: staleBefore },
    },
    data: {
      status: PENDING,
      availableAt: now,
      lastError: 'Processing lease expired; job will be retried.',
    },
  });
}

export async function claimPendingJobs(limit = 10, now = new Date()) {
  const candidates = await prisma.processingJob.findMany({
    where: {
      status: { in: [PENDING, FAILED] },
      availableAt: { lte: now },
    },
    orderBy: { availableAt: 'asc' },
    take: limit,
    select: { id: true, eventId: true, attempts: true, status: true },
  });

  const claimed = [];
  for (const candidate of candidates) {
    const result = await prisma.processingJob.updateMany({
      where: {
        id: candidate.id,
        status: candidate.status,
        availableAt: { lte: now },
      },
      data: {
        status: PROCESSING,
        attempts: candidate.attempts + 1,
        startedAt: now,
        lastError: null,
      },
    });
    if (result.count === 1) claimed.push(candidate);
  }

  return claimed;
}

export async function processClaimedJob(job, dependencies = {}) {
  const detect = dependencies.runDetection ?? runDetection;
  const startedAt = Date.now();

  try {
    const result = await detect({ eventIds: [job.eventId], windowMinutes: 15 });
    const processingMs = Date.now() - startedAt;

    if (result.errors.length > 0) {
      throw new Error('One or more detection rules failed.');
    }

    await prisma.processingJob.update({
      where: { id: job.id },
      data: {
        status: COMPLETED,
        completedAt: new Date(),
        failedAt: null,
        processingMs,
        lastError: result.errors.length > 0 ? 'One or more detection rules failed.' : null,
      },
    });

    publishLiveUpdate('analysis.completed', {
      eventId: job.eventId,
      processingMs,
      alertsCreated: result.alertsCreated,
      alertsUpdated: result.alertsUpdated,
    });

    return { jobId: job.id, status: COMPLETED, processingMs, summary: result };
  } catch (error) {
    const attempts = job.attempts + 1;
    const exhausted = attempts >= MAX_ATTEMPTS;

    await prisma.processingJob.update({
      where: { id: job.id },
      data: {
        status: exhausted ? FAILED : PENDING,
        availableAt: exhausted ? new Date() : new Date(Date.now() + retryDelayMs(attempts)),
        failedAt: exhausted ? new Date() : null,
        lastError: exhausted ? 'Analysis failed after maximum retries.' : 'Analysis failed; retry scheduled.',
      },
    });

    console.error(`[Analysis] Job ${job.id} failed (attempt ${attempts}/${MAX_ATTEMPTS}).`);
    return { jobId: job.id, status: exhausted ? FAILED : PENDING, error: error.message };
  }
}

export async function runAnalysisBatch(options = {}) {
  const limit = options.limit ?? 10;
  const reclaim = options.reclaim ?? reclaimStaleJobs;
  const claim = options.claim ?? claimPendingJobs;
  await reclaim();
  const processJob = options.processJob ?? processClaimedJob;
  const jobs = await claim(limit);

  const results = [];
  for (const job of jobs) {
    results.push(await processJob(job));
  }
  return results;
}

export async function runAnalysisCycle(ctx = {}) {
  if (processing) return { skipped: true };
  processing = true;
  try {
    const jobs = await runAnalysisBatch(ctx);
    return { skipped: false, jobs };
  } finally {
    processing = false;
  }
}

export function startAnalysisWorker(options = {}) {
  if (timerId) throw new Error('Analysis worker is already running.');

  const intervalMs = options.intervalMs ?? 1_000;
  const runCycle = options.runCycle ?? runAnalysisCycle;
  timerId = setInterval(() => {
    runCycle().catch((error) => {
      console.error(`[Analysis] Worker cycle failed: ${error.message}`);
    });
  }, intervalMs);
  console.log(`[Analysis] Worker started (interval: ${intervalMs}ms).`);
  return { intervalMs };
}

export function stopAnalysisWorker() {
  if (!timerId) return;
  clearInterval(timerId);
  timerId = null;
}

export function isAnalysisWorkerRunning() {
  return timerId !== null;
}
