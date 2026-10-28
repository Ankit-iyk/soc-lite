// server.js — Entry point
// Starts the HTTP server. Separated from app.js so tests can
// import the Express app without binding a port.

import { config, getMaskedDatabaseUrl } from './src/config/env.js';
import app from './src/app.js';
import prisma from './src/config/prisma.js';
import { startDetectionScheduler, stopDetectionScheduler } from './src/detection/scheduler.js';
import { startAnalysisWorker, stopAnalysisWorker } from './src/processing/analysis.worker.js';

const server = app.listen(config.port, () => {
  console.log(`\n🛡️  SOC Lite Backend`);
  console.log(`   Environment : ${config.nodeEnv}`);
  console.log(`   Listening on: http://localhost:${config.port}`);
  console.log(`   Health check: http://localhost:${config.port}/api/health`);
  console.log(`   Database    : ${getMaskedDatabaseUrl(config.databaseUrl)}\n`);

  // Start the detection scheduler only in non-test environments and when not
  // explicitly disabled via DETECTION_SCHEDULER_ENABLED=false.
  const schedulerEnabled = process.env.DETECTION_SCHEDULER_ENABLED !== 'false';
  const isTestEnv = config.nodeEnv === 'test';

  if (!isTestEnv && schedulerEnabled) {
    try {
      const { intervalMs, windowMinutes } = startDetectionScheduler();
      console.log(`   Scheduler   : enabled (interval: ${intervalMs}ms, window: ${windowMinutes}m)\n`);
    } catch (err) {
      // Invalid configuration should not crash the server; log clearly and continue.
      console.error(`   Scheduler   : failed to start — ${err.message}`);
      console.error(`   The HTTP server will continue running without automated detection.\n`);
    }
  } else {
    const reason = isTestEnv ? 'NODE_ENV=test' : 'DETECTION_SCHEDULER_ENABLED=false';
    console.log(`   Scheduler   : disabled (${reason})\n`);
  }

  if (!isTestEnv) {
    const intervalMs = Number.parseInt(process.env.ANALYSIS_INTERVAL_MS ?? '1000', 10);
    try {
      startAnalysisWorker({ intervalMs });
    } catch (err) {
      console.error(`   Analysis    : failed to start — ${err.message}\n`);
    }
  }
});

// Tracks whether shutdown is in progress to prevent duplicate invocations.
let _shuttingDown = false;

// Graceful shutdown helper
async function shutdown(signal) {
  if (_shuttingDown) return;
  _shuttingDown = true;

  console.log(`\n${signal} received, shutting down gracefully…`);

  // 1. Stop future scheduled detection runs.
  // NOTE: If a detection pass is currently executing, this does NOT cancel it.
  // The in-flight database transaction will complete normally. We do not
  // forcibly terminate the process while a detection run is active because
  // doing so would leave the database in an indeterminate state.
  stopDetectionScheduler();
  stopAnalysisWorker();

  // 2. Close the HTTP server (stop accepting new connections).
  server.close(async () => {
    console.log('   HTTP server closed.');

    // 3. Disconnect from PostgreSQL after the HTTP server has drained.
    try {
      await prisma.$disconnect();
      console.log('   PostgreSQL connection closed.');
    } catch (err) {
      console.error('   Error closing database connection:', err.message);
    }

    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
