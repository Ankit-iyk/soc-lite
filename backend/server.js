// server.js — Entry point
// Starts the HTTP server. Separated from app.js so tests can
// import the Express app without binding a port.

import { config, getMaskedDatabaseUrl } from './src/config/env.js';
import app from './src/app.js';
import prisma from './src/config/prisma.js';

const server = app.listen(config.port, () => {
  console.log(`\n🛡️  SOC Lite Backend`);
  console.log(`   Environment : ${config.nodeEnv}`);
  console.log(`   Listening on: http://localhost:${config.port}`);
  console.log(`   Health check: http://localhost:${config.port}/api/health`);
  console.log(`   Database    : ${getMaskedDatabaseUrl(config.databaseUrl)}\n`);
});

// Graceful shutdown helper
async function shutdown(signal) {
  console.log(`\n${signal} received, shutting down gracefully…`);
  try {
    await prisma.$disconnect();
    console.log('   PostgreSQL connection closed.');
  } catch (err) {
    console.error('   Error closing database connection:', err.message);
  }
  server.close(() => {
    console.log('   HTTP server closed.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
