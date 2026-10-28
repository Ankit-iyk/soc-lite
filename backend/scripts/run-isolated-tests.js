import 'dotenv/config';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCHEMA = 'soc_lite_test';
const configuredUrl = process.env.DATABASE_URL;

if (!configuredUrl) {
  throw new Error('DATABASE_URL is required');
}

const parsed = new URL(configuredUrl);
const host = parsed.hostname.toLowerCase();
const allowedHosts = new Set(['localhost', '127.0.0.1', '::1']);

if (!allowedHosts.has(host) || parsed.port !== '5432') {
  throw new Error('Refusing to run isolated tests against a non-local PostgreSQL server');
}

if (parsed.pathname !== '/soc_lite_db') {
  throw new Error('Refusing to run isolated tests against a database other than soc_lite_db');
}

parsed.searchParams.set('schema', 'public');
process.env.DATABASE_URL = parsed.toString();

const { default: prisma } = await import('../src/config/prisma.js');

try {
  await prisma.$executeRawUnsafe(`DROP SCHEMA IF EXISTS "${SCHEMA}" CASCADE`);
  await prisma.$executeRawUnsafe(`CREATE SCHEMA "${SCHEMA}"`);
} finally {
  await prisma.$disconnect();
}

parsed.searchParams.set('schema', SCHEMA);
process.env.DATABASE_URL = parsed.toString();

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: ROOT,
    env: process.env,
    stdio: 'inherit',
  });

  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const prismaCli = join(ROOT, 'node_modules', 'prisma', 'build', 'index.js');
run(process.execPath, [prismaCli, 'db', 'push', '--accept-data-loss', '--skip-generate']);
run(process.execPath, [join(ROOT, 'prisma', 'seed.js')]);
const testTargets = process.argv.slice(2);
run(process.execPath, [
  '--test',
  '--test-concurrency=1',
  ...(testTargets.length > 0 ? testTargets : ['test/**/*.test.js']),
]);
