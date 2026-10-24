import prisma from './src/config/prisma.js';

async function main() {
  const logs = await prisma.auditLog.findMany({
    orderBy: { timestamp: 'desc' },
    take: 5,
  });
  console.log(JSON.stringify(logs.map(l => ({
    action: l.action,
    details: l.details,
    ip: l.ipAddress,
    time: l.timestamp,
  })), null, 2));
}

main().finally(() => prisma.$disconnect());

