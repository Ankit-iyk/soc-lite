// prisma/seed.js
// Seeds the database with default accounts, detection rules, threat IOCs, and assets.
// Idempotent: safe to run multiple times using Prisma upserts.

import bcrypt from 'bcryptjs';
import { PrismaClient, Role, Severity, RuleType, IocType } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed…');

  // 1. Seed Users
  console.log('   Seeding default users…');
  const defaultUsers = [
    {
      email: 'admin@soclite.local',
      name: 'SOC Administrator',
      role: Role.ADMIN,
      password: 'Admin@SOC2026!',
    },
    {
      email: 'analyst@soclite.local',
      name: 'Tier-1 Security Analyst',
      role: Role.ANALYST,
      password: 'Analyst@SOC2026!',
    },
    {
      email: 'viewer@soclite.local',
      name: 'Executive Viewer',
      role: Role.VIEWER,
      password: 'Viewer@SOC2026!',
    },
  ];

  for (const u of defaultUsers) {
    const passwordHash = await bcrypt.hash(u.password, 10);
    const user = await prisma.user.upsert({
      where: { email: u.email },
      update: {
        name: u.name,
        role: u.role,
        passwordHash,
      },
      create: {
        email: u.email,
        name: u.name,
        role: u.role,
        passwordHash,
      },
    });
    console.log(`   ✓ User [${user.role}] ${user.email}`);
  }

  // 2. Seed Baseline Detection Rules
  console.log('   Seeding 4 baseline detection rules…');
  const defaultRules = [
    {
      name: 'SSH Brute Force Detection',
      type: RuleType.SSH_BRUTE_FORCE,
      severity: Severity.HIGH,
      description: 'Detects 5 or more failed SSH login attempts from the same source IP and username within 60 seconds.',
      enabled: true,
      config: {
        threshold: 5,
        windowSeconds: 60,
        eventType: 'ssh_login_failed',
      },
    },
    {
      name: 'Port Scanning Activity',
      type: RuleType.PORT_SCAN,
      severity: Severity.HIGH,
      description: 'Detects a single source IP attempting connections to 15 or more distinct destination ports within 120 seconds.',
      enabled: true,
      config: {
        portThreshold: 15,
        windowSeconds: 120,
        eventType: 'connection_attempt',
      },
    },
    {
      name: 'Known Suspicious IP Match',
      type: RuleType.SUSPICIOUS_IP,
      severity: Severity.CRITICAL,
      description: 'Flags events where source or destination IP matches an active threat-intel indicator.',
      enabled: true,
      config: {
        matchSource: true,
        matchDestination: true,
      },
    },
    {
      name: 'Suspicious Administrative Access',
      type: RuleType.SUSPICIOUS_ACCESS,
      severity: Severity.MEDIUM,
      description: 'Detects successful administrative logins outside approved operating hours (06:00 - 22:00) or on weekends.',
      enabled: true,
      config: {
        allowedHoursStart: 6,
        allowedHoursEnd: 22,
        alertOnWeekend: true,
        targetRole: 'ADMIN',
      },
    },
  ];

  for (const r of defaultRules) {
    const rule = await prisma.detectionRule.upsert({
      where: { name: r.name },
      update: {
        type: r.type,
        severity: r.severity,
        description: r.description,
        enabled: r.enabled,
        config: r.config,
      },
      create: r,
    });
    console.log(`   ✓ Rule [${rule.severity}] ${rule.name}`);
  }

  // 3. Seed Sample Threat Intelligence Indicators (IOCs)
  console.log('   Seeding sample threat indicators…');
  const defaultIocs = [
    {
      type: IocType.IP,
      value: '198.51.100.23',
      confidence: 95,
      source: 'AlienVault OTX',
      description: 'Known Cobalt Strike Command & Control server',
    },
    {
      type: IocType.IP,
      value: '203.0.113.88',
      confidence: 90,
      source: 'AbuseIPDB',
      description: 'Active SSH brute-force scanner',
    },
    {
      type: IocType.DOMAIN,
      value: 'c2-malware.evil-corp.xyz',
      confidence: 85,
      source: 'ThreatConnect',
      description: 'Malware distribution beacon domain',
    },
  ];

  for (const ioc of defaultIocs) {
    const item = await prisma.threatIndicator.upsert({
      where: { value: ioc.value },
      update: {
        type: ioc.type,
        confidence: ioc.confidence,
        source: ioc.source,
        description: ioc.description,
      },
      create: ioc,
    });
    console.log(`   ✓ IOC [${item.type}] ${item.value}`);
  }

  // 4. Seed Monitored Assets
  console.log('   Seeding initial monitored assets…');
  const defaultAssets = [
    {
      name: 'DC-01',
      ipAddress: '10.0.0.1',
      type: 'SERVER',
      owner: 'IT Infrastructure',
      criticality: Severity.CRITICAL,
      tags: ['domain-controller', 'active-directory', 'core'],
    },
    {
      name: 'WEB-PROD-01',
      ipAddress: '10.0.0.15',
      type: 'SERVER',
      owner: 'Web Operations',
      criticality: Severity.HIGH,
      tags: ['nginx', 'production', 'dmz'],
    },
    {
      name: 'FW-EDGE-01',
      ipAddress: '10.0.0.254',
      type: 'FIREWALL',
      owner: 'SecOps',
      criticality: Severity.CRITICAL,
      tags: ['pfsense', 'edge', 'perimeter'],
    },
  ];

  for (const asset of defaultAssets) {
    const item = await prisma.asset.upsert({
      where: { ipAddress: asset.ipAddress },
      update: {
        name: asset.name,
        type: asset.type,
        owner: asset.owner,
        criticality: asset.criticality,
        tags: asset.tags,
      },
      create: asset,
    });
    console.log(`   ✓ Asset [${item.criticality}] ${item.name} (${item.ipAddress})`);
  }

  console.log('✅ Database seed completed successfully.');
}

main()
  .catch((err) => {
    console.error('❌ Seed failed:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
