// test/socWorkflow.test.js
// Phase 11 Section 5: End-to-End SOC Workflow Integration Tests.
// Validates the complete lifecycle:
// 1. Ingest security log
// 2. Verify parsing and event persistence
// 3. Trigger detection rule
// 4. Verify corresponding alert
// 5. Link alert to an incident
// 6. Add incident note and update status
// 7. Verify dashboard statistics reflect changes
// 8. Verify asset and threat-intelligence correlations
// 9. Generate security report and verify totals & PDF signature
// 10. Verify audit events for supported actions

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../src/app.js';
import prisma from '../src/config/prisma.js';
import { signToken } from '../src/utils/jwt.js';

let server;
let baseUrl;
let adminToken;
let analystToken;
let adminUser;
let analystUser;

// Isolated unique identifiers for this workflow test run
const testRunId = `e2e-${Date.now()}`;
const testIp = '198.51.100.88';
let createdRawLogId = null;
let createdEventId = null;
let createdAlertId = null;
let createdIncidentId = null;
let createdAssetId = null;
let createdIocId = null;

describe('Phase 11 — End-to-End SOC Workflow Integration Tests', () => {
  before(async () => {
    // 1. Start dynamic HTTP server
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });

    // 2. Load seeded users
    adminUser = await prisma.user.findUnique({ where: { email: 'admin@soclite.local' } });
    analystUser = await prisma.user.findUnique({ where: { email: 'analyst@soclite.local' } });

    assert.ok(adminUser, 'Seeded admin user must exist');
    assert.ok(analystUser, 'Seeded analyst user must exist');

    adminToken = signToken({ userId: adminUser.id, email: adminUser.email, role: adminUser.role });
    analystToken = signToken({ userId: analystUser.id, email: analystUser.email, role: analystUser.role });

    // 3. Pre-create threat IOC and asset for correlation
    const iocRes = await fetch(`${baseUrl}/api/threat-intel/iocs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        type: 'IP',
        value: testIp,
        severity: 'HIGH',
        confidence: 90,
        source: 'Automated Threat Intel Feed',
        description: `E2E Test Indicator ${testRunId}`,
      }),
    });
    assert.equal(iocRes.status, 201, 'Should create threat indicator');
    const iocBody = await iocRes.json();
    createdIocId = iocBody.data.id;

    const assetRes = await fetch(`${baseUrl}/api/assets`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        name: `E2E-Target-Server-${testRunId}`,
        hostname: `srv-${testRunId}.corp.local`,
        ipAddress: testIp,
        type: 'SERVER',
        criticality: 'HIGH',
        environment: 'PRODUCTION',
      }),
    });
    assert.equal(assetRes.status, 201, 'Should create monitored asset');
    const assetBody = await assetRes.json();
    createdAssetId = assetBody.data.id;
  });

  after(async () => {
    // Clean up only records created by this test run
    if (createdIncidentId) {
      await prisma.incidentAlert.deleteMany({ where: { incidentId: createdIncidentId } });
      await prisma.incident.deleteMany({ where: { id: createdIncidentId } });
      await prisma.auditLog.deleteMany({ where: { targetId: createdIncidentId } });
    }
    if (createdAlertId) {
      await prisma.alertEvent.deleteMany({ where: { alertId: createdAlertId } });
      await prisma.alert.deleteMany({ where: { id: createdAlertId } });
    }
    if (createdEventId) {
      await prisma.event.deleteMany({ where: { id: createdEventId } });
    }
    if (createdRawLogId) {
      await prisma.rawLog.deleteMany({ where: { id: createdRawLogId } });
    }
    if (createdAssetId) {
      await prisma.asset.deleteMany({ where: { id: createdAssetId } });
      await prisma.auditLog.deleteMany({ where: { targetId: createdAssetId } });
    }
    if (createdIocId) {
      await prisma.iocEnrichment.deleteMany({ where: { indicatorId: createdIocId } });
      await prisma.threatIndicator.deleteMany({ where: { id: createdIocId } });
      await prisma.auditLog.deleteMany({ where: { targetId: createdIocId } });
    }

    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await prisma.$disconnect();
  });

  it('Step 1 & 2: Ingests a security log and verifies parsing & event persistence', async () => {
    const rawContent = `Oct 25 18:30:15 host-${testRunId} sshd[12345]: Failed password for invalid user root from ${testIp} port 49152 ssh2`;

    const res = await fetch(`${baseUrl}/api/logs/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        source: 'auth.log',
        content: rawContent,
      }),
    });

    assert.equal(res.status, 201, 'Log ingestion should return 201 Created');
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data?.count, 1, 'One parsed event must be returned');

    createdEventId = body.data.events[0].id;

    // Verify event in database
    const savedEvent = await prisma.event.findUnique({
      where: { id: createdEventId },
      include: { rawLog: true },
    });
    assert.ok(savedEvent, 'Event should exist in PostgreSQL database');
    assert.equal(savedEvent.srcIp, testIp, 'Parsed event srcIp should match ingested log');
    assert.equal(savedEvent.eventType, 'ssh_login_failed');
    assert.ok(savedEvent.rawLogId, 'RawLog relation should exist');
    createdRawLogId = savedEvent.rawLogId;
  });

  it('Step 3 & 4: Triggers detection rule and verifies corresponding alert', async () => {
    // Trigger detection run via API
    const res = await fetch(`${baseUrl}/api/detection/run`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });

    assert.equal(res.status, 200, 'Detection run should return 200 OK');
    const body = await res.json();
    assert.equal(body.success, true);

    // Find the alert generated for this suspicious IP
    const alert = await prisma.alert.findFirst({
      where: {
        title: { contains: testIp },
      },
      include: {
        alertEvents: true,
      },
      orderBy: { firedAt: 'desc' },
    });

    assert.ok(alert, `An alert should be created matching suspicious IP ${testIp}`);
    createdAlertId = alert.id;
    assert.equal(alert.status, 'OPEN');
  });

  it('Step 5: Links the alert to an incident', async () => {
    // Create new incident
    const incRes = await fetch(`${baseUrl}/api/incidents`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        title: `Suspicious Intrusion Campaign [${testRunId}]`,
        description: `Active threat indicator investigation against ${testIp}`,
        severity: 'HIGH',
      }),
    });

    assert.equal(incRes.status, 201, 'Incident creation should return 201');
    const incBody = await incRes.json();
    createdIncidentId = incBody.data.id;
    assert.ok(createdIncidentId, 'Incident ID must be returned');

    // Link the alert
    const linkRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}/alerts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        alertIds: [createdAlertId],
      }),
    });

    assert.equal(linkRes.status, 200, 'Alert linking should return 200');
    const linkBody = await linkRes.json();
    assert.equal(linkBody.success, true);

    // Verify linkage in DB
    const link = await prisma.incidentAlert.findUnique({
      where: {
        incidentId_alertId: {
          incidentId: createdIncidentId,
          alertId: createdAlertId,
        },
      },
    });
    assert.ok(link, 'IncidentAlert record must exist in DB');
  });

  it('Step 6: Adds an incident note and updates its status', async () => {
    // Add investigation note
    const noteRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}/notes`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        note: 'Tier-1 analyst triage: correlated IP with known threat actor feed.',
      }),
    });

    assert.equal(noteRes.status, 201, 'Adding incident note should return 201');
    const noteBody = await noteRes.json();
    assert.equal(noteBody.success, true);
    assert.equal(noteBody.data.note, 'Tier-1 analyst triage: correlated IP with known threat actor feed.');

    // Transition incident status to INVESTIGATING
    const updateRes = await fetch(`${baseUrl}/api/incidents/${createdIncidentId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        status: 'INVESTIGATING',
      }),
    });

    assert.equal(updateRes.status, 200, 'Incident update should return 200');
    const updateBody = await updateRes.json();
    assert.equal(updateBody.success, true);
    assert.equal(updateBody.data.status, 'INVESTIGATING');
  });

  it('Step 7: Verifies dashboard statistics reflect current system state', async () => {
    const summaryRes = await fetch(`${baseUrl}/api/dashboard/summary`, {
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });

    assert.equal(summaryRes.status, 200, 'Dashboard summary should return 200');
    const summary = await summaryRes.json();
    assert.equal(summary.success, true);
    assert.ok(summary.data.kpis.totalAlerts >= 1, 'Total alerts must be at least 1');
    assert.ok(summary.data.kpis.investigatingIncidents >= 1, 'Investigating incidents must be at least 1');
    assert.ok(typeof summary.data.kpis.totalEvents === 'number');
    assert.ok(typeof summary.data.kpis.openAlerts === 'number');
  });

  it('Step 8: Verifies asset and threat-intelligence correlations', async () => {
    const corrRes = await fetch(`${baseUrl}/api/threat-intel/iocs/${createdIocId}/correlation`, {
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });

    assert.equal(corrRes.status, 200, 'Correlation query should return 200');
    const corrBody = await corrRes.json();
    assert.equal(corrBody.success, true);
    assert.ok(Array.isArray(corrBody.data.assets), 'Assets array must exist in correlation data');
    assert.ok(Array.isArray(corrBody.data.events), 'Events array must exist in correlation data');

    // Verify correlated asset
    const matchingAsset = corrBody.data.assets.find((a) => a.id === createdAssetId);
    assert.ok(matchingAsset, 'Correlation must identify the matching registered asset');
    assert.equal(matchingAsset.ipAddress, testIp);

    // Verify correlated event
    const matchingEvent = corrBody.data.events.find((e) => e.id === createdEventId);
    assert.ok(matchingEvent, 'Correlation must identify the ingested security event');
  });

  it('Step 9: Generates security report and verifies totals and PDF signature', async () => {
    // 1. JSON Preview
    const previewRes = await fetch(`${baseUrl}/api/reports/preview?type=SECURITY_OVERVIEW`, {
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });

    assert.equal(previewRes.status, 200, 'Security report preview should return 200');
    const preview = await previewRes.json();
    assert.equal(preview.success, true);
    assert.ok(preview.data.report.summary.totalAlerts >= 1);
    assert.ok(preview.data.report.summary.totalIncidents >= 1);

    // 2. PDF Download
    const downloadRes = await fetch(`${baseUrl}/api/reports/download?type=SECURITY_OVERVIEW`, {
      headers: {
        Authorization: `Bearer ${analystToken}`,
      },
    });

    assert.equal(downloadRes.status, 200, 'Report download should return 200');
    assert.equal(downloadRes.headers.get('content-type'), 'application/pdf');
    const disposition = downloadRes.headers.get('content-disposition');
    assert.ok(disposition?.includes('attachment; filename='), 'Content-Disposition header must specify attachment');

    const pdfBuffer = Buffer.from(await downloadRes.arrayBuffer());
    assert.ok(pdfBuffer.length > 500, 'PDF buffer should be non-trivial size');
    // Verify standard PDF header magic bytes %PDF-
    assert.equal(pdfBuffer.subarray(0, 4).toString('ascii'), '%PDF', 'Must start with %PDF magic header');
  });

  it('Step 10: Verifies audit log events for all supported workflow actions', async () => {
    // Verify audit logs exist for:
    // LOGS_INGESTED, DETECTION_RUN, INCIDENT_CREATE, INCIDENT_ALERT_LINK, INCIDENT_NOTE_ADD, INCIDENT_STATUS_CHANGE
    const logs = await prisma.auditLog.findMany({
      where: {
        OR: [
          { action: 'LOGS_INGESTED' },
          { action: 'DETECTION_RUN' },
          { targetId: createdIncidentId },
          { targetId: createdIocId },
          { targetId: createdAssetId },
        ],
      },
    });

    const actions = new Set(logs.map((l) => l.action));
    assert.ok(actions.has('LOGS_INGESTED') || actions.has('DETECTION_RUN'), 'Must log ingestion or detection audit');
    assert.ok(actions.has('INCIDENT_CREATE'), 'Must record INCIDENT_CREATE audit log');
    assert.ok(actions.has('INCIDENT_ALERT_LINK'), 'Must record INCIDENT_ALERT_LINK audit log');
    assert.ok(actions.has('INCIDENT_NOTE_ADD'), 'Must record INCIDENT_NOTE_ADD audit log');
    assert.ok(actions.has('INCIDENT_STATUS_CHANGE'), 'Must record INCIDENT_STATUS_CHANGE audit log');
  });
});
