// src/modules/collectors/collectors.controller.js
// Controllers for collector agent management:
//   - POST /api/collectors/tokens   → ADMIN only: provision a new agent token
//   - GET  /api/collectors/tokens   → ADMIN only: list enrolled collectors
//   - DELETE /api/collectors/tokens/:id → ADMIN only: revoke a token
//   - POST /api/collectors/checkin  → Agent auth: heartbeat / status update
//   - POST /api/collectors/ingest   → Agent auth: batch Windows Event Log ingest
//   - GET  /api/collectors          → ADMIN/ANALYST/VIEWER: list collector status

import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import prisma from '../../config/prisma.js';
import { normalizeLog } from '../logs/logParser.js';

const BCRYPT_ROUNDS = 10;
const TOKEN_BYTE_LENGTH = 32; // 256-bit raw token
const MAX_BATCH_SIZE = 200;   // Higher limit for agent batches
const MAX_ERROR_LENGTH = 500;

// ── Token Management (ADMIN only) ────────────────────────────────────────────

/**
 * POST /api/collectors/tokens
 * Creates a new agent token. The raw token is returned ONCE and never stored.
 */
export async function createAgentToken(req, res, next) {
  try {
    const { name } = req.body || {};

    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({
        success: false,
        error: 'A non-empty collector name is required.',
      });
    }

    const trimmedName = name.trim().slice(0, 100);

    // Generate a cryptographically secure random token
    const rawToken = crypto.randomBytes(TOKEN_BYTE_LENGTH).toString('hex');
    const tokenHash = await bcrypt.hash(rawToken, BCRYPT_ROUNDS);

    const agentToken = await prisma.agentToken.create({
      data: {
        name: trimmedName,
        tokenHash,
        createdById: req.user?.id || null,
      },
      select: { id: true, name: true, createdAt: true, enabled: true },
    });

    // Audit
    await prisma.auditLog.create({
      data: {
        userId: req.user?.id,
        action: 'AGENT_TOKEN_CREATED',
        targetType: 'AgentToken',
        targetId: agentToken.id,
        ipAddress: req.ip || 'unknown',
        details: { name: trimmedName },
      },
    }).catch((err) => console.error('AuditLog error:', err.message));

    return res.status(201).json({
      success: true,
      message: 'Agent token created. Copy the rawToken now — it will not be shown again.',
      data: {
        ...agentToken,
        rawToken, // Shown ONCE here; server only stores the hash
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/collectors/tokens
 * Lists all agent tokens with their status. Never returns the raw token or hash.
 */
export async function listAgentTokens(req, res, next) {
  try {
    const tokens = await prisma.agentToken.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        enabled: true,
        lastUsedAt: true,
        createdAt: true,
        revokedAt: true,
        createdBy: { select: { email: true, name: true } },
        collectorStatus: {
          select: {
            hostname: true,
            platform: true,
            collectorVersion: true,
            lastCheckinAt: true,
            lastEventAt: true,
            eventsIngested: true,
            status: true,
            channels: true,
            lastError: true,
          },
        },
      },
    });

    return res.json({ success: true, data: tokens });
  } catch (err) {
    next(err);
  }
}

/**
 * DELETE /api/collectors/tokens/:id
 * Revokes a token (soft-delete: sets revokedAt and enabled=false).
 */
export async function revokeAgentToken(req, res, next) {
  try {
    const { id } = req.params;

    const existing = await prisma.agentToken.findUnique({ where: { id } });
    if (!existing) {
      return res.status(404).json({ success: false, error: 'Agent token not found.' });
    }

    const updated = await prisma.agentToken.update({
      where: { id },
      data: { enabled: false, revokedAt: new Date() },
      select: { id: true, name: true, revokedAt: true },
    });

    await prisma.auditLog.create({
      data: {
        userId: req.user?.id,
        action: 'AGENT_TOKEN_REVOKED',
        targetType: 'AgentToken',
        targetId: id,
        ipAddress: req.ip || 'unknown',
        details: { name: existing.name },
      },
    }).catch((err) => console.error('AuditLog error:', err.message));

    return res.json({ success: true, message: 'Agent token revoked.', data: updated });
  } catch (err) {
    next(err);
  }
}

// ── Agent Endpoints (Agent Token auth) ───────────────────────────────────────

/**
 * POST /api/collectors/checkin
 * Heartbeat endpoint. Agent reports its identity and last-seen info.
 * Updates CollectorStatus (upsert).
 */
export async function agentCheckin(req, res, next) {
  try {
    const agentToken = req.agentToken;
    const { hostname, platform, collectorVersion, channels } = req.body || {};

    const status = await prisma.collectorStatus.upsert({
      where: { agentTokenId: agentToken.id },
      create: {
        agentTokenId: agentToken.id,
        hostname: hostname?.toString().slice(0, 100) || null,
        platform: platform?.toString().slice(0, 200) || null,
        collectorVersion: collectorVersion?.toString().slice(0, 50) || null,
        lastCheckinAt: new Date(),
        status: 'OK',
        channels: Array.isArray(channels) ? channels.map(String).slice(0, 20) : [],
      },
      update: {
        hostname: hostname?.toString().slice(0, 100) || undefined,
        platform: platform?.toString().slice(0, 200) || undefined,
        collectorVersion: collectorVersion?.toString().slice(0, 50) || undefined,
        lastCheckinAt: new Date(),
        status: 'OK',
        lastError: null,
        channels: Array.isArray(channels) ? channels.map(String).slice(0, 20) : undefined,
      },
    });

    return res.json({
      success: true,
      message: 'Check-in recorded.',
      data: { agentName: agentToken.name, statusId: status.id },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/collectors/checkin/error
 * Agent reports an error condition (permission denied, channel unavailable, etc.)
 */
export async function agentReportError(req, res, next) {
  try {
    const agentToken = req.agentToken;
    const { error } = req.body || {};
    const truncatedError = typeof error === 'string'
      ? error.slice(0, MAX_ERROR_LENGTH)
      : 'Unknown error';

    await prisma.collectorStatus.upsert({
      where: { agentTokenId: agentToken.id },
      create: {
        agentTokenId: agentToken.id,
        lastCheckinAt: new Date(),
        status: 'ERROR',
        lastError: truncatedError,
        channels: [],
      },
      update: {
        lastCheckinAt: new Date(),
        status: 'ERROR',
        lastError: truncatedError,
      },
    });

    return res.json({ success: true, message: 'Error recorded.' });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/collectors/ingest
 * Batch-ingest Windows Event Log records from a collector agent.
 *
 * Expected body:
 * {
 *   "logs": [
 *     {
 *       "source": "Security",
 *       "content": "...",              // Raw event XML string or JSON string
 *       "eventRecordId": "12345",      // Windows-native RecordId for deduplication
 *       "eventId": 4625,
 *       "timeCreated": "2026-10-26T09:00:00Z"
 *     }
 *   ]
 * }
 *
 * Deduplication: each item may supply an eventRecordId. If an event with the
 * same (source, eventRecordId) already exists in raw_logs metadata, it is skipped.
 * This prevents duplicate events on agent restart with overlapping bookmarks.
 */
export async function agentIngest(req, res, next) {
  try {
    const agentToken = req.agentToken;
    const { logs } = req.body || {};

    if (!Array.isArray(logs) || logs.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Body must be { logs: [...] } with at least one item.',
      });
    }

    if (logs.length > MAX_BATCH_SIZE) {
      return res.status(400).json({
        success: false,
        error: `Batch size ${logs.length} exceeds maximum ${MAX_BATCH_SIZE}.`,
      });
    }

    // Validate each item
    for (let i = 0; i < logs.length; i++) {
      const item = logs[i];
      if (!item || typeof item !== 'object') {
        return res.status(400).json({ success: false, error: `Item at index ${i} must be an object.` });
      }
      if (!item.source || typeof item.source !== 'string' || !item.source.trim()) {
        return res.status(400).json({ success: false, error: `Item at index ${i} missing 'source'.` });
      }
      if (!item.content || typeof item.content !== 'string' || !item.content.trim()) {
        return res.status(400).json({ success: false, error: `Item at index ${i} missing 'content'.` });
      }
    }

    const receivedAt = new Date();

    const result = await prisma.$transaction(async (tx) => {
      let ingested = 0;
      let skipped = 0;
      const events = [];

      for (const item of logs) {
        const source = item.source.trim();
        const rawContent = item.content;
        const eventRecordId = item.eventRecordId?.toString() || null;

        // Deduplication: check if this Windows Record ID was already ingested
        // by looking for a raw_log with matching source and eventRecordId in metadata
        if (eventRecordId) {
          // We store eventRecordId in the Event.metadata field
          const existing = await tx.event.findFirst({
            where: {
              eventType: { startsWith: 'windows_' },
              metadata: { path: ['eventRecordId'], equals: eventRecordId },
              rawLog: { source },
            },
            select: { id: true },
          });
          if (existing) {
            skipped++;
            continue;
          }
        }

        const normalized = normalizeLog(source, rawContent, receivedAt);

        // Merge Windows-specific fields into metadata
        if (item.eventId) {
          normalized.metadata = {
            ...(normalized.metadata || {}),
            eventId: item.eventId,
            eventRecordId,
            channel: source,
            collectorName: agentToken.name,
          };
        }

        const rawLog = await tx.rawLog.create({
          data: { source, rawContent, receivedAt },
        });

        const event = await tx.event.create({
          data: {
            rawLogId: rawLog.id,
            timestamp: normalized.timestamp,
            eventType: normalized.eventType,
            srcIp: normalized.srcIp,
            dstIp: normalized.dstIp,
            srcPort: normalized.srcPort,
            dstPort: normalized.dstPort,
            username: normalized.username,
            hostname: normalized.hostname,
            message: normalized.message,
            severity: normalized.severity,
            metadata: normalized.metadata,
          },
        });

        events.push(event);
        ingested++;
      }

      // Update collector status with the latest event timestamp
      const latestTimestamp = events.length > 0
        ? events.reduce((max, e) => e.timestamp > max ? e.timestamp : max, events[0].timestamp)
        : null;

      await tx.collectorStatus.upsert({
        where: { agentTokenId: agentToken.id },
        create: {
          agentTokenId: agentToken.id,
          lastCheckinAt: receivedAt,
          lastEventAt: latestTimestamp,
          eventsIngested: ingested,
          status: 'OK',
          channels: [],
        },
        update: {
          lastCheckinAt: receivedAt,
          lastEventAt: latestTimestamp || undefined,
          eventsIngested: { increment: ingested },
          status: 'OK',
          lastError: null,
        },
      });

      return { ingested, skipped, events };
    });

    return res.status(201).json({
      success: true,
      message: `Ingested ${result.ingested} event(s). Skipped ${result.skipped} duplicate(s).`,
      data: {
        ingested: result.ingested,
        skipped: result.skipped,
        eventIds: result.events.map((e) => e.id),
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/collectors
 * Lists all enrolled collectors and their status (accessible to all authed users).
 */
export async function listCollectors(req, res, next) {
  try {
    const tokens = await prisma.agentToken.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        enabled: true,
        lastUsedAt: true,
        createdAt: true,
        revokedAt: true,
        collectorStatus: {
          select: {
            hostname: true,
            platform: true,
            collectorVersion: true,
            lastCheckinAt: true,
            lastEventAt: true,
            eventsIngested: true,
            status: true,
            channels: true,
            lastError: true,
            updatedAt: true,
          },
        },
      },
    });

    return res.json({ success: true, data: tokens });
  } catch (err) {
    next(err);
  }
}
