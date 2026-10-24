// src/modules/logs/logs.controller.js
// Controllers for log ingestion and raw log retrieval.

import prisma from '../../config/prisma.js';
import { normalizeLog } from './logParser.js';

const MAX_BATCH_SIZE = 100;
const MAX_SOURCE_LENGTH = 100;

/**
 * POST /api/logs/ingest
 * Ingests single or batch log entries atomically within a Prisma transaction.
 * Requires ADMIN or ANALYST role.
 */
export async function ingestLogs(req, res, next) {
  try {
    const body = req.body || {};

    // 1. Normalize request input into an array of items
    let rawItems = [];
    if (Array.isArray(body.logs)) {
      rawItems = body.logs;
    } else if (body.content && typeof body.content === 'string') {
      rawItems = [{ source: body.source, content: body.content }];
    } else {
      return res.status(400).json({
        success: false,
        error: "Invalid request payload. Expected { source, content } or { logs: [{ source, content }, ...] }.",
      });
    }

    // 2. Validate batch limits
    if (rawItems.length === 0) {
      return res.status(400).json({
        success: false,
        error: "Logs batch cannot be empty.",
      });
    }

    if (rawItems.length > MAX_BATCH_SIZE) {
      return res.status(400).json({
        success: false,
        error: `Batch exceeds maximum limit of ${MAX_BATCH_SIZE} logs per request. Received: ${rawItems.length}.`,
      });
    }

    // 3. Validate each item's structure
    for (let i = 0; i < rawItems.length; i++) {
      const item = rawItems[i];
      if (!item || typeof item !== 'object') {
        return res.status(400).json({
          success: false,
          error: `Log item at index ${i} must be an object with 'source' and 'content'.`,
        });
      }

      if (!item.source || typeof item.source !== 'string' || !item.source.trim()) {
        return res.status(400).json({
          success: false,
          error: `Log item at index ${i} is missing a non-empty 'source' string.`,
        });
      }

      if (item.source.length > MAX_SOURCE_LENGTH) {
        return res.status(400).json({
          success: false,
          error: `Log item at index ${i} source exceeds maximum length of ${MAX_SOURCE_LENGTH} characters.`,
        });
      }

      if (!item.content || typeof item.content !== 'string' || !item.content.trim()) {
        return res.status(400).json({
          success: false,
          error: `Log item at index ${i} is missing a non-empty 'content' string.`,
        });
      }
    }

    const receivedAt = new Date();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

    // 4. Parse and normalize all items
    const parsedEntries = rawItems.map((item) => {
      const source = item.source.trim();
      const rawContent = item.content;
      const normalized = normalizeLog(source, rawContent, receivedAt);
      return {
        source,
        rawContent,
        normalized,
      };
    });

    // 5. Execute storage atomically inside a Prisma transaction
    const result = await prisma.$transaction(async (tx) => {
      const createdEvents = [];
      const sourcesSet = new Set();

      for (const entry of parsedEntries) {
        sourcesSet.add(entry.source);

        // A. Store untouched raw log
        const rawLog = await tx.rawLog.create({
          data: {
            source: entry.source,
            rawContent: entry.rawContent,
            receivedAt,
          },
        });

        // B. Store normalized event linked to raw log
        const event = await tx.event.create({
          data: {
            rawLogId: rawLog.id,
            timestamp: entry.normalized.timestamp,
            eventType: entry.normalized.eventType,
            srcIp: entry.normalized.srcIp,
            dstIp: entry.normalized.dstIp,
            srcPort: entry.normalized.srcPort,
            dstPort: entry.normalized.dstPort,
            username: entry.normalized.username,
            hostname: entry.normalized.hostname,
            message: entry.normalized.message,
            severity: entry.normalized.severity,
            metadata: entry.normalized.metadata,
          },
        });

        createdEvents.push(event);
      }

      // C. Include security audit record in transaction
      if (req.user) {
        await tx.auditLog.create({
          data: {
            userId: req.user.id,
            action: 'LOGS_INGESTED',
            targetType: 'Event',
            ipAddress: clientIp,
            details: {
              count: createdEvents.length,
              sources: Array.from(sourcesSet),
            },
          },
        });
      }

      return createdEvents;
    });

    return res.status(201).json({
      success: true,
      message: `Successfully ingested and normalized ${result.length} log(s).`,
      data: {
        count: result.length,
        events: result.map((e) => ({
          id: e.id,
          rawLogId: e.rawLogId,
          timestamp: e.timestamp,
          eventType: e.eventType,
          severity: e.severity,
          srcIp: e.srcIp,
          dstIp: e.dstIp,
          srcPort: e.srcPort,
          dstPort: e.dstPort,
          username: e.username,
          hostname: e.hostname,
        })),
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/logs
 * Retrieves paginated list of raw logs with optional source filter.
 * Protected by requireAuth.
 */
export async function getRawLogs(req, res, next) {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const { source, search } = req.query;

    const where = {};
    if (source && typeof source === 'string') {
      where.source = { equals: source.trim(), mode: 'insensitive' };
    }
    if (search && typeof search === 'string') {
      where.rawContent = { contains: search.trim(), mode: 'insensitive' };
    }

    const [logs, total] = await Promise.all([
      prisma.rawLog.findMany({
        where,
        skip,
        take: limit,
        orderBy: { receivedAt: 'desc' },
      }),
      prisma.rawLog.count({ where }),
    ]);

    return res.json({
      success: true,
      data: logs,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit) || 1,
      },
    });
  } catch (err) {
    next(err);
  }
}
