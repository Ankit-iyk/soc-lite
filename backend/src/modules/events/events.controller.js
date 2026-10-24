// src/modules/events/events.controller.js
// Controllers for normalized event browsing and event detail queries.

import prisma from '../../config/prisma.js';
import { Severity } from '@prisma/client';

/**
 * GET /api/events
 * Paginated query for normalized events with filtering.
 * Protected by requireAuth.
 */
export async function getEvents(req, res, next) {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const { eventType, severity, srcIp, dstIp, username, startDate, endDate } = req.query;

    const where = {};

    if (eventType && typeof eventType === 'string') {
      where.eventType = { equals: eventType.trim(), mode: 'insensitive' };
    }

    if (severity && typeof severity === 'string') {
      const upperSev = severity.trim().toUpperCase();
      if (upperSev in Severity) {
        where.severity = upperSev;
      }
    }

    if (srcIp && typeof srcIp === 'string') {
      where.srcIp = { equals: srcIp.trim() };
    }

    if (dstIp && typeof dstIp === 'string') {
      where.dstIp = { equals: dstIp.trim() };
    }

    if (username && typeof username === 'string') {
      where.username = { equals: username.trim(), mode: 'insensitive' };
    }

    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) {
        const start = new Date(startDate);
        if (!Number.isNaN(start.getTime())) where.timestamp.gte = start;
      }
      if (endDate) {
        const end = new Date(endDate);
        if (!Number.isNaN(end.getTime())) where.timestamp.lte = end;
      }
    }

    const [events, total] = await Promise.all([
      prisma.event.findMany({
        where,
        skip,
        take: limit,
        orderBy: { timestamp: 'desc' },
      }),
      prisma.event.count({ where }),
    ]);

    return res.json({
      success: true,
      data: events,
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

/**
 * GET /api/events/:id
 * Fetches single normalized event including its originating raw log.
 * Protected by requireAuth.
 */
export async function getEventById(req, res, next) {
  try {
    const { id } = req.params;

    if (!id || typeof id !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Event ID parameter is required.',
      });
    }

    const event = await prisma.event.findUnique({
      where: { id },
      include: {
        rawLog: true,
      },
    });

    if (!event) {
      return res.status(404).json({
        success: false,
        error: 'Event not found.',
      });
    }

    return res.json({
      success: true,
      data: event,
    });
  } catch (err) {
    next(err);
  }
}
