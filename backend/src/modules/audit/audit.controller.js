// src/modules/audit/audit.controller.js
// Controllers for Security Audit Trail & Activity Inspection (Phase 12).

import prisma from '../../config/prisma.js';
import { validateAuditQueryParams } from './audit.validation.js';

/**
 * GET /api/audit-logs
 * Retrieves paginated, filterable audit log records with user attribution.
 * Accessible to ADMIN and ANALYST roles only (VIEWER is forbidden).
 */
export async function getAuditLogs(req, res, next) {
  try {
    const { isValid, error, sanitized } = validateAuditQueryParams(req.query);
    if (!isValid) {
      return res.status(400).json({ success: false, error });
    }

    const { page, limit, action, targetType, userId, search, startDate, endDate } = sanitized;
    const skip = (page - 1) * limit;

    const where = {};

    if (action) {
      where.action = action;
    }

    if (targetType) {
      where.targetType = targetType;
    }

    if (userId) {
      where.userId = userId;
    }

    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) where.timestamp.gte = startDate;
      if (endDate) where.timestamp.lte = endDate;
    }

    if (search) {
      where.OR = [
        { action: { contains: search, mode: 'insensitive' } },
        { targetType: { contains: search, mode: 'insensitive' } },
        { targetId: { contains: search, mode: 'insensitive' } },
        { ipAddress: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        skip,
        take: limit,
        orderBy: [{ timestamp: 'desc' }, { id: 'desc' }],
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              role: true,
            },
          },
        },
      }),
      prisma.auditLog.count({ where }),
    ]);

    const totalPages = Math.ceil(total / limit) || 1;

    return res.status(200).json({
      success: true,
      data: {
        logs,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
        },
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/audit-logs/stats
 * Returns summary statistics for security audit logging.
 * Accessible to ADMIN and ANALYST roles only.
 */
export async function getAuditStats(req, res, next) {
  try {
    const now = new Date();
    const past24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const [total, past24hCount, actionGroups, targetGroups] = await Promise.all([
      prisma.auditLog.count(),
      prisma.auditLog.count({
        where: { timestamp: { gte: past24h } },
      }),
      prisma.auditLog.groupBy({
        by: ['action'],
        _count: { _all: true },
        orderBy: { _count: { action: 'desc' } },
        take: 8,
      }),
      prisma.auditLog.groupBy({
        by: ['targetType'],
        _count: { _all: true },
        orderBy: { _count: { targetType: 'desc' } },
        take: 8,
      }),
    ]);

    const topActions = actionGroups.map((g) => ({
      action: g.action,
      count: g._count._all,
    }));

    const topTargetTypes = targetGroups
      .filter((g) => g.targetType !== null)
      .map((g) => ({
        targetType: g.targetType,
        count: g._count._all,
      }));

    return res.status(200).json({
      success: true,
      data: {
        total,
        past24hCount,
        topActions,
        topTargetTypes,
      },
    });
  } catch (err) {
    next(err);
  }
}
