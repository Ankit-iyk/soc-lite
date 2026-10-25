// src/modules/alerts/alerts.controller.js
// Controllers for Alert Management (Phase 5 Step 1).

import prisma from '../../config/prisma.js';
import { AlertStatus } from '@prisma/client';
import {
  validateAlertId,
  validateAlertQueryParams,
  validateUpdateStatusPayload,
} from './alerts.validation.js';

/**
 * GET /api/alerts
 * Returns a paginated list of alerts with filtering and rule association.
 * Default ordering: newest alerts first (firedAt desc).
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getAlerts(req, res, next) {
  try {
    const { isValid, error, sanitized } = validateAlertQueryParams(req.query);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        error,
      });
    }

    const { page, limit, status, severity, ruleId, search, startDate, endDate } = sanitized;
    const skip = (page - 1) * limit;

    const where = {};

    if (status) {
      where.status = status;
    }

    if (severity) {
      where.severity = severity;
    }

    if (ruleId) {
      where.ruleId = ruleId;
    }

    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (startDate || endDate) {
      where.firedAt = {};
      if (startDate) {
        where.firedAt.gte = startDate;
      }
      if (endDate) {
        where.firedAt.lte = endDate;
      }
    }

    const [alerts, total] = await Promise.all([
      prisma.alert.findMany({
        where,
        skip,
        take: limit,
        orderBy: { firedAt: 'desc' },
        include: {
          rule: {
            select: {
              id: true,
              name: true,
              type: true,
              severity: true,
              enabled: true,
            },
          },
          _count: {
            select: { alertEvents: true },
          },
        },
      }),
      prisma.alert.count({ where }),
    ]);

    const data = alerts.map((a) => ({
      id: a.id,
      ruleId: a.ruleId,
      title: a.title,
      description: a.description,
      severity: a.severity,
      status: a.status,
      firedAt: a.firedAt,
      acknowledgedAt: a.acknowledgedAt,
      acknowledgedBy: a.acknowledgedBy,
      rule: a.rule,
      evidenceCount: a._count?.alertEvents ?? 0,
    }));

    return res.status(200).json({
      success: true,
      data,
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
 * GET /api/alerts/stats
 * Aggregates alert statistics: total alerts, counts by status, and counts by severity.
 * Ensures counts reflect the exact enum definitions and handles empty database gracefully.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getAlertStats(_req, res, next) {
  try {
    const [total, statusGroups, severityGroups] = await Promise.all([
      prisma.alert.count(),
      prisma.alert.groupBy({
        by: ['status'],
        _count: { _all: true },
      }),
      prisma.alert.groupBy({
        by: ['severity'],
        _count: { _all: true },
      }),
    ]);

    const byStatus = {
      OPEN: 0,
      ACKNOWLEDGED: 0,
      CLOSED: 0,
    };
    for (const group of statusGroups) {
      if (group.status in byStatus) {
        byStatus[group.status] = group._count._all;
      }
    }

    const bySeverity = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    for (const group of severityGroups) {
      if (group.severity in bySeverity) {
        bySeverity[group.severity] = group._count._all;
      }
    }

    return res.status(200).json({
      success: true,
      data: {
        total,
        byStatus,
        bySeverity,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/alerts/:id
 * Fetches a single alert by ID with its detection rule and full evidence chain:
 * AlertEvent -> Event -> RawLog (originating log source and content).
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getAlertById(req, res, next) {
  try {
    const { id } = req.params;
    const validation = validateAlertId(id);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        error: validation.error,
      });
    }

    const alert = await prisma.alert.findUnique({
      where: { id },
      include: {
        rule: {
          select: {
            id: true,
            name: true,
            type: true,
            description: true,
            severity: true,
            enabled: true,
            config: true,
            createdAt: true,
            updatedAt: true,
          },
        },
        alertEvents: {
          include: {
            event: {
              include: {
                rawLog: {
                  select: {
                    id: true,
                    source: true,
                    receivedAt: true,
                    rawContent: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!alert) {
      return res.status(404).json({
        success: false,
        error: `Alert not found with ID "${id}".`,
      });
    }

    const formattedAlert = {
      id: alert.id,
      ruleId: alert.ruleId,
      title: alert.title,
      description: alert.description,
      severity: alert.severity,
      status: alert.status,
      firedAt: alert.firedAt,
      acknowledgedAt: alert.acknowledgedAt,
      acknowledgedBy: alert.acknowledgedBy,
      rule: alert.rule,
      evidenceCount: alert.alertEvents.length,
      evidence: alert.alertEvents.map((ae) => ({
        alertId: ae.alertId,
        eventId: ae.eventId,
        event: ae.event,
      })),
    };

    return res.status(200).json({
      success: true,
      data: formattedAlert,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * PATCH /api/alerts/:id/status
 * Transitions an alert's status to ACKNOWLEDGED or CLOSED.
 *
 * State transition rules:
 * - OPEN -> ACKNOWLEDGED: sets acknowledgedAt, acknowledgedBy from authenticated user.
 * - OPEN -> CLOSED: closes the alert.
 * - ACKNOWLEDGED -> CLOSED: preserves existing acknowledgedAt and acknowledgedBy metadata.
 * - CLOSED -> ACKNOWLEDGED: rejected (cannot acknowledge an already closed alert).
 * - Target status identical to current: rejected with 400 to prevent duplicate audit logs.
 *
 * Atomic Prisma transaction ensures status update and AuditLog entry are written together.
 * Allowed roles: ADMIN, ANALYST only.
 */
export async function updateAlertStatus(req, res, next) {
  try {
    const { id } = req.params;
    const idValidation = validateAlertId(id);
    if (!idValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: idValidation.error,
      });
    }

    const payloadValidation = validateUpdateStatusPayload(req.body);
    if (!payloadValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: payloadValidation.error,
      });
    }

    const targetStatus = payloadValidation.status;

    // Server-side actor context from authenticated user
    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Fetch current alert inside transaction
      const alert = await tx.alert.findUnique({
        where: { id },
        include: {
          rule: {
            select: { id: true, name: true, type: true, severity: true },
          },
        },
      });

      if (!alert) {
        return { notFound: true };
      }

      // 2. Prevent redundant/no-op transitions
      if (alert.status === targetStatus) {
        return {
          conflict: true,
          message: `Alert is already in ${targetStatus} status.`,
        };
      }

      // 3. Enforce sensible transition rules
      if (alert.status === AlertStatus.CLOSED && targetStatus === AlertStatus.ACKNOWLEDGED) {
        return {
          invalidTransition: true,
          message: 'Cannot acknowledge an alert that is already CLOSED.',
        };
      }

      // 4. Prepare update data
      const previousState = {
        status: alert.status,
        acknowledgedAt: alert.acknowledgedAt,
        acknowledgedBy: alert.acknowledgedBy,
      };

      const updateData = {
        status: targetStatus,
      };

      const auditAction = targetStatus === AlertStatus.ACKNOWLEDGED ? 'ALERT_ACK' : 'ALERT_CLOSE';

      if (targetStatus === AlertStatus.ACKNOWLEDGED) {
        updateData.acknowledgedAt = new Date();
        updateData.acknowledgedBy = actorIdentifier;
      }
      // If closing an already acknowledged alert, existing acknowledgedAt and acknowledgedBy are preserved.

      // 4b. Perform atomic conditional update to guard against concurrent status transitions
      const updateResult = await tx.alert.updateMany({
        where: {
          id: alert.id,
          status: alert.status,
        },
        data: updateData,
      });

      if (updateResult.count === 0) {
        const latest = await tx.alert.findUnique({ where: { id: alert.id } });
        return {
          conflict: true,
          message: `Alert is already in ${latest?.status || targetStatus} status.`,
        };
      }

      const updatedAlert = await tx.alert.findUnique({
        where: { id: alert.id },
        include: {
          rule: {
            select: { id: true, name: true, type: true, severity: true },
          },
        },
      });

      const updatedState = {
        status: updatedAlert.status,
        acknowledgedAt: updatedAlert.acknowledgedAt,
        acknowledgedBy: updatedAlert.acknowledgedBy,
      };

      // 5. Create audit log entry inside transaction
      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: auditAction,
          targetType: 'Alert',
          targetId: alert.id,
          ipAddress: clientIp,
          details: {
            alertTitle: alert.title,
            ruleName: alert.rule?.name || null,
            previous: previousState,
            updated: updatedState,
            actionBy: actorIdentifier,
          },
        },
      });

      return {
        success: true,
        alert: updatedAlert,
      };
    });

    if (result.notFound) {
      return res.status(404).json({
        success: false,
        error: `Alert not found with ID "${id}".`,
      });
    }

    if (result.conflict) {
      return res.status(400).json({
        success: false,
        error: result.message,
      });
    }

    if (result.invalidTransition) {
      return res.status(400).json({
        success: false,
        error: result.message,
      });
    }

    return res.status(200).json({
      success: true,
      message: `Alert "${result.alert.title}" successfully transitioned to ${result.alert.status}.`,
      data: result.alert,
    });
  } catch (err) {
    next(err);
  }
}
