// src/modules/incidents/incidents.controller.js
// Controllers for Incident Tracking and Investigation Management (Phase 6).

import prisma from '../../config/prisma.js';
import { IncidentStatus } from '@prisma/client';
import {
  validateIncidentId,
  validateIncidentQueryParams,
  validateCreateIncidentPayload,
  validateUpdateIncidentPayload,
  validateLinkAlertsPayload,
  validateAddNotePayload,
  isValidUuid,
} from './incidents.validation.js';

/**
 * Format a human-readable identifier for an incident.
 * e.g. "INC-A1B2C3D4"
 */
function formatReadableId(id) {
  if (!id || typeof id !== 'string') return 'INC-UNKNOWN';
  return `INC-${id.slice(0, 8).toUpperCase()}`;
}

/**
 * GET /api/incidents
 * Returns a paginated list of incidents with filtering, search, and assignee.
 * Default ordering: newest incidents first (createdAt desc).
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getIncidents(req, res, next) {
  try {
    const { isValid, error, sanitized } = validateIncidentQueryParams(req.query);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        error,
      });
    }

    const { page, limit, status, severity, assignedToId, search, startDate, endDate } = sanitized;
    const skip = (page - 1) * limit;

    const where = {};

    if (status) {
      where.status = status;
    }

    if (severity) {
      where.severity = severity;
    }

    if (assignedToId) {
      where.assignedToId = assignedToId;
    }

    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) {
        where.createdAt.gte = startDate;
      }
      if (endDate) {
        where.createdAt.lte = endDate;
      }
    }

    const [incidents, total] = await Promise.all([
      prisma.incident.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          assignedTo: {
            select: {
              id: true,
              name: true,
              email: true,
              role: true,
            },
          },
          _count: {
            select: { incidentAlerts: true },
          },
        },
      }),
      prisma.incident.count({ where }),
    ]);

    const data = incidents.map((inc) => ({
      id: inc.id,
      readableId: formatReadableId(inc.id),
      title: inc.title,
      description: inc.description,
      severity: inc.severity,
      status: inc.status,
      assignedToId: inc.assignedToId,
      assignedTo: inc.assignedTo,
      createdAt: inc.createdAt,
      updatedAt: inc.updatedAt,
      resolvedAt: inc.resolvedAt,
      alertCount: inc._count?.incidentAlerts ?? 0,
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
 * GET /api/incidents/stats
 * Aggregates incident statistics: total count, counts by status, and counts by severity.
 * Ensures counts reflect exact enum definitions and handles empty database gracefully.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getIncidentStats(_req, res, next) {
  try {
    const [total, statusGroups, severityGroups] = await Promise.all([
      prisma.incident.count(),
      prisma.incident.groupBy({
        by: ['status'],
        _count: { _all: true },
      }),
      prisma.incident.groupBy({
        by: ['severity'],
        _count: { _all: true },
      }),
    ]);

    const byStatus = {
      OPEN: 0,
      INVESTIGATING: 0,
      RESOLVED: 0,
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
 * GET /api/incidents/:id
 * Fetches single incident with its assigned analyst, linked alerts (with rules),
 * and investigation history timeline constructed from AuditLog entries.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getIncidentById(req, res, next) {
  try {
    const { id } = req.params;
    const validation = validateIncidentId(id);
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        error: validation.error,
      });
    }

    const [incident, auditLogs] = await Promise.all([
      prisma.incident.findUnique({
        where: { id },
        include: {
          assignedTo: {
            select: {
              id: true,
              name: true,
              email: true,
              role: true,
            },
          },
          incidentAlerts: {
            include: {
              alert: {
                include: {
                  rule: {
                    select: {
                      id: true,
                      name: true,
                      type: true,
                      severity: true,
                    },
                  },
                },
              },
            },
          },
        },
      }),
      prisma.auditLog.findMany({
        where: {
          targetType: 'Incident',
          targetId: id,
        },
        orderBy: { timestamp: 'desc' },
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
    ]);

    if (!incident) {
      return res.status(404).json({
        success: false,
        error: `Incident not found with ID "${id}".`,
      });
    }

    const timeline = auditLogs.map((log) => ({
      id: log.id,
      action: log.action,
      timestamp: log.timestamp,
      actor: log.user
        ? {
            id: log.user.id,
            name: log.user.name,
            email: log.user.email,
            role: log.user.role,
          }
        : null,
      details: log.details,
    }));

    const formattedIncident = {
      id: incident.id,
      readableId: formatReadableId(incident.id),
      title: incident.title,
      description: incident.description,
      severity: incident.severity,
      status: incident.status,
      assignedToId: incident.assignedToId,
      assignedTo: incident.assignedTo,
      createdAt: incident.createdAt,
      updatedAt: incident.updatedAt,
      resolvedAt: incident.resolvedAt,
      alertCount: incident.incidentAlerts.length,
      alerts: incident.incidentAlerts.map((ia) => ({
        id: ia.alert.id,
        ruleId: ia.alert.ruleId,
        title: ia.alert.title,
        description: ia.alert.description,
        severity: ia.alert.severity,
        status: ia.alert.status,
        firedAt: ia.alert.firedAt,
        acknowledgedAt: ia.alert.acknowledgedAt,
        acknowledgedBy: ia.alert.acknowledgedBy,
        rule: ia.alert.rule,
      })),
      timeline,
    };

    return res.status(200).json({
      success: true,
      data: formattedIncident,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/incidents
 * Creates a new incident with optional initial alert links.
 * Atomic Prisma transaction ensures incident, alert links, and AuditLog are written together.
 * Allowed roles: ADMIN, ANALYST only.
 */
export async function createIncident(req, res, next) {
  try {
    const { isValid, error, sanitized } = validateCreateIncidentPayload(req.body);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        error,
      });
    }

    const { title, description, severity, status, assignedToId, alertIds } = sanitized;

    // Verify assigned user exists if assignedToId was provided
    if (assignedToId) {
      const assignedUser = await prisma.user.findUnique({
        where: { id: assignedToId },
        select: { id: true, name: true },
      });
      if (!assignedUser) {
        return res.status(400).json({
          success: false,
          error: `Assigned user not found with ID "${assignedToId}".`,
        });
      }
    }

    // Verify all referenced alerts exist if alertIds was provided
    if (alertIds.length > 0) {
      const existingAlerts = await prisma.alert.findMany({
        where: { id: { in: alertIds } },
        select: { id: true },
      });
      if (existingAlerts.length !== alertIds.length) {
        const foundSet = new Set(existingAlerts.map((a) => a.id));
        const missing = alertIds.filter((id) => !foundSet.has(id));
        return res.status(400).json({
          success: false,
          error: `One or more referenced alerts do not exist: ${missing.join(', ')}.`,
        });
      }
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Create incident
      const incident = await tx.incident.create({
        data: {
          title,
          description,
          severity,
          status,
          assignedToId,
          resolvedAt: status === IncidentStatus.RESOLVED ? new Date() : null,
        },
        include: {
          assignedTo: {
            select: {
              id: true,
              name: true,
              email: true,
              role: true,
            },
          },
        },
      });

      // 2. Link initial alerts
      if (alertIds.length > 0) {
        await tx.incidentAlert.createMany({
          data: alertIds.map((alertId) => ({
            incidentId: incident.id,
            alertId,
          })),
        });
      }

      // 3. Create AuditLog entry
      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: 'INCIDENT_CREATE',
          targetType: 'Incident',
          targetId: incident.id,
          ipAddress: clientIp,
          details: {
            title,
            severity,
            status,
            assignedToId,
            initialAlertCount: alertIds.length,
            createdBy: actorIdentifier,
          },
        },
      });

      return incident;
    });

    return res.status(201).json({
      success: true,
      message: `Incident "${result.title}" created successfully.`,
      data: {
        id: result.id,
        readableId: formatReadableId(result.id),
        title: result.title,
        description: result.description,
        severity: result.severity,
        status: result.status,
        assignedToId: result.assignedToId,
        assignedTo: result.assignedTo,
        createdAt: result.createdAt,
        updatedAt: result.updatedAt,
        resolvedAt: result.resolvedAt,
        alertCount: alertIds.length,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * PATCH /api/incidents/:id
 * Updates permitted incident fields (title, description, severity, status, assignedToId).
 * Enforces resolvedAt transitions and concurrency safety.
 * Allowed roles: ADMIN, ANALYST only.
 */
export async function updateIncident(req, res, next) {
  try {
    const { id } = req.params;
    const idValidation = validateIncidentId(id);
    if (!idValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: idValidation.error,
      });
    }

    const payloadValidation = validateUpdateIncidentPayload(req.body);
    if (!payloadValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: payloadValidation.error,
      });
    }

    const { sanitized } = payloadValidation;

    // Verify assigned user exists if assignedToId is being changed to a non-null UUID
    if ('assignedToId' in sanitized && sanitized.assignedToId !== null) {
      const assignedUser = await prisma.user.findUnique({
        where: { id: sanitized.assignedToId },
        select: { id: true },
      });
      if (!assignedUser) {
        return res.status(400).json({
          success: false,
          error: `Assigned user not found with ID "${sanitized.assignedToId}".`,
        });
      }
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Fetch current incident inside transaction
      const incident = await tx.incident.findUnique({
        where: { id },
      });

      if (!incident) {
        return { notFound: true };
      }

      // 2. Prepare update data & track changes
      const updateData = { ...sanitized };
      const previousState = {};
      const updatedState = {};

      for (const field of Object.keys(sanitized)) {
        previousState[field] = incident[field];
        updatedState[field] = sanitized[field];
      }

      // Enforce resolvedAt semantics:
      if ('status' in sanitized) {
        const nextStatus = sanitized.status;
        const prevStatus = incident.status;

        if (nextStatus === IncidentStatus.RESOLVED && prevStatus !== IncidentStatus.RESOLVED) {
          updateData.resolvedAt = new Date();
          updatedState.resolvedAt = updateData.resolvedAt;
          previousState.resolvedAt = incident.resolvedAt;
        } else if (
          (nextStatus === IncidentStatus.OPEN || nextStatus === IncidentStatus.INVESTIGATING) &&
          incident.resolvedAt !== null
        ) {
          // Reopening a previously resolved incident clears resolvedAt
          updateData.resolvedAt = null;
          updatedState.resolvedAt = null;
          previousState.resolvedAt = incident.resolvedAt;
        } else if (nextStatus === IncidentStatus.CLOSED) {
          // Preserves existing resolvedAt if resolved earlier, or leaves null
        }
      }

      // 3. Concurrency guard using updatedAt precondition
      const updateResult = await tx.incident.updateMany({
        where: {
          id: incident.id,
          updatedAt: incident.updatedAt,
        },
        data: updateData,
      });

      if (updateResult.count === 0) {
        return { conflict: true };
      }

      const updatedIncident = await tx.incident.findUnique({
        where: { id: incident.id },
        include: {
          assignedTo: {
            select: {
              id: true,
              name: true,
              email: true,
              role: true,
            },
          },
          _count: {
            select: { incidentAlerts: true },
          },
        },
      });

      // 4. Create AuditLog entry
      const statusChanged = 'status' in sanitized && sanitized.status !== incident.status;
      const auditAction = statusChanged ? 'INCIDENT_STATUS_CHANGE' : 'INCIDENT_UPDATE';

      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: auditAction,
          targetType: 'Incident',
          targetId: incident.id,
          ipAddress: clientIp,
          details: {
            changedFields: Object.keys(updateData),
            previous: previousState,
            updated: updatedState,
            actionBy: actorIdentifier,
          },
        },
      });

      return {
        success: true,
        incident: updatedIncident,
      };
    });

    if (result.notFound) {
      return res.status(404).json({
        success: false,
        error: `Incident not found with ID "${id}".`,
      });
    }

    if (result.conflict) {
      return res.status(409).json({
        success: false,
        error: 'Incident was concurrently updated by another request. Please refresh and retry.',
      });
    }

    const inc = result.incident;
    return res.status(200).json({
      success: true,
      message: `Incident "${inc.title}" updated successfully.`,
      data: {
        id: inc.id,
        readableId: formatReadableId(inc.id),
        title: inc.title,
        description: inc.description,
        severity: inc.severity,
        status: inc.status,
        assignedToId: inc.assignedToId,
        assignedTo: inc.assignedTo,
        createdAt: inc.createdAt,
        updatedAt: inc.updatedAt,
        resolvedAt: inc.resolvedAt,
        alertCount: inc._count?.incidentAlerts ?? 0,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/incidents/:id/alerts
 * Links one or more existing alerts to an incident.
 * Skips already-linked alerts to prevent duplicate violations.
 * Allowed roles: ADMIN, ANALYST only.
 */
export async function linkAlerts(req, res, next) {
  try {
    const { id } = req.params;
    const idValidation = validateIncidentId(id);
    if (!idValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: idValidation.error,
      });
    }

    const payloadValidation = validateLinkAlertsPayload(req.body);
    if (!payloadValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: payloadValidation.error,
      });
    }

    const { alertIds } = payloadValidation;

    // Verify all specified alerts exist in the database
    const existingAlerts = await prisma.alert.findMany({
      where: { id: { in: alertIds } },
      select: { id: true, title: true },
    });

    if (existingAlerts.length !== alertIds.length) {
      const foundSet = new Set(existingAlerts.map((a) => a.id));
      const missing = alertIds.filter((aId) => !foundSet.has(aId));
      return res.status(400).json({
        success: false,
        error: `One or more specified alerts do not exist: ${missing.join(', ')}.`,
      });
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Verify incident exists
      const incident = await tx.incident.findUnique({
        where: { id },
        select: { id: true, title: true },
      });

      if (!incident) {
        return { notFound: true };
      }

      // 2. Identify alerts not yet linked to avoid duplicate primary key violations
      const alreadyLinked = await tx.incidentAlert.findMany({
        where: {
          incidentId: id,
          alertId: { in: alertIds },
        },
        select: { alertId: true },
      });

      const alreadyLinkedSet = new Set(alreadyLinked.map((l) => l.alertId));
      const newlyLinkedAlertIds = alertIds.filter((aId) => !alreadyLinkedSet.has(aId));

      if (newlyLinkedAlertIds.length === 0) {
        return {
          noOp: true,
          message: 'All specified alerts are already linked to this incident.',
        };
      }

      // 3. Insert newly linked records
      // skipDuplicates: true makes the insert idempotent at the database level.
      // This handles concurrent requests that both pass the pre-check above and
      // then race into createMany simultaneously — without it, the second insert
      // would hit a unique-constraint violation and return a 500 instead of 200.
      await tx.incidentAlert.createMany({
        data: newlyLinkedAlertIds.map((alertId) => ({
          incidentId: id,
          alertId,
        })),
        skipDuplicates: true,
      });

      // Update incident's updatedAt timestamp
      await tx.incident.update({
        where: { id },
        data: { updatedAt: new Date() },
      });

      // 4. Create AuditLog entry
      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: 'INCIDENT_ALERT_LINK',
          targetType: 'Incident',
          targetId: id,
          ipAddress: clientIp,
          details: {
            incidentTitle: incident.title,
            newlyLinkedAlertIds,
            count: newlyLinkedAlertIds.length,
            actionBy: actorIdentifier,
          },
        },
      });

      const totalLinkedCount = await tx.incidentAlert.count({
        where: { incidentId: id },
      });

      return {
        success: true,
        incident,
        newlyLinkedAlertIds,
        totalLinkedCount,
      };
    });

    if (result.notFound) {
      return res.status(404).json({
        success: false,
        error: `Incident not found with ID "${id}".`,
      });
    }

    if (result.noOp) {
      return res.status(200).json({
        success: true,
        message: result.message,
        data: { newlyLinked: [], totalAlerts: alertIds.length },
      });
    }

    return res.status(200).json({
      success: true,
      message: `Successfully linked ${result.newlyLinkedAlertIds.length} alert(s) to incident.`,
      data: {
        newlyLinkedAlertIds: result.newlyLinkedAlertIds,
        totalAlerts: result.totalLinkedCount,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * DELETE /api/incidents/:id/alerts/:alertId
 * Unlinks an alert from an incident.
 * Allowed roles: ADMIN, ANALYST only.
 */
export async function unlinkAlert(req, res, next) {
  try {
    const { id, alertId } = req.params;
    const idValidation = validateIncidentId(id);
    if (!idValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: idValidation.error,
      });
    }

    if (!alertId || typeof alertId !== 'string' || !isValidUuid(alertId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid alert ID parameter. Must be a valid UUID.',
      });
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Verify incident exists
      const incident = await tx.incident.findUnique({
        where: { id },
        select: { id: true, title: true },
      });

      if (!incident) {
        return { notFoundIncident: true };
      }

      // 2. Check if the link exists
      const link = await tx.incidentAlert.findUnique({
        where: {
          incidentId_alertId: {
            incidentId: id,
            alertId,
          },
        },
      });

      if (!link) {
        return { notFoundLink: true };
      }

      // 3. Remove the link
      await tx.incidentAlert.delete({
        where: {
          incidentId_alertId: {
            incidentId: id,
            alertId,
          },
        },
      });

      // Update incident's updatedAt timestamp
      await tx.incident.update({
        where: { id },
        data: { updatedAt: new Date() },
      });

      // 4. Create AuditLog entry
      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: 'INCIDENT_ALERT_UNLINK',
          targetType: 'Incident',
          targetId: id,
          ipAddress: clientIp,
          details: {
            incidentTitle: incident.title,
            unlinkedAlertId: alertId,
            actionBy: actorIdentifier,
          },
        },
      });

      const remainingAlertCount = await tx.incidentAlert.count({
        where: { incidentId: id },
      });

      return {
        success: true,
        remainingAlertCount,
      };
    });

    if (result.notFoundIncident) {
      return res.status(404).json({
        success: false,
        error: `Incident not found with ID "${id}".`,
      });
    }

    if (result.notFoundLink) {
      return res.status(404).json({
        success: false,
        error: `Alert "${alertId}" is not linked to this incident.`,
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Alert unlinked from incident successfully.',
      data: {
        unlinkedAlertId: alertId,
        remainingAlertCount: result.remainingAlertCount,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/incidents/:id/notes
 * Adds an investigation note to an incident.
 * Stored in AuditLog with action 'INCIDENT_NOTE_ADD' and user attribution.
 * Allowed roles: ADMIN, ANALYST only.
 */
export async function addIncidentNote(req, res, next) {
  try {
    const { id } = req.params;
    const idValidation = validateIncidentId(id);
    if (!idValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: idValidation.error,
      });
    }

    const payloadValidation = validateAddNotePayload(req.body);
    if (!payloadValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: payloadValidation.error,
      });
    }

    const { note } = payloadValidation;
    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Verify incident exists
      const incident = await tx.incident.findUnique({
        where: { id },
        select: { id: true, title: true },
      });

      if (!incident) {
        return { notFound: true };
      }

      // 2. Create AuditLog entry for investigation note
      const auditEntry = await tx.auditLog.create({
        data: {
          userId: actorId,
          action: 'INCIDENT_NOTE_ADD',
          targetType: 'Incident',
          targetId: id,
          ipAddress: clientIp,
          details: {
            note,
            authorName: actorIdentifier,
            authorRole: req.user.role,
          },
        },
      });

      // 3. Touch incident's updatedAt
      await tx.incident.update({
        where: { id },
        data: { updatedAt: new Date() },
      });

      return {
        success: true,
        auditEntry,
      };
    });

    if (result.notFound) {
      return res.status(404).json({
        success: false,
        error: `Incident not found with ID "${id}".`,
      });
    }

    return res.status(201).json({
      success: true,
      message: 'Investigation note added successfully.',
      data: {
        id: result.auditEntry.id,
        note,
        author: {
          id: actorId,
          name: req.user.name,
          email: req.user.email,
          role: req.user.role,
        },
        timestamp: result.auditEntry.timestamp,
      },
    });
  } catch (err) {
    next(err);
  }
}
