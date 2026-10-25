// src/modules/assets/assets.controller.js
// Controllers for Asset Management (Phase 8).

import prisma from '../../config/prisma.js';
import { Severity, AssetStatus } from '@prisma/client';
import {
  validateAssetId,
  validateAssetQueryParams,
  validateCreateAssetPayload,
  validateUpdateAssetPayload,
} from './assets.validation.js';

/**
 * GET /api/assets
 * Returns paginated list of assets with search and filtering.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getAssets(req, res, next) {
  try {
    const validation = validateAssetQueryParams(req.query);
    if (!validation.isValid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    const { page, limit, search, status, criticality, type, environment, sortBy, sortOrder } =
      validation.sanitized;
    const skip = (page - 1) * limit;

    const where = {};

    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { hostname: { contains: search, mode: 'insensitive' } },
        { ipAddress: { contains: search, mode: 'insensitive' } },
        { owner: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (status) {
      where.status = status;
    }

    if (criticality) {
      where.criticality = criticality;
    }

    if (type) {
      where.type = { equals: type, mode: 'insensitive' };
    }

    if (environment) {
      where.environment = { equals: environment, mode: 'insensitive' };
    }

    const [assets, total] = await Promise.all([
      prisma.asset.findMany({
        where,
        skip,
        take: limit,
        orderBy: [{ [sortBy]: sortOrder }, { id: 'asc' }],
      }),
      prisma.asset.count({ where }),
    ]);

    const totalPages = Math.ceil(total / limit) || 1;

    return res.status(200).json({
      success: true,
      data: assets,
      pagination: {
        page,
        limit,
        total,
        totalPages,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/assets/stats
 * Aggregates asset inventory counts: total, active, inactive, decommissioned, critical, by type.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getAssetStats(_req, res, next) {
  try {
    const [total, statusGroups, criticalityGroups, typeGroups] = await Promise.all([
      prisma.asset.count(),
      prisma.asset.groupBy({
        by: ['status'],
        _count: { _all: true },
      }),
      prisma.asset.groupBy({
        by: ['criticality'],
        _count: { _all: true },
      }),
      prisma.asset.groupBy({
        by: ['type'],
        _count: { _all: true },
      }),
    ]);

    const byStatus = {
      ACTIVE: 0,
      INACTIVE: 0,
      DECOMMISSIONED: 0,
    };
    for (const g of statusGroups) {
      if (g.status in byStatus) byStatus[g.status] = g._count._all;
    }

    const byCriticality = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    for (const g of criticalityGroups) {
      if (g.criticality in byCriticality) byCriticality[g.criticality] = g._count._all;
    }

    const byType = {};
    for (const g of typeGroups) {
      if (g.type) byType[g.type] = g._count._all;
    }

    return res.status(200).json({
      success: true,
      data: {
        total,
        active: byStatus.ACTIVE,
        inactive: byStatus.INACTIVE,
        decommissioned: byStatus.DECOMMISSIONED,
        critical: byCriticality.CRITICAL,
        byStatus,
        byCriticality,
        byType,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/assets/:id
 * Returns asset details and audit log timeline.
 * Allowed roles: ADMIN, ANALYST, VIEWER.
 */
export async function getAssetById(req, res, next) {
  try {
    const idValidation = validateAssetId(req.params.id);
    if (!idValidation.isValid) {
      return res.status(400).json({ success: false, error: idValidation.error });
    }

    const { id } = idValidation;

    const [asset, auditLogs] = await Promise.all([
      prisma.asset.findUnique({ where: { id } }),
      prisma.auditLog.findMany({
        where: { targetType: 'Asset', targetId: id },
        orderBy: { timestamp: 'desc' },
        take: 50,
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

    if (!asset) {
      return res.status(404).json({
        success: false,
        error: `Asset with ID "${id}" was not found.`,
      });
    }

    const timeline = auditLogs.map((log) => ({
      id: log.id,
      action: log.action,
      timestamp: log.timestamp,
      actor: log.user
        ? { id: log.user.id, name: log.user.name, email: log.user.email, role: log.user.role }
        : null,
      details: log.details,
    }));

    return res.status(200).json({
      success: true,
      data: {
        ...asset,
        timeline,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/assets
 * Registers a new asset and records an audit log entry.
 * Allowed roles: ADMIN, ANALYST.
 */
export async function createAsset(req, res, next) {
  try {
    const validation = validateCreateAssetPayload(req.body);
    if (!validation.isValid) {
      return res.status(400).json({ success: false, error: validation.error });
    }

    const { sanitized } = validation;

    // Check IP uniqueness if an IP address is provided
    if (sanitized.ipAddress) {
      const existingWithIp = await prisma.asset.findUnique({
        where: { ipAddress: sanitized.ipAddress },
        select: { id: true, name: true },
      });
      if (existingWithIp) {
        return res.status(409).json({
          success: false,
          error: `An asset with IP address "${sanitized.ipAddress}" already exists ("${existingWithIp.name}").`,
        });
      }
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const newAsset = await prisma.$transaction(async (tx) => {
      const asset = await tx.asset.create({
        data: sanitized,
      });

      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: 'ASSET_CREATE',
          targetType: 'Asset',
          targetId: asset.id,
          ipAddress: clientIp,
          details: {
            name: asset.name,
            ipAddress: asset.ipAddress,
            type: asset.type,
            criticality: asset.criticality,
            status: asset.status,
            actionBy: actorIdentifier,
          },
        },
      });

      return asset;
    });

    return res.status(201).json({
      success: true,
      message: `Asset "${newAsset.name}" registered successfully.`,
      data: newAsset,
    });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({
        success: false,
        error: 'An asset with this unique property (e.g. IP address) already exists.',
      });
    }
    next(err);
  }
}

/**
 * PATCH /api/assets/:id
 * Updates an asset record and records an audit log entry.
 * Allowed roles: ADMIN, ANALYST.
 */
export async function updateAsset(req, res, next) {
  try {
    const idValidation = validateAssetId(req.params.id);
    if (!idValidation.isValid) {
      return res.status(400).json({ success: false, error: idValidation.error });
    }

    const payloadValidation = validateUpdateAssetPayload(req.body);
    if (!payloadValidation.isValid) {
      return res.status(400).json({ success: false, error: payloadValidation.error });
    }

    const { id } = idValidation;
    const { sanitized } = payloadValidation;

    // Verify asset exists
    const existing = await prisma.asset.findUnique({ where: { id } });
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: `Asset with ID "${id}" was not found.`,
      });
    }

    // Check unique IP conflict if IP is being changed
    if (sanitized.ipAddress && sanitized.ipAddress !== existing.ipAddress) {
      const conflict = await prisma.asset.findUnique({
        where: { ipAddress: sanitized.ipAddress },
        select: { id: true, name: true },
      });
      if (conflict && conflict.id !== id) {
        return res.status(409).json({
          success: false,
          error: `Another asset with IP address "${sanitized.ipAddress}" already exists ("${conflict.name}").`,
        });
      }
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const previousValues = {};
    for (const key of Object.keys(sanitized)) {
      previousValues[key] = existing[key];
    }

    const statusChanged = 'status' in sanitized && sanitized.status !== existing.status;
    const auditAction = statusChanged ? 'ASSET_STATUS_CHANGE' : 'ASSET_UPDATE';

    const updated = await prisma.$transaction(async (tx) => {
      const asset = await tx.asset.update({
        where: { id },
        data: sanitized,
      });

      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: auditAction,
          targetType: 'Asset',
          targetId: id,
          ipAddress: clientIp,
          details: {
            changedFields: Object.keys(sanitized),
            previous: previousValues,
            updated: sanitized,
            actionBy: actorIdentifier,
          },
        },
      });

      return asset;
    });

    return res.status(200).json({
      success: true,
      message: `Asset "${updated.name}" updated successfully.`,
      data: updated,
    });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({
        success: false,
        error: 'An asset with this unique property (e.g. IP address) already exists.',
      });
    }
    next(err);
  }
}

/**
 * PATCH /api/assets/:id/decommission
 * Safely marks an asset as DECOMMISSIONED without destroying historical records.
 * Allowed roles: ADMIN, ANALYST.
 */
export async function decommissionAsset(req, res, next) {
  try {
    const idValidation = validateAssetId(req.params.id);
    if (!idValidation.isValid) {
      return res.status(400).json({ success: false, error: idValidation.error });
    }

    const { id } = idValidation;

    const existing = await prisma.asset.findUnique({ where: { id } });
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: `Asset with ID "${id}" was not found.`,
      });
    }

    if (existing.status === AssetStatus.DECOMMISSIONED) {
      return res.status(200).json({
        success: true,
        message: `Asset "${existing.name}" is already decommissioned.`,
        data: existing,
      });
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const updated = await prisma.$transaction(async (tx) => {
      const asset = await tx.asset.update({
        where: { id },
        data: { status: AssetStatus.DECOMMISSIONED },
      });

      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: 'ASSET_DECOMMISSION',
          targetType: 'Asset',
          targetId: id,
          ipAddress: clientIp,
          details: {
            previousStatus: existing.status,
            newStatus: AssetStatus.DECOMMISSIONED,
            actionBy: actorIdentifier,
          },
        },
      });

      return asset;
    });

    return res.status(200).json({
      success: true,
      message: `Asset "${updated.name}" has been decommissioned.`,
      data: updated,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * DELETE /api/assets/:id
 * Permanently removes an asset and records an audit log entry.
 * Allowed roles: ADMIN only.
 */
export async function deleteAsset(req, res, next) {
  try {
    const idValidation = validateAssetId(req.params.id);
    if (!idValidation.isValid) {
      return res.status(400).json({ success: false, error: idValidation.error });
    }

    const { id } = idValidation;

    const existing = await prisma.asset.findUnique({ where: { id } });
    if (!existing) {
      return res.status(404).json({
        success: false,
        error: `Asset with ID "${id}" was not found.`,
      });
    }

    const actorId = req.user.id;
    const actorIdentifier = req.user.name || req.user.email || req.user.id;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    await prisma.$transaction(async (tx) => {
      // Record final audit log before deleting
      await tx.auditLog.create({
        data: {
          userId: actorId,
          action: 'ASSET_DELETE',
          targetType: 'Asset',
          targetId: id,
          ipAddress: clientIp,
          details: {
            deletedAssetName: existing.name,
            deletedIpAddress: existing.ipAddress,
            deletedType: existing.type,
            actionBy: actorIdentifier,
          },
        },
      });

      await tx.asset.delete({ where: { id } });
    });

    return res.status(200).json({
      success: true,
      message: `Asset "${existing.name}" was permanently deleted.`,
    });
  } catch (err) {
    next(err);
  }
}
