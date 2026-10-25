// backend/src/modules/threat-intelligence/threatIntel.controller.js
// Controller actions for Phase 9 Threat Intelligence & IOC Integration.

import prisma from '../../config/prisma.js';
import {
  validateCreateIocPayload,
  validateUpdateIocPayload,
  validateUuid,
  validateIocQueryParams,
} from './threatIntel.validation.js';
import {
  resolveProviderForLookup,
  getAvailableProviders,
  getProvider,
} from './providers/index.js';

// Cache TTL: 24 hours in milliseconds
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * GET /api/threat-intel/iocs
 * List IOCs with filtering, search, pagination, and latest enrichment summary.
 */
export async function getIocs(req, res, next) {
  try {
    const params = validateIocQueryParams(req.query);

    const where = {};

    if (params.type) {
      where.type = params.type;
    }

    if (params.status) {
      where.status = params.status;
    }

    if (params.severity) {
      where.severity = params.severity;
    }

    if (params.search) {
      where.OR = [
        { value: { contains: params.search, mode: 'insensitive' } },
        { description: { contains: params.search, mode: 'insensitive' } },
        { source: { contains: params.search, mode: 'insensitive' } },
      ];
    }

    const [total, iocs] = await Promise.all([
      prisma.threatIndicator.count({ where }),
      prisma.threatIndicator.findMany({
        where,
        skip: (params.page - 1) * params.limit,
        take: params.limit,
        orderBy: { [params.sortBy]: params.sortOrder },
        include: {
          enrichments: {
            orderBy: { queriedAt: 'desc' },
            take: 1,
          },
        },
      }),
    ]);

    // Format output with latestEnrichment convenience field
    const formatted = iocs.map((ioc) => ({
      ...ioc,
      latestEnrichment: ioc.enrichments[0] || null,
    }));

    return res.status(200).json({
      success: true,
      data: formatted,
      pagination: {
        total,
        page: params.page,
        limit: params.limit,
        totalPages: Math.ceil(total / params.limit) || 1,
      },
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/threat-intel/stats
 * Aggregated statistics for the Threat Intelligence dashboard.
 */
export async function getIocStats(_req, res, next) {
  try {
    const [total, active, expired, ipCount, domainCount, hashCount, urlCount, severities, maliciousEnrichments] =
      await Promise.all([
        prisma.threatIndicator.count(),
        prisma.threatIndicator.count({ where: { status: 'ACTIVE' } }),
        prisma.threatIndicator.count({ where: { status: 'EXPIRED' } }),
        prisma.threatIndicator.count({ where: { type: 'IP' } }),
        prisma.threatIndicator.count({ where: { type: 'DOMAIN' } }),
        prisma.threatIndicator.count({ where: { type: 'HASH' } }),
        prisma.threatIndicator.count({ where: { type: 'URL' } }),
        prisma.threatIndicator.groupBy({
          by: ['severity'],
          _count: { _all: true },
        }),
        // Count distinct indicators that have at least one MALICIOUS enrichment
        prisma.iocEnrichment.findMany({
          where: { verdict: 'MALICIOUS' },
          distinct: ['indicatorId'],
          select: { indicatorId: true },
        }),
      ]);

    const severityMap = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };
    for (const s of severities) {
      if (severityMap[s.severity] !== undefined) {
        severityMap[s.severity] = s._count._all;
      }
    }

    return res.status(200).json({
      success: true,
      data: {
        total,
        active,
        inactive: total - active,
        expired,
        byType: {
          IP: ipCount,
          DOMAIN: domainCount,
          HASH: hashCount,
          URL: urlCount,
        },
        bySeverity: severityMap,
        confirmedMaliciousCount: maliciousEnrichments.length,
        providers: getAvailableProviders(),
      },
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * Helper to fetch real correlated assets, events, and alerts.
 */
async function findCorrelatedEntities(ioc) {
  const correlations = {
    assets: [],
    events: [],
    alerts: [],
  };

  try {
    // 1. Asset Correlation (by exact IP or hostname match)
    if (ioc.type === 'IP') {
      const matchedAssets = await prisma.asset.findMany({
        where: { ipAddress: ioc.value },
        select: {
          id: true,
          name: true,
          hostname: true,
          ipAddress: true,
          type: true,
          criticality: true,
          status: true,
          owner: true,
        },
        take: 5,
      });
      correlations.assets = matchedAssets.map((a) => ({
        ...a,
        matchReason: `Asset IP address matches indicator (${ioc.value})`,
      }));
    } else if (ioc.type === 'DOMAIN') {
      const matchedAssets = await prisma.asset.findMany({
        where: { hostname: { contains: ioc.value, mode: 'insensitive' } },
        select: {
          id: true,
          name: true,
          hostname: true,
          ipAddress: true,
          type: true,
          criticality: true,
          status: true,
          owner: true,
        },
        take: 5,
      });
      correlations.assets = matchedAssets.map((a) => ({
        ...a,
        matchReason: `Asset hostname matches indicator domain (${ioc.value})`,
      }));
    }

    // 2. Event Correlation (by srcIp, dstIp, or hostname)
    if (ioc.type === 'IP') {
      const matchedEvents = await prisma.event.findMany({
        where: {
          OR: [{ srcIp: ioc.value }, { dstIp: ioc.value }],
        },
        select: {
          id: true,
          timestamp: true,
          eventType: true,
          srcIp: true,
          dstIp: true,
          username: true,
          hostname: true,
          severity: true,
          message: true,
        },
        orderBy: { timestamp: 'desc' },
        take: 10,
      });
      correlations.events = matchedEvents.map((e) => ({
        ...e,
        matchReason: e.srcIp === ioc.value ? 'Source IP match' : 'Destination IP match',
      }));
    } else if (ioc.type === 'DOMAIN') {
      const matchedEvents = await prisma.event.findMany({
        where: {
          hostname: { contains: ioc.value, mode: 'insensitive' },
        },
        select: {
          id: true,
          timestamp: true,
          eventType: true,
          srcIp: true,
          dstIp: true,
          username: true,
          hostname: true,
          severity: true,
          message: true,
        },
        orderBy: { timestamp: 'desc' },
        take: 10,
      });
      correlations.events = matchedEvents.map((e) => ({
        ...e,
        matchReason: 'Hostname match',
      }));
    }

    // 3. Alert Correlation (by title/description match or alerts linked to matched events)
    const alertWhere = {
      OR: [
        { title: { contains: ioc.value, mode: 'insensitive' } },
        { description: { contains: ioc.value, mode: 'insensitive' } },
      ],
    };

    if (correlations.events.length > 0) {
      const eventIds = correlations.events.map((e) => e.id);
      alertWhere.OR.push({
        alertEvents: {
          some: {
            eventId: { in: eventIds },
          },
        },
      });
    }

    const matchedAlerts = await prisma.alert.findMany({
      where: alertWhere,
      select: {
        id: true,
        title: true,
        description: true,
        severity: true,
        status: true,
        firedAt: true,
      },
      orderBy: { firedAt: 'desc' },
      take: 10,
    });

    correlations.alerts = matchedAlerts.map((a) => ({
      ...a,
      matchReason: 'Alert evidence references indicator value',
    }));
  } catch {
    // Non-blocking correlation failure
  }

  return correlations;
}

/**
 * GET /api/threat-intel/iocs/:id
 * Fetch detailed IOC metadata, latest enrichment history, and correlated assets/events.
 */
export async function getIocById(req, res, next) {
  try {
    const { id } = req.params;
    if (!validateUuid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid indicator UUID format' });
    }

    const ioc = await prisma.threatIndicator.findUnique({
      where: { id },
      include: {
        enrichments: {
          orderBy: { queriedAt: 'desc' },
          take: 10,
        },
      },
    });

    if (!ioc) {
      return res.status(404).json({ success: false, error: 'Threat indicator not found' });
    }

    // Fetch correlated assets, events, and alerts
    const correlations = await findCorrelatedEntities(ioc);

    // Fetch audit timeline
    const auditLogs = await prisma.auditLog.findMany({
      where: {
        targetType: 'ThreatIndicator',
        targetId: id,
      },
      include: {
        user: { select: { id: true, name: true, email: true, role: true } },
      },
      orderBy: { timestamp: 'desc' },
      take: 20,
    });

    return res.status(200).json({
      success: true,
      data: {
        ...ioc,
        latestEnrichment: ioc.enrichments[0] || null,
        correlations,
        auditLogs,
      },
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST /api/threat-intel/iocs
 * Register a new IOC. Allowed: ADMIN, ANALYST.
 */
export async function createIoc(req, res, next) {
  try {
    const validation = validateCreateIocPayload(req.body);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: validation.errors.join('; '),
        errors: validation.errors,
      });
    }

    const { type, value, status, severity, confidence, source, description, firstSeenAt, lastSeenAt, expiresAt } =
      validation.data;

    // Check duplicate value
    const existing = await prisma.threatIndicator.findUnique({ where: { value } });
    if (existing) {
      return res.status(409).json({
        success: false,
        error: `Indicator value "${value}" is already registered in Threat Intelligence (ID: ${existing.id})`,
        conflictId: existing.id,
      });
    }

    // Create indicator and audit log in a transaction
    const indicator = await prisma.$transaction(async (tx) => {
      const created = await tx.threatIndicator.create({
        data: {
          type,
          value,
          status,
          severity,
          confidence,
          source,
          description,
          firstSeenAt,
          lastSeenAt,
          expiresAt,
        },
      });

      await tx.auditLog.create({
        data: {
          userId: req.user?.id || null,
          action: 'IOC_CREATE',
          targetType: 'ThreatIndicator',
          targetId: created.id,
          ipAddress: req.ip || null,
          details: {
            type: created.type,
            value: created.value,
            severity: created.severity,
            status: created.status,
            confidence: created.confidence,
            source: created.source,
          },
        },
      });

      return created;
    });

    return res.status(201).json({
      success: true,
      message: 'Threat indicator registered successfully',
      data: indicator,
    });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(409).json({
        success: false,
        error: 'Indicator with this value already exists',
      });
    }
    return next(err);
  }
}

/**
 * PATCH /api/threat-intel/iocs/:id
 * Update IOC metadata (status, severity, confidence, description, timestamps).
 * Indicator value and type are immutable.
 */
export async function updateIoc(req, res, next) {
  try {
    const { id } = req.params;
    if (!validateUuid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid indicator UUID format' });
    }

    const validation = validateUpdateIocPayload(req.body);
    if (!validation.valid) {
      return res.status(400).json({
        success: false,
        error: validation.errors.join('; '),
        errors: validation.errors,
      });
    }

    const existing = await prisma.threatIndicator.findUnique({ where: { id } });
    if (!existing) {
      return res.status(404).json({ success: false, error: 'Threat indicator not found' });
    }

    const updated = await prisma.$transaction(async (tx) => {
      const item = await tx.threatIndicator.update({
        where: { id },
        data: validation.data,
      });

      await tx.auditLog.create({
        data: {
          userId: req.user?.id || null,
          action: validation.data.status && validation.data.status !== existing.status ? 'IOC_STATUS_CHANGE' : 'IOC_UPDATE',
          targetType: 'ThreatIndicator',
          targetId: id,
          ipAddress: req.ip || null,
          details: {
            changes: validation.data,
            previous: {
              status: existing.status,
              severity: existing.severity,
              confidence: existing.confidence,
            },
          },
        },
      });

      return item;
    });

    return res.status(200).json({
      success: true,
      message: 'Threat indicator updated successfully',
      data: updated,
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * DELETE /api/threat-intel/iocs/:id
 * Permanently delete an IOC. Allowed: ADMIN only.
 */
export async function deleteIoc(req, res, next) {
  try {
    const { id } = req.params;
    if (!validateUuid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid indicator UUID format' });
    }

    const existing = await prisma.threatIndicator.findUnique({ where: { id } });
    if (!existing) {
      return res.status(404).json({ success: false, error: 'Threat indicator not found' });
    }

    await prisma.$transaction(async (tx) => {
      // Delete child enrichments first (cascade is set, but explicit is clean)
      await tx.iocEnrichment.deleteMany({ where: { indicatorId: id } });
      await tx.threatIndicator.delete({ where: { id } });

      await tx.auditLog.create({
        data: {
          userId: req.user?.id || null,
          action: 'IOC_DELETE',
          targetType: 'ThreatIndicator',
          targetId: id,
          ipAddress: req.ip || null,
          details: {
            deletedValue: existing.value,
            deletedType: existing.type,
          },
        },
      });
    });

    return res.status(200).json({
      success: true,
      message: `Threat indicator "${existing.value}" permanently deleted`,
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST /api/threat-intel/iocs/:id/lookup
 * Query external threat intelligence provider for this indicator.
 * Allowed: ADMIN, ANALYST (VIEWER blocked).
 */
export async function lookupIoc(req, res, next) {
  try {
    const { id } = req.params;
    if (!validateUuid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid indicator UUID format' });
    }

    const indicator = await prisma.threatIndicator.findUnique({ where: { id } });
    if (!indicator) {
      return res.status(404).json({ success: false, error: 'Threat indicator not found' });
    }

    const { provider: requestedProvider, forceRefresh = false } = req.body || {};

    // 1. Caching check: if not forcing refresh, check if recent successful lookup exists within TTL
    if (!forceRefresh) {
      const cutoff = new Date(Date.now() - CACHE_TTL_MS);
      const recentEnrichment = await prisma.iocEnrichment.findFirst({
        where: {
          indicatorId: id,
          status: 'SUCCESS',
          queriedAt: { gte: cutoff },
          ...(requestedProvider ? { provider: requestedProvider.toUpperCase() } : {}),
        },
        orderBy: { queriedAt: 'desc' },
      });

      if (recentEnrichment) {
        return res.status(200).json({
          success: true,
          cached: true,
          message: `Returned cached observation from ${recentEnrichment.provider} (queried ${recentEnrichment.queriedAt.toISOString()})`,
          data: {
            ...recentEnrichment,
            cached: true,
          },
        });
      }
    }

    // 2. Resolve provider adapter
    let providerAdapter;
    if (requestedProvider) {
      providerAdapter = getProvider(requestedProvider);
      if (!providerAdapter) {
        return res.status(400).json({
          success: false,
          error: `Unknown threat intelligence provider "${requestedProvider}". Available: AbuseIPDB, VirusTotal, AlienVault_OTX`,
        });
      }
      if (!providerAdapter.supports(indicator.type)) {
        return res.status(400).json({
          success: false,
          error: `Provider "${providerAdapter.name}" does not support indicator type "${indicator.type}"`,
        });
      }
    } else {
      providerAdapter = resolveProviderForLookup(indicator.type);
    }

    // 3. Perform lookup outside database transaction
    const lookupResult = await providerAdapter.lookup(indicator.type, indicator.value);

    // 4. Persist observation to database (do not hold transactions during external calls)
    const enrichment = await prisma.iocEnrichment.create({
      data: {
        indicatorId: id,
        provider: providerAdapter.name,
        status: lookupResult.status,
        verdict: lookupResult.verdict,
        score: lookupResult.score,
        detectionCount: lookupResult.detectionCount,
        totalEngines: lookupResult.totalEngines,
        rawSummary: lookupResult.rawSummary,
        errorMessage: lookupResult.errorMessage,
        cached: false,
      },
    });

    // 5. Update indicator lastSeenAt if lookup succeeded
    if (lookupResult.status === 'SUCCESS') {
      await prisma.threatIndicator.update({
        where: { id },
        data: {
          lastSeenAt: new Date(),
          // If provider returned high confidence malicious verdict, elevate severity if currently low
          ...(lookupResult.verdict === 'MALICIOUS' && (indicator.severity === 'LOW' || indicator.severity === 'MEDIUM')
            ? { severity: 'HIGH' }
            : {}),
        },
      });
    }

    // 6. Log audit entry for lookup
    await prisma.auditLog.create({
      data: {
        userId: req.user?.id || null,
        action: 'IOC_LOOKUP',
        targetType: 'ThreatIndicator',
        targetId: id,
        ipAddress: req.ip || null,
        details: {
          provider: providerAdapter.name,
          status: lookupResult.status,
          verdict: lookupResult.verdict,
          detectionCount: lookupResult.detectionCount,
        },
      },
    });

    return res.status(200).json({
      success: true,
      cached: false,
      data: enrichment,
      provider: providerAdapter.name,
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/threat-intel/iocs/:id/enrichment-history
 * Fetch all provider enrichment observations for an indicator.
 */
export async function getEnrichmentHistory(req, res, next) {
  try {
    const { id } = req.params;
    if (!validateUuid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid indicator UUID format' });
    }

    const enrichments = await prisma.iocEnrichment.findMany({
      where: { indicatorId: id },
      orderBy: { queriedAt: 'desc' },
      take: 50,
    });

    return res.status(200).json({
      success: true,
      data: enrichments,
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/threat-intel/iocs/:id/correlation
 * Return correlation matches against Assets, Security Events, and Alerts.
 */
export async function getIocCorrelation(req, res, next) {
  try {
    const { id } = req.params;
    if (!validateUuid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid indicator UUID format' });
    }

    const indicator = await prisma.threatIndicator.findUnique({ where: { id } });
    if (!indicator) {
      return res.status(404).json({ success: false, error: 'Threat indicator not found' });
    }

    const correlations = await findCorrelatedEntities(indicator);

    return res.status(200).json({
      success: true,
      data: correlations,
    });
  } catch (err) {
    return next(err);
  }
}
