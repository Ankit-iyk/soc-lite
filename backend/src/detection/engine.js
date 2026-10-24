// src/detection/engine.js
// Detection Engine Orchestrator for SOC Lite.
//
// Bridges pure evaluators, database models (DetectionRule, Event, ThreatIndicator,
// User, Alert, AlertEvent, AuditLog), and alert persistence with deterministic deduplication.

import prisma from '../config/prisma.js';
import { isValidIp } from '../modules/logs/logParser.js';
import { evaluate as evaluateSshBruteForce } from './evaluators/sshBruteForce.js';
import { evaluate as evaluatePortScan } from './evaluators/portScan.js';
import { evaluate as evaluateSuspiciousIp } from './evaluators/suspiciousIp.js';
import { evaluate as evaluateSuspiciousAccess } from './evaluators/suspiciousAccess.js';
import { AlertStatus } from '@prisma/client';

// In-process lock / queue to serialize concurrent detection engine executions
// within the same Node.js process.
let engineExecutionLock = Promise.resolve();

// Tracks whether a detection pipeline is actively executing right now.
// Used by the scheduler to implement skip-if-busy without queuing unlimited work.
let _currentlyRunning = false;

/**
 * Returns true if a detection pipeline execution is currently in progress.
 * Safe to call from any part of the same Node.js process.
 * @returns {boolean}
 */
export function isDetectionRunning() {
  return _currentlyRunning;
}

/**
 * Builds a deterministic title and description for a match without
 * using human-readable free text search for deduplication.
 * @param {object} match - Evaluator match object
 * @param {object} rule - DetectionRule model instance
 * @returns {{ title: string, description: string }}
 */
export function buildMatchTitleAndDescription(match, rule) {
  const meta = match.metadata || {};

  switch (rule.type) {
    case 'SSH_BRUTE_FORCE': {
      const username = meta.username || 'unknown';
      const srcIp = meta.srcIp || 'unknown';
      const count = meta.count || match.triggeringEvents?.length || rule.config.threshold;
      const windowSec = rule.config.windowSeconds || 60;
      return {
        title: `SSH Brute Force: ${username} from ${srcIp}`,
        description: `Detected ${count} failed SSH login attempts for user '${username}' from source IP ${srcIp} within ${windowSec} seconds.`,
      };
    }

    case 'PORT_SCAN': {
      const srcIp = meta.srcIp || 'unknown';
      const portCount = meta.distinctPortCount || rule.config.portThreshold;
      const windowSec = rule.config.windowSeconds || 120;
      return {
        title: `Port Scan: ${srcIp}`,
        description: `Detected connection attempts to ${portCount} distinct destination ports from source IP ${srcIp} within ${windowSec} seconds.`,
      };
    }

    case 'SUSPICIOUS_IP': {
      const primary = (meta.matchedIndicators && meta.matchedIndicators[0]) || {};
      const ip = primary.ip || meta.srcIp || meta.dstIp || 'unknown';
      const source = primary.indicator?.source || 'Threat Intel';
      const confidence = primary.indicator?.confidence != null ? `${primary.indicator.confidence}%` : 'N/A';
      return {
        title: `Suspicious IP: ${ip} (${source})`,
        description: `Observed traffic involving known threat intelligence indicator IP ${ip} (Source: ${source}, Confidence: ${confidence}).`,
      };
    }

    case 'SUSPICIOUS_ACCESS': {
      const username = meta.username || 'unknown';
      const reasons = meta.reasons?.join(', ') || 'outside approved operating schedule';
      return {
        title: `Suspicious Admin Access: ${username}`,
        description: `Administrative user '${username}' authenticated via SSH outside approved operating schedule (${reasons}).`,
      };
    }

    default:
      return {
        title: `${rule.name}: Security Alert`,
        description: rule.description || `Detection rule ${rule.name} matched.`,
      };
  }
}

/**
 * Executes detection evaluation across enabled rules and persists alerts with deduplication.
 *
 * @param {object} [options]
 * @param {Array<object>} [options.events]          - Explicit events to evaluate (bypasses DB event query)
 * @param {Array<string>} [options.eventIds]        - Filter events by IDs from database
 * @param {Date}          [options.since]           - Evaluate events with timestamp >= since
 * @param {number}        [options.windowMinutes]   - Evaluate events within the past N minutes
 * @param {number}        [options.limit]           - Limit on number of events loaded (default 1000)
 * @param {string}        [options.ruleId]          - Evaluate only a specific rule by ID
 * @param {string}        [options.userId]          - User ID who triggered the run (for AuditLog)
 * @param {string}        [options.ipAddress]       - Client IP address (for AuditLog)
 * @returns {Promise<object>} Summary of the detection run
 */
export async function runDetection(options = {}) {
  // Serialize runs within this Node.js instance
  const release = engineExecutionLock;
  let unlock;
  engineExecutionLock = new Promise((resolve) => {
    unlock = resolve;
  });

  _currentlyRunning = true;
  try {
    await release;
    return await executeDetectionPipeline(options);
  } finally {
    _currentlyRunning = false;
    unlock();
  }
}

/**
 * Internal core execution pipeline.
 */
async function executeDetectionPipeline(options) {
  const summary = {
    rulesEvaluated: 0,
    matchesFound: 0,
    alertsCreated: 0,
    alertsUpdated: 0,
    alerts: [],
    errors: [],
  };

  // 1. Load enabled detection rules
  const ruleWhere = { enabled: true };
  if (options.ruleId) {
    ruleWhere.id = options.ruleId;
  }
  const rules = await prisma.detectionRule.findMany({ where: ruleWhere });

  if (rules.length === 0) {
    return summary;
  }

  // 2. Load Threat Intelligence indicators (IP only)
  const rawIndicators = await prisma.threatIndicator.findMany({
    where: { type: 'IP' },
    select: {
      id: true,
      value: true,
      type: true,
      confidence: true,
      source: true,
      description: true,
    },
  });

  // Ensure indicators are valid IPs (exclude any malformed entries)
  const validIndicators = rawIndicators.filter((ioc) => isValidIp(ioc.value));

  // 3. Derive admin usernames from actual, valid User identity data (do not assume 'root' or 'admin')
  const adminUsers = await prisma.user.findMany({
    where: { role: 'ADMIN' },
    select: {
      id: true,
      email: true,
      name: true,
    },
  });

  const adminUsernameSet = new Set();
  for (const u of adminUsers) {
    if (u.email) {
      adminUsernameSet.add(u.email.toLowerCase());
      const localPart = u.email.split('@')[0];
      if (localPart) {
        adminUsernameSet.add(localPart.toLowerCase());
      }
    }
  }

  const context = {
    indicators: validIndicators,
    adminUsernames: Array.from(adminUsernameSet),
  };

  // 4. Load events to evaluate
  let events = options.events;
  if (!events) {
    const eventWhere = {};

    if (options.eventIds && Array.isArray(options.eventIds) && options.eventIds.length > 0) {
      eventWhere.id = { in: options.eventIds };
    } else if (options.since) {
      eventWhere.timestamp = { gte: options.since };
    } else if (options.windowMinutes) {
      const sinceDate = new Date(Date.now() - options.windowMinutes * 60 * 1000);
      eventWhere.timestamp = { gte: sinceDate };
    }

    events = await prisma.event.findMany({
      where: eventWhere,
      orderBy: { timestamp: 'asc' },
      take: options.limit || 1000,
    });
  }

  // 5. Evaluate each rule
  for (const rule of rules) {
    try {
      summary.rulesEvaluated++;
      let matches = [];

      switch (rule.type) {
        case 'SSH_BRUTE_FORCE':
          matches = evaluateSshBruteForce(events, rule, context);
          break;

        case 'PORT_SCAN':
          matches = evaluatePortScan(events, rule, context);
          break;

        case 'SUSPICIOUS_IP':
          matches = evaluateSuspiciousIp(events, rule, context);
          break;

        case 'SUSPICIOUS_ACCESS':
          matches = evaluateSuspiciousAccess(events, rule, context);
          break;

        default:
          summary.errors.push(`Unsupported rule type '${rule.type}' on rule '${rule.name}'`);
          continue;
      }

      summary.matchesFound += matches.length;

      // 6. Persist matches with robust deduplication in Prisma transactions
      for (const match of matches) {
        const persistResult = await persistMatchWithDeduplication(match, rule);
        if (persistResult) {
          if (persistResult.action === 'created') {
            summary.alertsCreated++;
            summary.alerts.push({
              id: persistResult.alert.id,
              ruleId: rule.id,
              title: persistResult.alert.title,
              action: 'created',
            });
          } else if (persistResult.action === 'updated') {
            summary.alertsUpdated++;
            summary.alerts.push({
              id: persistResult.alert.id,
              ruleId: rule.id,
              title: persistResult.alert.title,
              action: 'updated',
              newEvidenceCount: persistResult.newEvidenceCount,
            });
          }
        }
      }
    } catch (err) {
      summary.errors.push(`Error evaluating rule ${rule.name}: ${err.message}`);
    }
  }

  // 7. Security audit logging (if triggered by a known user)
  if (options.userId) {
    await prisma.auditLog
      .create({
        data: {
          userId: options.userId,
          action: 'DETECTION_RUN',
          targetType: 'DetectionEngine',
          ipAddress: options.ipAddress || null,
          details: {
            rulesEvaluated: summary.rulesEvaluated,
            matchesFound: summary.matchesFound,
            alertsCreated: summary.alertsCreated,
            alertsUpdated: summary.alertsUpdated,
            errorsCount: summary.errors.length,
          },
        },
      })
      .catch((err) => console.error('AuditLog error in detection run:', err.message));
  }

  return summary;
}

/**
 * Persists a detection match inside a transaction.
 * Deduplication Strategy:
 * 1. Checks if any triggering event is already linked to an OPEN or ACKNOWLEDGED alert for this rule.
 * 2. Checks if an OPEN or ACKNOWLEDGED alert exists with the exact structured title for this rule & target entity.
 * 3. Checks if ALL triggering events were already closed in a previous CLOSED alert (if so, skips).
 * 4. If an equivalent OPEN alert exists: updates evidence links without creating duplicates.
 * 5. If no equivalent OPEN alert exists: creates a new Alert and links AlertEvent records.
 *
 * @param {object} match - Evaluator match object
 * @param {object} rule - DetectionRule model instance
 * @returns {Promise<object|null>}
 */
async function persistMatchWithDeduplication(match, rule) {
  const { title, description } = buildMatchTitleAndDescription(match, rule);
  const triggeringEventIds = (match.triggeringEvents || []).map((e) => e.id).filter(Boolean);

  return prisma.$transaction(async (tx) => {
    let existingAlert = null;

    // Check 1: Do any triggering events already link to an active (OPEN or ACKNOWLEDGED) alert for this rule?
    if (triggeringEventIds.length > 0) {
      const existingAlertEvents = await tx.alertEvent.findMany({
        where: {
          eventId: { in: triggeringEventIds },
          alert: {
            ruleId: rule.id,
            status: { in: [AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED] },
          },
        },
        include: {
          alert: true,
        },
      });

      if (existingAlertEvents.length > 0) {
        existingAlert = existingAlertEvents[0].alert;
      }
    }

    // Check 2: If not found by event overlap, check by exact structured entity title
    if (!existingAlert) {
      existingAlert = await tx.alert.findFirst({
        where: {
          ruleId: rule.id,
          title,
          status: { in: [AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED] },
        },
      });
    }

    // Check 3: If no open alert found, check if ALL triggering events were already linked to a CLOSED alert.
    // If every event was already part of a closed alert, do not recreate an alert for historical, closed evidence.
    if (!existingAlert && triggeringEventIds.length > 0) {
      const closedAlertEvents = await tx.alertEvent.findMany({
        where: {
          eventId: { in: triggeringEventIds },
          alert: {
            ruleId: rule.id,
            status: AlertStatus.CLOSED,
          },
        },
      });

      const closedEventIdSet = new Set(closedAlertEvents.map((ae) => ae.eventId));
      const allEventsClosed = triggeringEventIds.every((id) => closedEventIdSet.has(id));

      if (allEventsClosed) {
        return null; // All events were previously closed; do not create duplicate alert
      }
    }

    // Case A: Equivalent active alert already exists -> Update evidence links
    if (existingAlert) {
      const currentlyLinked = await tx.alertEvent.findMany({
        where: { alertId: existingAlert.id },
        select: { eventId: true },
      });
      const currentlyLinkedSet = new Set(currentlyLinked.map((ae) => ae.eventId));

      const newEventIds = triggeringEventIds.filter((id) => !currentlyLinkedSet.has(id));

      if (newEventIds.length > 0) {
        await tx.alertEvent.createMany({
          data: newEventIds.map((eventId) => ({
            alertId: existingAlert.id,
            eventId,
          })),
          skipDuplicates: true,
        });

        return {
          action: 'updated',
          alert: existingAlert,
          newEvidenceCount: newEventIds.length,
        };
      }

      // No new evidence to link — already completely recorded
      return {
        action: 'unchanged',
        alert: existingAlert,
        newEvidenceCount: 0,
      };
    }

    // Case B: No equivalent active alert -> Create new Alert and link AlertEvents
    const newAlert = await tx.alert.create({
      data: {
        ruleId: rule.id,
        title,
        description,
        severity: rule.severity,
        status: AlertStatus.OPEN,
        firedAt: new Date(),
      },
    });

    if (triggeringEventIds.length > 0) {
      await tx.alertEvent.createMany({
        data: triggeringEventIds.map((eventId) => ({
          alertId: newAlert.id,
          eventId,
        })),
        skipDuplicates: true,
      });
    }

    return {
      action: 'created',
      alert: newAlert,
    };
  });
}
