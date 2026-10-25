// src/utils/audit.js
// Centralized, hardened audit logging utility for SOC Lite (Phase 12).
// Enforces:
// 1. Sanitization of sensitive keys (passwords, tokens, secrets, API keys)
// 2. Bounding of metadata size to prevent uncontrolled database growth
// 3. Reliable transaction support (accepts Prisma transaction client tx)
// 4. Safe fallback and non-destructive execution

import prisma from '../config/prisma.js';

// Sensitive keys that must NEVER be written to audit logs in plain text
const SENSITIVE_KEY_REGEX = /(password|passwordhash|token|secret|apikey|authorization|cookie|credentials|bearer)/i;

// Maximum string length for any single field in audit metadata
const MAX_METADATA_STRING_LENGTH = 1000;
// Maximum items in an array within audit metadata
const MAX_ARRAY_ITEMS = 50;

/**
 * Deep sanitization and bounding for audit metadata payloads.
 * Redacts sensitive fields, truncates excessively long strings, and bounds arrays.
 *
 * @param {*} value - The value to sanitize
 * @param {number} depth - Recursion guard depth
 * @returns {*} Sanitized, safe JSON-serializable value
 */
export function sanitizeAuditDetails(value, depth = 0) {
  if (value === null || value === undefined) {
    return value;
  }

  // Prevent circular references or overly deep structures
  if (depth > 5) {
    return '[MAX_DEPTH_REACHED]';
  }

  if (typeof value === 'string') {
    if (value.length > MAX_METADATA_STRING_LENGTH) {
      return `${value.slice(0, MAX_METADATA_STRING_LENGTH)}... [TRUNCATED]`;
    }
    return value;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (Array.isArray(value)) {
    const truncated = value.slice(0, MAX_ARRAY_ITEMS);
    const result = truncated.map((item) => sanitizeAuditDetails(item, depth + 1));
    if (value.length > MAX_ARRAY_ITEMS) {
      result.push(`[${value.length - MAX_ARRAY_ITEMS} MORE ITEMS TRUNCATED]`);
    }
    return result;
  }

  if (typeof value === 'object') {
    const sanitizedObj = {};
    for (const [key, val] of Object.entries(value)) {
      if (SENSITIVE_KEY_REGEX.test(key)) {
        sanitizedObj[key] = '[REDACTED]';
      } else {
        sanitizedObj[key] = sanitizeAuditDetails(val, depth + 1);
      }
    }
    return sanitizedObj;
  }

  return String(value);
}

/**
 * Records an immutable AuditLog entry in the database.
 * Supports both standalone execution and atomic execution within a Prisma transaction.
 *
 * @param {object} params
 * @param {object} [params.tx] - Optional Prisma transaction client. If omitted, uses global prisma client.
 * @param {string} [params.userId] - ID of the user performing the action
 * @param {string} params.action - Canonical action identifier (e.g. 'INCIDENT_UPDATE', 'ASSET_DELETE')
 * @param {string} [params.targetType] - Type of entity affected (e.g. 'Incident', 'Asset', 'ThreatIndicator')
 * @param {string} [params.targetId] - UUID or identifier of affected entity
 * @param {string} [params.ipAddress] - Client IP address
 * @param {object} [params.details] - Arbitrary structured metadata describing the action
 * @returns {Promise<object>} Created AuditLog record
 */
export async function writeAuditLog({
  tx,
  userId = null,
  action,
  targetType = null,
  targetId = null,
  ipAddress = null,
  details = null,
}) {
  if (!action || typeof action !== 'string') {
    throw new Error('AuditLog requires a valid action string');
  }

  const client = tx || prisma;
  const sanitizedDetails = details ? sanitizeAuditDetails(details) : null;

  return client.auditLog.create({
    data: {
      userId: userId || null,
      action: action.toUpperCase(),
      targetType: targetType || null,
      targetId: targetId ? String(targetId) : null,
      ipAddress: ipAddress ? String(ipAddress).slice(0, 45) : null,
      details: sanitizedDetails,
    },
  });
}
