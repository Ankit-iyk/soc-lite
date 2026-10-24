// src/modules/rules/rules.validation.js
// Validation logic for Detection Rules configuration and updates.

import { Severity, Role } from '@prisma/client';

export const ALLOWED_UPDATE_FIELDS = ['enabled', 'description', 'severity', 'config'];

const VALID_SEVERITIES = Object.values(Severity);
const VALID_ROLES = Object.values(Role);

/**
 * Validates top-level fields for PUT /api/rules/:id.
 * Returns an error string if invalid, or null if valid.
 */
export function validateRuleUpdatePayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'Request body must be a JSON object.';
  }

  const keys = Object.keys(body);
  if (keys.length === 0) {
    return 'No update fields provided. At least one of [enabled, description, severity, config] must be specified.';
  }

  // Reject unsupported / immutable fields (e.g. id, type, name, createdAt, updatedAt, etc.)
  const unsupportedKeys = keys.filter((k) => !ALLOWED_UPDATE_FIELDS.includes(k));
  if (unsupportedKeys.length > 0) {
    return `Unsupported or unmodifiable field(s): ${unsupportedKeys.join(', ')}. Allowed fields: ${ALLOWED_UPDATE_FIELDS.join(', ')}.`;
  }

  // Field: enabled
  if ('enabled' in body && typeof body.enabled !== 'boolean') {
    return 'Field "enabled" must be a boolean.';
  }

  // Field: description
  if ('description' in body) {
    if (body.description !== null && typeof body.description !== 'string') {
      return 'Field "description" must be a string or null.';
    }
    if (typeof body.description === 'string' && body.description.length > 500) {
      return 'Field "description" must not exceed 500 characters.';
    }
  }

  // Field: severity
  if ('severity' in body) {
    if (!VALID_SEVERITIES.includes(body.severity)) {
      return `Field "severity" must be one of: ${VALID_SEVERITIES.join(', ')}.`;
    }
  }

  // Field: config
  if ('config' in body) {
    if (!body.config || typeof body.config !== 'object' || Array.isArray(body.config)) {
      return 'Field "config" must be a non-empty JSON object.';
    }
  }

  return null;
}

/**
 * Validates rule-specific configuration based on rule type and evaluator requirements.
 * Returns an error string if invalid, or null if valid.
 *
 * @param {string} ruleType - 'SSH_BRUTE_FORCE', 'PORT_SCAN', 'SUSPICIOUS_IP', 'SUSPICIOUS_ACCESS'
 * @param {object} partialConfig - The new config keys sent in the request
 * @param {object} mergedConfig - The combined config (existing + partial)
 */
export function validateRuleConfig(ruleType, partialConfig, mergedConfig) {
  switch (ruleType) {
    case 'SSH_BRUTE_FORCE':
      return validateSshBruteForceConfig(partialConfig, mergedConfig);

    case 'PORT_SCAN':
      return validatePortScanConfig(partialConfig, mergedConfig);

    case 'SUSPICIOUS_IP':
      return validateSuspiciousIpConfig(partialConfig, mergedConfig);

    case 'SUSPICIOUS_ACCESS':
      return validateSuspiciousAccessConfig(partialConfig, mergedConfig);

    default:
      return `Unknown rule type "${ruleType}".`;
  }
}

/**
 * SSH_BRUTE_FORCE validation
 * Keys: threshold (1-1000), windowSeconds (1-86400), eventType (string)
 */
function validateSshBruteForceConfig(partialConfig, mergedConfig) {
  const allowed = ['threshold', 'windowSeconds', 'eventType'];
  const unknown = Object.keys(partialConfig).filter((k) => !allowed.includes(k));
  if (unknown.length > 0) {
    return `Unsupported config key(s) for SSH_BRUTE_FORCE: ${unknown.join(', ')}. Allowed: ${allowed.join(', ')}.`;
  }

  const { threshold, windowSeconds, eventType } = mergedConfig;

  if (threshold !== undefined) {
    if (!Number.isInteger(threshold) || threshold < 1 || threshold > 1000) {
      return 'SSH_BRUTE_FORCE config.threshold must be an integer between 1 and 1000.';
    }
  } else {
    return 'SSH_BRUTE_FORCE requires config.threshold.';
  }

  if (windowSeconds !== undefined) {
    if (!Number.isInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 86400) {
      return 'SSH_BRUTE_FORCE config.windowSeconds must be an integer between 1 and 86400 seconds (24h).';
    }
  } else {
    return 'SSH_BRUTE_FORCE requires config.windowSeconds.';
  }

  if (eventType !== undefined) {
    if (typeof eventType !== 'string' || !eventType.trim()) {
      return 'SSH_BRUTE_FORCE config.eventType must be a non-empty string.';
    }
  } else {
    return 'SSH_BRUTE_FORCE requires config.eventType.';
  }

  return null;
}

/**
 * PORT_SCAN validation
 * Keys: portThreshold (1-65535), windowSeconds (1-86400), eventType (string or string[])
 */
function validatePortScanConfig(partialConfig, mergedConfig) {
  const allowed = ['portThreshold', 'windowSeconds', 'eventType'];
  const unknown = Object.keys(partialConfig).filter((k) => !allowed.includes(k));
  if (unknown.length > 0) {
    return `Unsupported config key(s) for PORT_SCAN: ${unknown.join(', ')}. Allowed: ${allowed.join(', ')}.`;
  }

  const { portThreshold, windowSeconds, eventType } = mergedConfig;

  if (portThreshold !== undefined) {
    if (!Number.isInteger(portThreshold) || portThreshold < 1 || portThreshold > 65535) {
      return 'PORT_SCAN config.portThreshold must be an integer between 1 and 65535 ports.';
    }
  } else {
    return 'PORT_SCAN requires config.portThreshold.';
  }

  if (windowSeconds !== undefined) {
    if (!Number.isInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 86400) {
      return 'PORT_SCAN config.windowSeconds must be an integer between 1 and 86400 seconds (24h).';
    }
  } else {
    return 'PORT_SCAN requires config.windowSeconds.';
  }

  if (eventType !== undefined) {
    if (typeof eventType === 'string') {
      if (!eventType.trim()) return 'PORT_SCAN config.eventType must be a non-empty string.';
    } else if (Array.isArray(eventType)) {
      if (eventType.length === 0 || !eventType.every((t) => typeof t === 'string' && t.trim())) {
        return 'PORT_SCAN config.eventType array must contain non-empty strings.';
      }
    } else {
      return 'PORT_SCAN config.eventType must be a string or array of strings.';
    }
  } else {
    return 'PORT_SCAN requires config.eventType.';
  }

  return null;
}

/**
 * SUSPICIOUS_IP validation
 * Keys: matchSource (boolean), matchDestination (boolean)
 * At least one must be true.
 */
function validateSuspiciousIpConfig(partialConfig, mergedConfig) {
  const allowed = ['matchSource', 'matchDestination'];
  const unknown = Object.keys(partialConfig).filter((k) => !allowed.includes(k));
  if (unknown.length > 0) {
    return `Unsupported config key(s) for SUSPICIOUS_IP: ${unknown.join(', ')}. Allowed: ${allowed.join(', ')}.`;
  }

  const { matchSource, matchDestination } = mergedConfig;

  if (matchSource !== undefined && typeof matchSource !== 'boolean') {
    return 'SUSPICIOUS_IP config.matchSource must be a boolean.';
  }
  if (matchDestination !== undefined && typeof matchDestination !== 'boolean') {
    return 'SUSPICIOUS_IP config.matchDestination must be a boolean.';
  }

  if (matchSource === false && matchDestination === false) {
    return 'SUSPICIOUS_IP config must have at least one of matchSource or matchDestination enabled (true).';
  }

  return null;
}

/**
 * SUSPICIOUS_ACCESS validation
 * Keys: allowedHoursStart (0-23), allowedHoursEnd (1-24), alertOnWeekend (boolean), targetRole (string)
 */
function validateSuspiciousAccessConfig(partialConfig, mergedConfig) {
  const allowed = ['allowedHoursStart', 'allowedHoursEnd', 'alertOnWeekend', 'targetRole'];
  const unknown = Object.keys(partialConfig).filter((k) => !allowed.includes(k));
  if (unknown.length > 0) {
    return `Unsupported config key(s) for SUSPICIOUS_ACCESS: ${unknown.join(', ')}. Allowed: ${allowed.join(', ')}.`;
  }

  const { allowedHoursStart, allowedHoursEnd, alertOnWeekend, targetRole } = mergedConfig;

  if (allowedHoursStart !== undefined) {
    if (!Number.isInteger(allowedHoursStart) || allowedHoursStart < 0 || allowedHoursStart > 23) {
      return 'SUSPICIOUS_ACCESS config.allowedHoursStart must be an integer between 0 and 23.';
    }
  } else {
    return 'SUSPICIOUS_ACCESS requires config.allowedHoursStart.';
  }

  if (allowedHoursEnd !== undefined) {
    if (!Number.isInteger(allowedHoursEnd) || allowedHoursEnd < 1 || allowedHoursEnd > 24) {
      return 'SUSPICIOUS_ACCESS config.allowedHoursEnd must be an integer between 1 and 24.';
    }
  } else {
    return 'SUSPICIOUS_ACCESS requires config.allowedHoursEnd.';
  }

  if (allowedHoursStart >= allowedHoursEnd) {
    return `SUSPICIOUS_ACCESS config.allowedHoursStart (${allowedHoursStart}) must be strictly less than allowedHoursEnd (${allowedHoursEnd}).`;
  }

  if (alertOnWeekend !== undefined) {
    if (typeof alertOnWeekend !== 'boolean') {
      return 'SUSPICIOUS_ACCESS config.alertOnWeekend must be a boolean.';
    }
  } else {
    return 'SUSPICIOUS_ACCESS requires config.alertOnWeekend.';
  }

  if (targetRole !== undefined) {
    if (typeof targetRole !== 'string' || !VALID_ROLES.includes(targetRole.toUpperCase())) {
      return `SUSPICIOUS_ACCESS config.targetRole must be one of: ${VALID_ROLES.join(', ')}.`;
    }
  }

  return null;
}
