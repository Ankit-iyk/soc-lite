// backend/src/modules/threat-intelligence/threatIntel.validation.js
// Validation and normalization helpers for Phase 9 Threat Intelligence & IOC Integration.

import { URL } from 'node:url';

// ── Regular Expressions & Patterns ──────────────────────────────────────────

// Standard IPv4: 4 octets, 0-255
const IPV4_REGEX = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;

// Comprehensive IPv6 pattern supporting compressed and full notation
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;

// Standard Domain Name (RFC 1035): label.label.tld
const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

// Supported file hash lengths: MD5 (32), SHA-1 (40), SHA-256 (64)
const HASH_REGEX = /^[0-9a-fA-F]+$/;

// UUID validation (standard hex 8-4-4-4-12)
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const VALID_IOC_TYPES = ['IP', 'DOMAIN', 'HASH', 'URL'];
export const VALID_IOC_STATUSES = ['ACTIVE', 'INACTIVE', 'EXPIRED', 'REVOKED'];
export const VALID_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * Normalizes input type string to standard Prisma IocType enum.
 * Supports friendly aliases like "IP_ADDRESS" and "FILE_HASH".
 */
export function normalizeIocType(rawType) {
  if (!rawType || typeof rawType !== 'string') return null;
  const upper = rawType.trim().toUpperCase();
  if (upper === 'IP' || upper === 'IP_ADDRESS') return 'IP';
  if (upper === 'DOMAIN') return 'DOMAIN';
  if (upper === 'HASH' || upper === 'FILE_HASH') return 'HASH';
  if (upper === 'URL') return 'URL';
  return null;
}

/**
 * Validates and normalizes an indicator value according to its type.
 * Returns { valid: true, value: normalizedValue, hashType: string|undefined } or { valid: false, error: string }
 */
export function validateAndNormalizeIocValue(type, rawValue) {
  if (typeof rawValue !== 'string' || !rawValue.trim()) {
    return { valid: false, error: 'Indicator value cannot be empty' };
  }

  const trimmed = rawValue.trim();

  switch (type) {
    case 'IP': {
      if (IPV4_REGEX.test(trimmed)) {
        return { valid: true, value: trimmed };
      }
      if (IPV6_REGEX.test(trimmed)) {
        return { valid: true, value: trimmed.toLowerCase() };
      }
      return { valid: false, error: 'Invalid IPv4 or IPv6 address format' };
    }

    case 'DOMAIN': {
      // Strip leading protocol or trailing slashes if user pasted a domain with http/https
      let cleanDomain = trimmed;
      if (cleanDomain.startsWith('http://') || cleanDomain.startsWith('https://')) {
        try {
          cleanDomain = new URL(cleanDomain).hostname;
        } catch {
          return { valid: false, error: 'Invalid domain format' };
        }
      }
      cleanDomain = cleanDomain.toLowerCase().replace(/\/+$/, '');

      if (!DOMAIN_REGEX.test(cleanDomain) || cleanDomain.length > 253) {
        return { valid: false, error: 'Invalid domain name format (e.g., evil-domain.com)' };
      }
      return { valid: true, value: cleanDomain };
    }

    case 'HASH': {
      const lower = trimmed.toLowerCase();
      if (!HASH_REGEX.test(lower)) {
        return { valid: false, error: 'Hash must contain hexadecimal characters only (0-9, a-f)' };
      }

      let hashType;
      if (lower.length === 32) {
        hashType = 'MD5';
      } else if (lower.length === 40) {
        hashType = 'SHA-1';
      } else if (lower.length === 64) {
        hashType = 'SHA-256';
      } else {
        return { valid: false, error: 'Unsupported hash length. Must be MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars)' };
      }

      return { valid: true, value: lower, hashType };
    }

    case 'URL': {
      if (trimmed.length > 2048) {
        return { valid: false, error: 'URL exceeds maximum length of 2048 characters' };
      }

      let parsed;
      try {
        parsed = new URL(trimmed);
      } catch {
        return { valid: false, error: 'Malformed URL format' };
      }

      // Restrict to safe protocols (prevent javascript:, file:, data:, blob:)
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { valid: false, error: `Invalid URL protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted` };
      }

      if (!parsed.hostname || parsed.hostname.length < 3) {
        return { valid: false, error: 'URL must contain a valid hostname' };
      }

      // Normalized URL: lowercase scheme and host, preserve path, search, and hash
      const normalized = `${parsed.protocol}//${parsed.host.toLowerCase()}${parsed.pathname}${parsed.search}${parsed.hash}`;
      return { valid: true, value: normalized };
    }

    default:
      return { valid: false, error: `Unsupported indicator type "${type}"` };
  }
}

/**
 * Validates request payload for registering an IOC.
 */
export function validateCreateIocPayload(body) {
  const errors = [];

  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }

  // 1. Validate Type
  const normalizedType = normalizeIocType(body.type);
  if (!normalizedType) {
    errors.push(`Invalid IOC type. Must be one of: ${VALID_IOC_TYPES.join(', ')} (or IP_ADDRESS, FILE_HASH)`);
  }

  // 2. Validate Value
  let normalizedValue = null;
  let hashType = null;
  if (normalizedType) {
    const valResult = validateAndNormalizeIocValue(normalizedType, body.value);
    if (!valResult.valid) {
      errors.push(valResult.error);
    } else {
      normalizedValue = valResult.value;
      hashType = valResult.hashType;
    }
  }

  // 3. Validate Severity (optional, default MEDIUM)
  let severity = 'MEDIUM';
  if (body.severity !== undefined) {
    const upperSev = String(body.severity).toUpperCase();
    if (!VALID_SEVERITIES.includes(upperSev)) {
      errors.push(`Invalid severity "${body.severity}". Must be one of: ${VALID_SEVERITIES.join(', ')}`);
    } else {
      severity = upperSev;
    }
  }

  // 4. Validate Status (optional, default ACTIVE)
  let status = 'ACTIVE';
  if (body.status !== undefined) {
    const upperStat = String(body.status).toUpperCase();
    if (!VALID_IOC_STATUSES.includes(upperStat)) {
      errors.push(`Invalid status "${body.status}". Must be one of: ${VALID_IOC_STATUSES.join(', ')}`);
    } else {
      status = upperStat;
    }
  }

  // 5. Validate Confidence (optional, default 80)
  let confidence = 80;
  if (body.confidence !== undefined) {
    const parsedConf = Number(body.confidence);
    if (!Number.isInteger(parsedConf) || parsedConf < 0 || parsedConf > 100) {
      errors.push('Confidence must be an integer between 0 and 100');
    } else {
      confidence = parsedConf;
    }
  }

  // 6. Source (optional, default "MANUAL")
  let source = 'MANUAL';
  if (body.source !== undefined && body.source !== null) {
    if (typeof body.source !== 'string' || body.source.trim().length === 0) {
      errors.push('Source must be a non-empty string');
    } else if (body.source.trim().length > 100) {
      errors.push('Source must not exceed 100 characters');
    } else {
      source = body.source.trim();
    }
  }

  // 7. Description (optional)
  let description = null;
  if (body.description !== undefined && body.description !== null) {
    if (typeof body.description !== 'string') {
      errors.push('Description must be a string');
    } else if (body.description.trim().length > 2000) {
      errors.push('Description must not exceed 2000 characters');
    } else {
      description = body.description.trim() || null;
    }
  }

  // 8. Timestamps (firstSeenAt, lastSeenAt, expiresAt)
  const parseDate = (val, fieldName) => {
    if (val === undefined || val === null || val === '') return null;
    const d = new Date(val);
    if (isNaN(d.getTime())) {
      errors.push(`Invalid ISO date for "${fieldName}"`);
      return null;
    }
    return d;
  };

  const firstSeenAt = parseDate(body.firstSeenAt, 'firstSeenAt');
  const lastSeenAt = parseDate(body.lastSeenAt, 'lastSeenAt');
  const expiresAt = parseDate(body.expiresAt, 'expiresAt');

  if (firstSeenAt && lastSeenAt && firstSeenAt > lastSeenAt) {
    errors.push('firstSeenAt cannot be after lastSeenAt');
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      type: normalizedType,
      value: normalizedValue,
      status,
      severity,
      confidence,
      source,
      description,
      firstSeenAt,
      lastSeenAt,
      expiresAt,
      hashType,
    },
  };
}

/**
 * Validates partial update payload for an existing IOC.
 * Value cannot be changed (IOC value is immutable to prevent identity corruption).
 */
export function validateUpdateIocPayload(body) {
  const errors = [];

  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }

  const updates = {};

  if (body.value !== undefined) {
    errors.push('Indicator value cannot be modified. Delete and recreate the IOC if the value is incorrect.');
  }

  if (body.type !== undefined) {
    errors.push('Indicator type cannot be modified.');
  }

  if (body.severity !== undefined) {
    const upper = String(body.severity).toUpperCase();
    if (!VALID_SEVERITIES.includes(upper)) {
      errors.push(`Invalid severity "${body.severity}". Must be one of: ${VALID_SEVERITIES.join(', ')}`);
    } else {
      updates.severity = upper;
    }
  }

  if (body.status !== undefined) {
    const upper = String(body.status).toUpperCase();
    if (!VALID_IOC_STATUSES.includes(upper)) {
      errors.push(`Invalid status "${body.status}". Must be one of: ${VALID_IOC_STATUSES.join(', ')}`);
    } else {
      updates.status = upper;
    }
  }

  if (body.confidence !== undefined) {
    const parsedConf = Number(body.confidence);
    if (!Number.isInteger(parsedConf) || parsedConf < 0 || parsedConf > 100) {
      errors.push('Confidence must be an integer between 0 and 100');
    } else {
      updates.confidence = parsedConf;
    }
  }

  if (body.source !== undefined) {
    if (typeof body.source !== 'string' || body.source.trim().length === 0) {
      errors.push('Source must be a non-empty string');
    } else if (body.source.trim().length > 100) {
      errors.push('Source must not exceed 100 characters');
    } else {
      updates.source = body.source.trim();
    }
  }

  if (body.description !== undefined) {
    if (body.description === null || body.description === '') {
      updates.description = null;
    } else if (typeof body.description !== 'string') {
      errors.push('Description must be a string');
    } else if (body.description.trim().length > 2000) {
      errors.push('Description must not exceed 2000 characters');
    } else {
      updates.description = body.description.trim();
    }
  }

  const parseDate = (val, fieldName) => {
    if (val === undefined || val === null || val === '') return null;
    const d = new Date(val);
    if (isNaN(d.getTime())) {
      errors.push(`Invalid ISO date for "${fieldName}"`);
      return null;
    }
    return d;
  };

  if (body.firstSeenAt !== undefined) {
    updates.firstSeenAt = parseDate(body.firstSeenAt, 'firstSeenAt');
  }
  if (body.lastSeenAt !== undefined) {
    updates.lastSeenAt = parseDate(body.lastSeenAt, 'lastSeenAt');
  }
  if (body.expiresAt !== undefined) {
    updates.expiresAt = parseDate(body.expiresAt, 'expiresAt');
  }

  if (Object.keys(updates).length === 0 && errors.length === 0) {
    errors.push('No valid update fields provided');
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true, data: updates };
}

/**
 * Validates UUID parameter.
 */
export function validateUuid(id) {
  return typeof id === 'string' && UUID_REGEX.test(id.trim());
}

/**
 * Validates query parameters for listing IOCs.
 */
export function validateIocQueryParams(query) {
  const page = Math.max(1, parseInt(query.page ?? '1', 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit ?? '10', 10) || 10));

  const search = typeof query.search === 'string' && query.search.trim() ? query.search.trim().slice(0, 100) : null;

  let type = null;
  if (query.type) {
    type = normalizeIocType(query.type);
  }

  let status = null;
  if (query.status) {
    const s = String(query.status).toUpperCase();
    if (VALID_IOC_STATUSES.includes(s)) status = s;
  }

  let severity = null;
  if (query.severity) {
    const sev = String(query.severity).toUpperCase();
    if (VALID_SEVERITIES.includes(sev)) severity = sev;
  }

  const allowedSortBy = ['createdAt', 'value', 'confidence', 'severity', 'status', 'addedAt'];
  const sortBy = allowedSortBy.includes(query.sortBy) ? query.sortBy : 'createdAt';
  const sortOrder = query.sortOrder === 'asc' ? 'asc' : 'desc';

  return {
    page,
    limit,
    search,
    type,
    status,
    severity,
    sortBy,
    sortOrder,
  };
}
