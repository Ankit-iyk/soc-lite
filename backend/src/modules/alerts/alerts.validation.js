// src/modules/alerts/alerts.validation.js
// Validation logic for Alert Management endpoints (Phase 5 Step 1).

import { AlertStatus, Severity } from '@prisma/client';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const VALID_ALERT_STATUSES = Object.values(AlertStatus);
export const VALID_SEVERITIES = Object.values(Severity);
export const ALLOWED_STATUS_TRANSITIONS = ['ACKNOWLEDGED', 'CLOSED'];
export const ALLOWED_UPDATE_BODY_FIELDS = ['status'];

/**
 * Checks whether a value is a valid UUID string.
 * @param {*} val
 * @returns {boolean}
 */
export function isValidUuid(val) {
  return typeof val === 'string' && UUID_REGEX.test(val.trim());
}

/**
 * Validates the alert ID path parameter.
 * @param {*} id
 * @returns {{ isValid: boolean, error?: string }}
 */
export function validateAlertId(id) {
  if (!id || typeof id !== 'string' || !isValidUuid(id)) {
    return {
      isValid: false,
      error: 'Invalid alert ID format. Must be a valid UUID.',
    };
  }
  return { isValid: true };
}

/**
 * Validates and sanitizes query parameters for GET /api/alerts.
 *
 * Supported query parameters:
 * - status: 'OPEN' | 'ACKNOWLEDGED' | 'CLOSED'
 * - severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
 * - ruleId: UUID string
 * - search: string (max 200 chars)
 * - page: positive integer (>= 1, default 1)
 * - limit: positive integer (1-100, default 20)
 * - startDate: ISO date string
 * - endDate: ISO date string
 *
 * @param {object} query
 * @returns {{ isValid: boolean, error?: string, sanitized?: object }}
 */
export function validateAlertQueryParams(query = {}) {
  const sanitized = {
    page: 1,
    limit: 20,
  };

  // 1. Pagination: page
  if (query.page !== undefined) {
    const parsedPage = Number(query.page);
    if (!Number.isInteger(parsedPage) || parsedPage < 1) {
      return {
        isValid: false,
        error: 'Query parameter "page" must be a positive integer greater than or equal to 1.',
      };
    }
    sanitized.page = parsedPage;
  }

  // 2. Pagination: limit
  if (query.limit !== undefined) {
    const parsedLimit = Number(query.limit);
    if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
      return {
        isValid: false,
        error: 'Query parameter "limit" must be an integer between 1 and 100.',
      };
    }
    sanitized.limit = parsedLimit;
  }

  // 3. Status filter
  if (query.status !== undefined && query.status !== '') {
    if (typeof query.status !== 'string') {
      return { isValid: false, error: 'Query parameter "status" must be a string.' };
    }
    const normalizedStatus = query.status.trim().toUpperCase();
    if (!VALID_ALERT_STATUSES.includes(normalizedStatus)) {
      return {
        isValid: false,
        error: `Invalid status filter. Allowed values: ${VALID_ALERT_STATUSES.join(', ')}.`,
      };
    }
    sanitized.status = normalizedStatus;
  }

  // 4. Severity filter
  if (query.severity !== undefined && query.severity !== '') {
    if (typeof query.severity !== 'string') {
      return { isValid: false, error: 'Query parameter "severity" must be a string.' };
    }
    const normalizedSeverity = query.severity.trim().toUpperCase();
    if (!VALID_SEVERITIES.includes(normalizedSeverity)) {
      return {
        isValid: false,
        error: `Invalid severity filter. Allowed values: ${VALID_SEVERITIES.join(', ')}.`,
      };
    }
    sanitized.severity = normalizedSeverity;
  }

  // 5. Rule ID filter
  if (query.ruleId !== undefined && query.ruleId !== '') {
    if (typeof query.ruleId !== 'string' || !isValidUuid(query.ruleId)) {
      return {
        isValid: false,
        error: 'Query parameter "ruleId" must be a valid UUID.',
      };
    }
    sanitized.ruleId = query.ruleId.trim();
  }

  // 6. Search keyword
  if (query.search !== undefined && query.search !== '') {
    if (typeof query.search !== 'string') {
      return { isValid: false, error: 'Query parameter "search" must be a string.' };
    }
    const trimmedSearch = query.search.trim();
    if (trimmedSearch.length > 200) {
      return {
        isValid: false,
        error: 'Query parameter "search" must not exceed 200 characters.',
      };
    }
    sanitized.search = trimmedSearch;
  }

  // 7. Date range: startDate and endDate
  let startDateObj = null;
  let endDateObj = null;

  if (query.startDate !== undefined && query.startDate !== '') {
    if (typeof query.startDate !== 'string') {
      return { isValid: false, error: 'Query parameter "startDate" must be a valid date string.' };
    }
    startDateObj = new Date(query.startDate);
    if (Number.isNaN(startDateObj.getTime())) {
      return {
        isValid: false,
        error: 'Query parameter "startDate" must be a valid parseable date string (e.g. ISO 8601).',
      };
    }
    sanitized.startDate = startDateObj;
  }

  if (query.endDate !== undefined && query.endDate !== '') {
    if (typeof query.endDate !== 'string') {
      return { isValid: false, error: 'Query parameter "endDate" must be a valid date string.' };
    }
    endDateObj = new Date(query.endDate);
    if (Number.isNaN(endDateObj.getTime())) {
      return {
        isValid: false,
        error: 'Query parameter "endDate" must be a valid parseable date string (e.g. ISO 8601).',
      };
    }
    sanitized.endDate = endDateObj;
  }

  if (startDateObj && endDateObj && startDateObj.getTime() > endDateObj.getTime()) {
    return {
      isValid: false,
      error: 'Query parameter "startDate" must be less than or equal to "endDate".',
    };
  }

  return {
    isValid: true,
    sanitized,
  };
}

/**
 * Validates request payload for PATCH /api/alerts/:id/status.
 * Only allows transitions to 'ACKNOWLEDGED' or 'CLOSED'.
 * Rejects client-supplied IDs, audit fields, timestamps, or arbitrary fields.
 *
 * @param {object} body
 * @returns {{ isValid: boolean, error?: string, status?: string }}
 */
export function validateUpdateStatusPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {
      isValid: false,
      error: 'Request body must be a JSON object.',
    };
  }

  const keys = Object.keys(body);
  if (keys.length === 0) {
    return {
      isValid: false,
      error: 'Request body is empty. Field "status" is required.',
    };
  }

  // Reject unsupported / immutable / client-spoofed fields
  const unsupportedKeys = keys.filter((k) => !ALLOWED_UPDATE_BODY_FIELDS.includes(k));
  if (unsupportedKeys.length > 0) {
    return {
      isValid: false,
      error: `Unsupported or unmodifiable field(s): ${unsupportedKeys.join(', ')}. Only "status" can be updated.`,
    };
  }

  if (!('status' in body) || typeof body.status !== 'string') {
    return {
      isValid: false,
      error: 'Field "status" is required and must be a string.',
    };
  }

  const normalizedStatus = body.status.trim().toUpperCase();
  if (!ALLOWED_STATUS_TRANSITIONS.includes(normalizedStatus)) {
    return {
      isValid: false,
      error: `Invalid status transition "${body.status}". Allowed target statuses are: ${ALLOWED_STATUS_TRANSITIONS.join(', ')}.`,
    };
  }

  return {
    isValid: true,
    status: normalizedStatus,
  };
}
