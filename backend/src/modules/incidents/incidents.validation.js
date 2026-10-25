// src/modules/incidents/incidents.validation.js
// Validation logic for Incident Management endpoints (Phase 6).

import { IncidentStatus, Severity } from '@prisma/client';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const VALID_INCIDENT_STATUSES = Object.values(IncidentStatus);
export const VALID_SEVERITIES = Object.values(Severity);
export const ALLOWED_CREATE_FIELDS = ['title', 'description', 'severity', 'status', 'assignedToId', 'alertIds'];
export const ALLOWED_UPDATE_FIELDS = ['title', 'description', 'severity', 'status', 'assignedToId'];

/**
 * Checks whether a value is a valid UUID string.
 * @param {*} val
 * @returns {boolean}
 */
export function isValidUuid(val) {
  return typeof val === 'string' && UUID_REGEX.test(val.trim());
}

/**
 * Validates the incident ID path parameter.
 * @param {*} id
 * @returns {{ isValid: boolean, error?: string }}
 */
export function validateIncidentId(id) {
  if (!id || typeof id !== 'string' || !isValidUuid(id)) {
    return {
      isValid: false,
      error: 'Invalid incident ID format. Must be a valid UUID.',
    };
  }
  return { isValid: true };
}

/**
 * Validates and sanitizes query parameters for GET /api/incidents.
 *
 * Supported query parameters:
 * - status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED'
 * - severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
 * - assignedToId: UUID string
 * - search: string (max 200 chars)
 * - page: positive integer (>= 1, default 1)
 * - limit: positive integer (1-100, default 20)
 * - startDate: ISO date string
 * - endDate: ISO date string
 *
 * @param {object} query
 * @returns {{ isValid: boolean, error?: string, sanitized?: object }}
 */
export function validateIncidentQueryParams(query = {}) {
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
    if (!VALID_INCIDENT_STATUSES.includes(normalizedStatus)) {
      return {
        isValid: false,
        error: `Invalid status filter. Allowed values: ${VALID_INCIDENT_STATUSES.join(', ')}.`,
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

  // 5. Assigned user ID filter
  if (query.assignedToId !== undefined && query.assignedToId !== '') {
    if (typeof query.assignedToId !== 'string' || !isValidUuid(query.assignedToId)) {
      return {
        isValid: false,
        error: 'Query parameter "assignedToId" must be a valid UUID.',
      };
    }
    sanitized.assignedToId = query.assignedToId.trim();
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
 * Validates request payload for POST /api/incidents.
 * Rejects client-supplied IDs, audit fields, timestamps, or arbitrary fields.
 *
 * @param {object} body
 * @returns {{ isValid: boolean, error?: string, sanitized?: object }}
 */
export function validateCreateIncidentPayload(body) {
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
      error: 'Request body is empty. Field "title" is required.',
    };
  }

  // Reject unsupported fields
  const unsupportedKeys = keys.filter((k) => !ALLOWED_CREATE_FIELDS.includes(k));
  if (unsupportedKeys.length > 0) {
    return {
      isValid: false,
      error: `Unsupported field(s): ${unsupportedKeys.join(', ')}. Allowed fields: ${ALLOWED_CREATE_FIELDS.join(', ')}.`,
    };
  }

  // 1. Title (required)
  if (!('title' in body) || typeof body.title !== 'string' || !body.title.trim()) {
    return {
      isValid: false,
      error: 'Field "title" is required and must be a non-empty string.',
    };
  }
  const title = body.title.trim();
  if (title.length > 200) {
    return {
      isValid: false,
      error: 'Field "title" must not exceed 200 characters.',
    };
  }

  const sanitized = { title };

  // 2. Description (optional)
  if ('description' in body && body.description !== null && body.description !== undefined) {
    if (typeof body.description !== 'string') {
      return { isValid: false, error: 'Field "description" must be a string or null.' };
    }
    if (body.description.length > 2000) {
      return { isValid: false, error: 'Field "description" must not exceed 2000 characters.' };
    }
    sanitized.description = body.description.trim() || null;
  } else {
    sanitized.description = null;
  }

  // 3. Severity (optional, default MEDIUM)
  if ('severity' in body && body.severity !== undefined) {
    if (typeof body.severity !== 'string') {
      return { isValid: false, error: 'Field "severity" must be a string.' };
    }
    const normalizedSev = body.severity.trim().toUpperCase();
    if (!VALID_SEVERITIES.includes(normalizedSev)) {
      return {
        isValid: false,
        error: `Invalid severity "${body.severity}". Allowed: ${VALID_SEVERITIES.join(', ')}.`,
      };
    }
    sanitized.severity = normalizedSev;
  } else {
    sanitized.severity = Severity.MEDIUM;
  }

  // 4. Status (optional, default OPEN)
  if ('status' in body && body.status !== undefined) {
    if (typeof body.status !== 'string') {
      return { isValid: false, error: 'Field "status" must be a string.' };
    }
    const normalizedStatus = body.status.trim().toUpperCase();
    if (!VALID_INCIDENT_STATUSES.includes(normalizedStatus)) {
      return {
        isValid: false,
        error: `Invalid status "${body.status}". Allowed: ${VALID_INCIDENT_STATUSES.join(', ')}.`,
      };
    }
    sanitized.status = normalizedStatus;
  } else {
    sanitized.status = IncidentStatus.OPEN;
  }

  // 5. AssignedToId (optional)
  if ('assignedToId' in body && body.assignedToId !== null && body.assignedToId !== undefined) {
    if (typeof body.assignedToId !== 'string' || !isValidUuid(body.assignedToId)) {
      return {
        isValid: false,
        error: 'Field "assignedToId" must be a valid UUID or null.',
      };
    }
    sanitized.assignedToId = body.assignedToId.trim();
  } else {
    sanitized.assignedToId = null;
  }

  // 6. AlertIds (optional, array of UUIDs)
  if ('alertIds' in body && body.alertIds !== undefined) {
    if (!Array.isArray(body.alertIds)) {
      return {
        isValid: false,
        error: 'Field "alertIds" must be an array of alert UUID strings.',
      };
    }
    for (const aId of body.alertIds) {
      if (typeof aId !== 'string' || !isValidUuid(aId)) {
        return {
          isValid: false,
          error: `Invalid alert ID "${aId}" in alertIds array. Must be a valid UUID.`,
        };
      }
    }
    sanitized.alertIds = [...new Set(body.alertIds.map((id) => id.trim()))];
  } else {
    sanitized.alertIds = [];
  }

  return {
    isValid: true,
    sanitized,
  };
}

/**
 * Validates request payload for PATCH /api/incidents/:id.
 * Allows partial updates of title, description, severity, status, assignedToId.
 *
 * @param {object} body
 * @returns {{ isValid: boolean, error?: string, sanitized?: object }}
 */
export function validateUpdateIncidentPayload(body) {
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
      error: 'No update fields provided. At least one of [title, description, severity, status, assignedToId] must be specified.',
    };
  }

  const unsupportedKeys = keys.filter((k) => !ALLOWED_UPDATE_FIELDS.includes(k));
  if (unsupportedKeys.length > 0) {
    return {
      isValid: false,
      error: `Unsupported or unmodifiable field(s): ${unsupportedKeys.join(', ')}. Allowed fields: ${ALLOWED_UPDATE_FIELDS.join(', ')}.`,
    };
  }

  const sanitized = {};

  // Title
  if ('title' in body) {
    if (typeof body.title !== 'string' || !body.title.trim()) {
      return { isValid: false, error: 'Field "title" must be a non-empty string.' };
    }
    if (body.title.trim().length > 200) {
      return { isValid: false, error: 'Field "title" must not exceed 200 characters.' };
    }
    sanitized.title = body.title.trim();
  }

  // Description
  if ('description' in body) {
    if (body.description !== null && typeof body.description !== 'string') {
      return { isValid: false, error: 'Field "description" must be a string or null.' };
    }
    if (typeof body.description === 'string' && body.description.length > 2000) {
      return { isValid: false, error: 'Field "description" must not exceed 2000 characters.' };
    }
    sanitized.description = typeof body.description === 'string' ? body.description.trim() || null : null;
  }

  // Severity
  if ('severity' in body) {
    if (typeof body.severity !== 'string') {
      return { isValid: false, error: 'Field "severity" must be a string.' };
    }
    const normalizedSev = body.severity.trim().toUpperCase();
    if (!VALID_SEVERITIES.includes(normalizedSev)) {
      return {
        isValid: false,
        error: `Invalid severity "${body.severity}". Allowed: ${VALID_SEVERITIES.join(', ')}.`,
      };
    }
    sanitized.severity = normalizedSev;
  }

  // Status
  if ('status' in body) {
    if (typeof body.status !== 'string') {
      return { isValid: false, error: 'Field "status" must be a string.' };
    }
    const normalizedStatus = body.status.trim().toUpperCase();
    if (!VALID_INCIDENT_STATUSES.includes(normalizedStatus)) {
      return {
        isValid: false,
        error: `Invalid status "${body.status}". Allowed: ${VALID_INCIDENT_STATUSES.join(', ')}.`,
      };
    }
    sanitized.status = normalizedStatus;
  }

  // AssignedToId
  if ('assignedToId' in body) {
    if (body.assignedToId !== null && (typeof body.assignedToId !== 'string' || !isValidUuid(body.assignedToId))) {
      return { isValid: false, error: 'Field "assignedToId" must be a valid UUID or null.' };
    }
    sanitized.assignedToId = typeof body.assignedToId === 'string' ? body.assignedToId.trim() : null;
  }

  return {
    isValid: true,
    sanitized,
  };
}

/**
 * Validates request payload for POST /api/incidents/:id/alerts.
 * Accepts { alertIds: string[] } or { alertId: string }.
 *
 * @param {object} body
 * @returns {{ isValid: boolean, error?: string, alertIds?: string[] }}
 */
export function validateLinkAlertsPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {
      isValid: false,
      error: 'Request body must be a JSON object.',
    };
  }

  let rawIds = [];

  if (Array.isArray(body.alertIds)) {
    rawIds = body.alertIds;
  } else if (typeof body.alertId === 'string') {
    rawIds = [body.alertId];
  } else {
    return {
      isValid: false,
      error: 'Request body must contain "alertIds" (array of UUIDs) or "alertId" (UUID string).',
    };
  }

  if (rawIds.length === 0) {
    return {
      isValid: false,
      error: 'At least one alert ID must be provided to link.',
    };
  }

  const sanitizedIds = [];
  for (const aId of rawIds) {
    if (typeof aId !== 'string' || !isValidUuid(aId)) {
      return {
        isValid: false,
        error: `Invalid alert ID "${aId}". Must be a valid UUID.`,
      };
    }
    sanitizedIds.push(aId.trim());
  }

  return {
    isValid: true,
    alertIds: [...new Set(sanitizedIds)],
  };
}

/**
 * Validates request payload for POST /api/incidents/:id/notes.
 *
 * @param {object} body
 * @returns {{ isValid: boolean, error?: string, note?: string }}
 */
export function validateAddNotePayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {
      isValid: false,
      error: 'Request body must be a JSON object.',
    };
  }

  if (!('note' in body) || typeof body.note !== 'string' || !body.note.trim()) {
    return {
      isValid: false,
      error: 'Field "note" is required and must be a non-empty string.',
    };
  }

  const trimmedNote = body.note.trim();
  if (trimmedNote.length > 2000) {
    return {
      isValid: false,
      error: 'Field "note" must not exceed 2000 characters.',
    };
  }

  return {
    isValid: true,
    note: trimmedNote,
  };
}
