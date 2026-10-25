// src/modules/audit/audit.validation.js
// Request validation and sanitization for Audit History API (Phase 12).

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validates and sanitizes query parameters for GET /api/audit-logs
 * @param {object} query - Express req.query
 * @returns {{ isValid: boolean, error?: string, sanitized?: object }}
 */
export function validateAuditQueryParams(query = {}) {
  const sanitized = {
    page: 1,
    limit: 25,
    action: undefined,
    targetType: undefined,
    userId: undefined,
    search: undefined,
    startDate: undefined,
    endDate: undefined,
  };

  // 1. Page validation
  if (query.page !== undefined) {
    const parsedPage = parseInt(query.page, 10);
    if (isNaN(parsedPage) || parsedPage < 1) {
      return { isValid: false, error: 'Query parameter "page" must be a positive integer.' };
    }
    sanitized.page = parsedPage;
  }

  // 2. Limit validation (bounded 1 - 100)
  if (query.limit !== undefined) {
    const parsedLimit = parseInt(query.limit, 10);
    if (isNaN(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
      return { isValid: false, error: 'Query parameter "limit" must be an integer between 1 and 100.' };
    }
    sanitized.limit = parsedLimit;
  }

  // 3. Action filter
  if (query.action !== undefined && typeof query.action === 'string') {
    const trimmed = query.action.trim();
    if (trimmed.length > 60) {
      return { isValid: false, error: 'Action filter exceeds maximum length of 60 characters.' };
    }
    if (trimmed.length > 0) {
      sanitized.action = trimmed.toUpperCase();
    }
  }

  // 4. TargetType filter
  if (query.targetType !== undefined && typeof query.targetType === 'string') {
    const trimmed = query.targetType.trim();
    if (trimmed.length > 40) {
      return { isValid: false, error: 'TargetType filter exceeds maximum length of 40 characters.' };
    }
    if (trimmed.length > 0) {
      sanitized.targetType = trimmed;
    }
  }

  // 5. UserId filter
  if (query.userId !== undefined && typeof query.userId === 'string') {
    const trimmed = query.userId.trim();
    if (trimmed.length > 0) {
      if (!UUID_REGEX.test(trimmed)) {
        return { isValid: false, error: 'User ID filter must be a valid UUID format.' };
      }
      sanitized.userId = trimmed;
    }
  }

  // 6. Free text search
  if (query.search !== undefined && typeof query.search === 'string') {
    const trimmed = query.search.trim();
    if (trimmed.length > 100) {
      return { isValid: false, error: 'Search term exceeds maximum length of 100 characters.' };
    }
    if (trimmed.length > 0) {
      sanitized.search = trimmed;
    }
  }

  // 7. Date range validation
  if (query.startDate) {
    const parsed = new Date(query.startDate);
    if (isNaN(parsed.getTime())) {
      return { isValid: false, error: 'Invalid startDate format. Must be an ISO 8601 date string.' };
    }
    sanitized.startDate = parsed;
  }

  if (query.endDate) {
    const parsed = new Date(query.endDate);
    if (isNaN(parsed.getTime())) {
      return { isValid: false, error: 'Invalid endDate format. Must be an ISO 8601 date string.' };
    }
    sanitized.endDate = parsed;
  }

  if (sanitized.startDate && sanitized.endDate && sanitized.startDate > sanitized.endDate) {
    return { isValid: false, error: 'startDate cannot be later than endDate.' };
  }

  return { isValid: true, sanitized };
}
