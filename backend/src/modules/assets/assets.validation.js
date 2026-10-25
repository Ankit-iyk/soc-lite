// src/modules/assets/assets.validation.js
// Validation helpers for Asset Management (Phase 8).

import net from 'node:net';
import { Severity, AssetStatus } from '@prisma/client';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const ALLOWED_ASSET_TYPES = [
  'SERVER',
  'WORKSTATION',
  'LAPTOP',
  'FIREWALL',
  'ROUTER',
  'SWITCH',
  'CLOUD_INSTANCE',
  'OTHER',
];

export const ALLOWED_ENVIRONMENTS = [
  'PRODUCTION',
  'STAGING',
  'DEVELOPMENT',
  'LAB',
  'OTHER',
];

export const ALLOWED_SORT_FIELDS = [
  'name',
  'hostname',
  'ipAddress',
  'type',
  'criticality',
  'status',
  'createdAt',
  'updatedAt',
];

/**
 * Validates a UUID v4 string identifier.
 */
export function validateAssetId(id) {
  if (!id || typeof id !== 'string' || !UUID_REGEX.test(id.trim())) {
    return {
      isValid: false,
      error: 'Invalid asset ID format. Expected a valid UUID.',
    };
  }
  return { isValid: true, id: id.trim() };
}

/**
 * Checks if a string is a valid IPv4 or IPv6 address.
 */
export function isValidIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  return net.isIP(ip.trim()) !== 0;
}

/**
 * Validates query parameters for GET /api/assets.
 */
export function validateAssetQueryParams(query = {}) {
  const sanitized = {
    page: 1,
    limit: 20,
    sortBy: 'createdAt',
    sortOrder: 'desc',
  };

  // Pagination: page
  if (query.page !== undefined && query.page !== null && query.page !== '') {
    const pageNum = parseInt(query.page, 10);
    if (Number.isNaN(pageNum) || pageNum < 1) {
      return { isValid: false, error: 'Query parameter "page" must be a positive integer.' };
    }
    sanitized.page = pageNum;
  }

  // Pagination: limit
  if (query.limit !== undefined && query.limit !== null && query.limit !== '') {
    const limitNum = parseInt(query.limit, 10);
    if (Number.isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
      return { isValid: false, error: 'Query parameter "limit" must be an integer between 1 and 100.' };
    }
    sanitized.limit = limitNum;
  }

  // Search filter (name, hostname, ipAddress, owner)
  if (query.search !== undefined && query.search !== null && query.search !== '') {
    if (typeof query.search !== 'string') {
      return { isValid: false, error: 'Query parameter "search" must be a string.' };
    }
    const trimmed = query.search.trim();
    if (trimmed.length > 100) {
      return { isValid: false, error: 'Query parameter "search" cannot exceed 100 characters.' };
    }
    if (trimmed.length > 0) sanitized.search = trimmed;
  }

  // Status filter
  if (query.status !== undefined && query.status !== null && query.status !== '') {
    if (typeof query.status !== 'string') {
      return { isValid: false, error: 'Query parameter "status" must be a string.' };
    }
    const upper = query.status.trim().toUpperCase();
    if (!(upper in AssetStatus)) {
      return {
        isValid: false,
        error: `Invalid status "${query.status}". Allowed values: ${Object.keys(AssetStatus).join(', ')}.`,
      };
    }
    sanitized.status = upper;
  }

  // Criticality filter
  if (query.criticality !== undefined && query.criticality !== null && query.criticality !== '') {
    if (typeof query.criticality !== 'string') {
      return { isValid: false, error: 'Query parameter "criticality" must be a string.' };
    }
    const upper = query.criticality.trim().toUpperCase();
    if (!(upper in Severity)) {
      return {
        isValid: false,
        error: `Invalid criticality "${query.criticality}". Allowed values: ${Object.keys(Severity).join(', ')}.`,
      };
    }
    sanitized.criticality = upper;
  }

  // Type filter
  if (query.type !== undefined && query.type !== null && query.type !== '') {
    if (typeof query.type !== 'string') {
      return { isValid: false, error: 'Query parameter "type" must be a string.' };
    }
    const upper = query.type.trim().toUpperCase();
    if (upper.length > 50) {
      return { isValid: false, error: 'Query parameter "type" cannot exceed 50 characters.' };
    }
    sanitized.type = upper;
  }

  // Environment filter
  if (query.environment !== undefined && query.environment !== null && query.environment !== '') {
    if (typeof query.environment !== 'string') {
      return { isValid: false, error: 'Query parameter "environment" must be a string.' };
    }
    const upper = query.environment.trim().toUpperCase();
    if (upper.length > 50) {
      return { isValid: false, error: 'Query parameter "environment" cannot exceed 50 characters.' };
    }
    sanitized.environment = upper;
  }

  // Sorting: sortBy
  if (query.sortBy !== undefined && query.sortBy !== null && query.sortBy !== '') {
    if (typeof query.sortBy !== 'string' || !ALLOWED_SORT_FIELDS.includes(query.sortBy.trim())) {
      return {
        isValid: false,
        error: `Invalid sortBy "${query.sortBy}". Allowed fields: ${ALLOWED_SORT_FIELDS.join(', ')}.`,
      };
    }
    sanitized.sortBy = query.sortBy.trim();
  }

  // Sorting: sortOrder
  if (query.sortOrder !== undefined && query.sortOrder !== null && query.sortOrder !== '') {
    const order = query.sortOrder.trim().toLowerCase();
    if (order !== 'asc' && order !== 'desc') {
      return { isValid: false, error: 'Query parameter "sortOrder" must be either "asc" or "desc".' };
    }
    sanitized.sortOrder = order;
  }

  return { isValid: true, sanitized };
}

/**
 * Validates request payload for POST /api/assets.
 */
export function validateCreateAssetPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { isValid: false, error: 'Request body must be a JSON object.' };
  }

  const allowedKeys = [
    'name',
    'hostname',
    'ipAddress',
    'type',
    'status',
    'criticality',
    'environment',
    'operatingSystem',
    'owner',
    'description',
    'tags',
  ];

  const unexpected = Object.keys(body).filter((k) => !allowedKeys.includes(k));
  if (unexpected.length > 0) {
    return {
      isValid: false,
      error: `Unexpected fields in payload: ${unexpected.map((k) => `"${k}"`).join(', ')}.`,
    };
  }

  // Required: name
  if (typeof body.name !== 'string' || body.name.trim().length === 0) {
    return { isValid: false, error: 'Asset "name" is required and cannot be empty.' };
  }
  const name = body.name.trim();
  if (name.length > 100) {
    return { isValid: false, error: 'Asset "name" cannot exceed 100 characters.' };
  }

  const sanitized = { name };

  // Optional: hostname
  if (body.hostname !== undefined && body.hostname !== null && body.hostname !== '') {
    if (typeof body.hostname !== 'string') {
      return { isValid: false, error: 'Field "hostname" must be a string.' };
    }
    const hostname = body.hostname.trim();
    if (hostname.length > 255) {
      return { isValid: false, error: 'Field "hostname" cannot exceed 255 characters.' };
    }
    sanitized.hostname = hostname;
  } else {
    sanitized.hostname = null;
  }

  // Optional: ipAddress
  if (body.ipAddress !== undefined && body.ipAddress !== null && body.ipAddress !== '') {
    if (typeof body.ipAddress !== 'string' || !isValidIp(body.ipAddress)) {
      return { isValid: false, error: 'Field "ipAddress" must be a valid IPv4 or IPv6 address.' };
    }
    sanitized.ipAddress = body.ipAddress.trim();
  } else {
    sanitized.ipAddress = null;
  }

  // Optional: type (default: SERVER)
  if (body.type !== undefined && body.type !== null && body.type !== '') {
    if (typeof body.type !== 'string') {
      return { isValid: false, error: 'Field "type" must be a string.' };
    }
    const typeUpper = body.type.trim().toUpperCase();
    if (!ALLOWED_ASSET_TYPES.includes(typeUpper)) {
      return {
        isValid: false,
        error: `Invalid asset type "${body.type}". Allowed values: ${ALLOWED_ASSET_TYPES.join(', ')}.`,
      };
    }
    sanitized.type = typeUpper;
  } else {
    sanitized.type = 'SERVER';
  }

  // Optional: status (default: ACTIVE)
  if (body.status !== undefined && body.status !== null && body.status !== '') {
    if (typeof body.status !== 'string') {
      return { isValid: false, error: 'Field "status" must be a string.' };
    }
    const statusUpper = body.status.trim().toUpperCase();
    if (!(statusUpper in AssetStatus)) {
      return {
        isValid: false,
        error: `Invalid status "${body.status}". Allowed values: ${Object.keys(AssetStatus).join(', ')}.`,
      };
    }
    sanitized.status = statusUpper;
  } else {
    sanitized.status = 'ACTIVE';
  }

  // Optional: criticality (default: MEDIUM)
  if (body.criticality !== undefined && body.criticality !== null && body.criticality !== '') {
    if (typeof body.criticality !== 'string') {
      return { isValid: false, error: 'Field "criticality" must be a string.' };
    }
    const critUpper = body.criticality.trim().toUpperCase();
    if (!(critUpper in Severity)) {
      return {
        isValid: false,
        error: `Invalid criticality "${body.criticality}". Allowed values: ${Object.keys(Severity).join(', ')}.`,
      };
    }
    sanitized.criticality = critUpper;
  } else {
    sanitized.criticality = 'MEDIUM';
  }

  // Optional: environment
  if (body.environment !== undefined && body.environment !== null && body.environment !== '') {
    if (typeof body.environment !== 'string') {
      return { isValid: false, error: 'Field "environment" must be a string.' };
    }
    const envUpper = body.environment.trim().toUpperCase();
    if (!ALLOWED_ENVIRONMENTS.includes(envUpper)) {
      return {
        isValid: false,
        error: `Invalid environment "${body.environment}". Allowed values: ${ALLOWED_ENVIRONMENTS.join(', ')}.`,
      };
    }
    sanitized.environment = envUpper;
  } else {
    sanitized.environment = null;
  }

  // Optional: operatingSystem
  if (body.operatingSystem !== undefined && body.operatingSystem !== null && body.operatingSystem !== '') {
    if (typeof body.operatingSystem !== 'string') {
      return { isValid: false, error: 'Field "operatingSystem" must be a string.' };
    }
    const os = body.operatingSystem.trim();
    if (os.length > 100) {
      return { isValid: false, error: 'Field "operatingSystem" cannot exceed 100 characters.' };
    }
    sanitized.operatingSystem = os;
  } else {
    sanitized.operatingSystem = null;
  }

  // Optional: owner
  if (body.owner !== undefined && body.owner !== null && body.owner !== '') {
    if (typeof body.owner !== 'string') {
      return { isValid: false, error: 'Field "owner" must be a string.' };
    }
    const owner = body.owner.trim();
    if (owner.length > 100) {
      return { isValid: false, error: 'Field "owner" cannot exceed 100 characters.' };
    }
    sanitized.owner = owner;
  } else {
    sanitized.owner = null;
  }

  // Optional: description
  if (body.description !== undefined && body.description !== null && body.description !== '') {
    if (typeof body.description !== 'string') {
      return { isValid: false, error: 'Field "description" must be a string.' };
    }
    const desc = body.description.trim();
    if (desc.length > 1000) {
      return { isValid: false, error: 'Field "description" cannot exceed 1000 characters.' };
    }
    sanitized.description = desc;
  } else {
    sanitized.description = null;
  }

  // Optional: tags
  if (body.tags !== undefined && body.tags !== null) {
    if (!Array.isArray(body.tags)) {
      return { isValid: false, error: 'Field "tags" must be an array of strings.' };
    }
    if (body.tags.length > 20) {
      return { isValid: false, error: 'Cannot attach more than 20 tags to an asset.' };
    }
    const validTags = [];
    for (const tag of body.tags) {
      if (typeof tag !== 'string' || tag.trim().length === 0) {
        return { isValid: false, error: 'Each tag must be a non-empty string.' };
      }
      const t = tag.trim().toLowerCase();
      if (t.length > 50) {
        return { isValid: false, error: 'Tag cannot exceed 50 characters.' };
      }
      if (!validTags.includes(t)) validTags.push(t);
    }
    sanitized.tags = validTags;
  } else {
    sanitized.tags = [];
  }

  return { isValid: true, sanitized };
}

/**
 * Validates request payload for PATCH /api/assets/:id.
 */
export function validateUpdateAssetPayload(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { isValid: false, error: 'Request body must be a JSON object.' };
  }

  const allowedKeys = [
    'name',
    'hostname',
    'ipAddress',
    'type',
    'status',
    'criticality',
    'environment',
    'operatingSystem',
    'owner',
    'description',
    'tags',
  ];

  const keys = Object.keys(body);
  if (keys.length === 0) {
    return { isValid: false, error: 'Request body cannot be empty. At least one field must be updated.' };
  }

  const unexpected = keys.filter((k) => !allowedKeys.includes(k));
  if (unexpected.length > 0) {
    return {
      isValid: false,
      error: `Unexpected fields in payload: ${unexpected.map((k) => `"${k}"`).join(', ')}.`,
    };
  }

  const sanitized = {};

  if ('name' in body) {
    if (typeof body.name !== 'string' || body.name.trim().length === 0) {
      return { isValid: false, error: 'Field "name" cannot be empty.' };
    }
    const name = body.name.trim();
    if (name.length > 100) {
      return { isValid: false, error: 'Field "name" cannot exceed 100 characters.' };
    }
    sanitized.name = name;
  }

  if ('hostname' in body) {
    if (body.hostname === null || body.hostname === '') {
      sanitized.hostname = null;
    } else {
      if (typeof body.hostname !== 'string') {
        return { isValid: false, error: 'Field "hostname" must be a string or null.' };
      }
      const hostname = body.hostname.trim();
      if (hostname.length > 255) {
        return { isValid: false, error: 'Field "hostname" cannot exceed 255 characters.' };
      }
      sanitized.hostname = hostname;
    }
  }

  if ('ipAddress' in body) {
    if (body.ipAddress === null || body.ipAddress === '') {
      sanitized.ipAddress = null;
    } else {
      if (typeof body.ipAddress !== 'string' || !isValidIp(body.ipAddress)) {
        return { isValid: false, error: 'Field "ipAddress" must be a valid IPv4 or IPv6 address or null.' };
      }
      sanitized.ipAddress = body.ipAddress.trim();
    }
  }

  if ('type' in body) {
    if (typeof body.type !== 'string') {
      return { isValid: false, error: 'Field "type" must be a string.' };
    }
    const typeUpper = body.type.trim().toUpperCase();
    if (!ALLOWED_ASSET_TYPES.includes(typeUpper)) {
      return {
        isValid: false,
        error: `Invalid asset type "${body.type}". Allowed values: ${ALLOWED_ASSET_TYPES.join(', ')}.`,
      };
    }
    sanitized.type = typeUpper;
  }

  if ('status' in body) {
    if (typeof body.status !== 'string') {
      return { isValid: false, error: 'Field "status" must be a string.' };
    }
    const statusUpper = body.status.trim().toUpperCase();
    if (!(statusUpper in AssetStatus)) {
      return {
        isValid: false,
        error: `Invalid status "${body.status}". Allowed values: ${Object.keys(AssetStatus).join(', ')}.`,
      };
    }
    sanitized.status = statusUpper;
  }

  if ('criticality' in body) {
    if (typeof body.criticality !== 'string') {
      return { isValid: false, error: 'Field "criticality" must be a string.' };
    }
    const critUpper = body.criticality.trim().toUpperCase();
    if (!(critUpper in Severity)) {
      return {
        isValid: false,
        error: `Invalid criticality "${body.criticality}". Allowed values: ${Object.keys(Severity).join(', ')}.`,
      };
    }
    sanitized.criticality = critUpper;
  }

  if ('environment' in body) {
    if (body.environment === null || body.environment === '') {
      sanitized.environment = null;
    } else {
      if (typeof body.environment !== 'string') {
        return { isValid: false, error: 'Field "environment" must be a string or null.' };
      }
      const envUpper = body.environment.trim().toUpperCase();
      if (!ALLOWED_ENVIRONMENTS.includes(envUpper)) {
        return {
          isValid: false,
          error: `Invalid environment "${body.environment}". Allowed values: ${ALLOWED_ENVIRONMENTS.join(', ')}.`,
        };
      }
      sanitized.environment = envUpper;
    }
  }

  if ('operatingSystem' in body) {
    if (body.operatingSystem === null || body.operatingSystem === '') {
      sanitized.operatingSystem = null;
    } else {
      if (typeof body.operatingSystem !== 'string') {
        return { isValid: false, error: 'Field "operatingSystem" must be a string or null.' };
      }
      const os = body.operatingSystem.trim();
      if (os.length > 100) {
        return { isValid: false, error: 'Field "operatingSystem" cannot exceed 100 characters.' };
      }
      sanitized.operatingSystem = os;
    }
  }

  if ('owner' in body) {
    if (body.owner === null || body.owner === '') {
      sanitized.owner = null;
    } else {
      if (typeof body.owner !== 'string') {
        return { isValid: false, error: 'Field "owner" must be a string or null.' };
      }
      const owner = body.owner.trim();
      if (owner.length > 100) {
        return { isValid: false, error: 'Field "owner" cannot exceed 100 characters.' };
      }
      sanitized.owner = owner;
    }
  }

  if ('description' in body) {
    if (body.description === null || body.description === '') {
      sanitized.description = null;
    } else {
      if (typeof body.description !== 'string') {
        return { isValid: false, error: 'Field "description" must be a string or null.' };
      }
      const desc = body.description.trim();
      if (desc.length > 1000) {
        return { isValid: false, error: 'Field "description" cannot exceed 1000 characters.' };
      }
      sanitized.description = desc;
    }
  }

  if ('tags' in body) {
    if (!Array.isArray(body.tags)) {
      return { isValid: false, error: 'Field "tags" must be an array of strings.' };
    }
    if (body.tags.length > 20) {
      return { isValid: false, error: 'Cannot attach more than 20 tags to an asset.' };
    }
    const validTags = [];
    for (const tag of body.tags) {
      if (typeof tag !== 'string' || tag.trim().length === 0) {
        return { isValid: false, error: 'Each tag must be a non-empty string.' };
      }
      const t = tag.trim().toLowerCase();
      if (t.length > 50) {
        return { isValid: false, error: 'Tag cannot exceed 50 characters.' };
      }
      if (!validTags.includes(t)) validTags.push(t);
    }
    sanitized.tags = validTags;
  }

  return { isValid: true, sanitized };
}
