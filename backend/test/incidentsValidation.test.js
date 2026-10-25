// test/incidentsValidation.test.js
// Unit tests for Incident Management validation logic (Phase 6 Step 2).
// Uses Node 22 native test runner (node:test).

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidUuid,
  validateIncidentId,
  validateIncidentQueryParams,
  validateCreateIncidentPayload,
  validateUpdateIncidentPayload,
  validateLinkAlertsPayload,
  validateAddNotePayload,
  VALID_INCIDENT_STATUSES,
  VALID_SEVERITIES,
} from '../src/modules/incidents/incidents.validation.js';

describe('Phase 6 Step 2 — Incident Validation Unit Tests', () => {
  describe('isValidUuid and validateIncidentId', () => {
    it('accepts valid UUID strings', () => {
      const valid = '12345678-1234-4234-8234-123456789abc';
      assert.equal(isValidUuid(valid), true);
      const res = validateIncidentId(valid);
      assert.equal(res.isValid, true);
    });

    it('rejects malformed UUID strings', () => {
      const invalid = ['not-a-uuid', '', null, undefined, 123, {}];
      for (const val of invalid) {
        assert.equal(isValidUuid(val), false);
        const res = validateIncidentId(val);
        assert.equal(res.isValid, false);
      }
    });
  });

  describe('validateIncidentQueryParams', () => {
    it('provides sensible defaults for empty query', () => {
      const { isValid, sanitized } = validateIncidentQueryParams({});
      assert.equal(isValid, true);
      assert.equal(sanitized.page, 1);
      assert.equal(sanitized.limit, 20);
    });

    it('validates and sanitizes pagination', () => {
      const { isValid, sanitized } = validateIncidentQueryParams({ page: '2', limit: '50' });
      assert.equal(isValid, true);
      assert.equal(sanitized.page, 2);
      assert.equal(sanitized.limit, 50);
    });

    it('rejects invalid page or limit values', () => {
      assert.equal(validateIncidentQueryParams({ page: '0' }).isValid, false);
      assert.equal(validateIncidentQueryParams({ page: '-1' }).isValid, false);
      assert.equal(validateIncidentQueryParams({ limit: '0' }).isValid, false);
      assert.equal(validateIncidentQueryParams({ limit: '101' }).isValid, false);
    });

    it('accepts valid incident statuses case-insensitively', () => {
      for (const s of VALID_INCIDENT_STATUSES) {
        const { isValid, sanitized } = validateIncidentQueryParams({ status: s.toLowerCase() });
        assert.equal(isValid, true);
        assert.equal(sanitized.status, s);
      }
    });

    it('rejects invalid status filter', () => {
      const { isValid, error } = validateIncidentQueryParams({ status: 'INVALID_STATUS' });
      assert.equal(isValid, false);
      assert.ok(error.includes('Invalid status filter'));
    });

    it('accepts valid severities case-insensitively', () => {
      for (const sev of VALID_SEVERITIES) {
        const { isValid, sanitized } = validateIncidentQueryParams({ severity: sev.toLowerCase() });
        assert.equal(isValid, true);
        assert.equal(sanitized.severity, sev);
      }
    });

    it('rejects invalid severity filter', () => {
      const { isValid, error } = validateIncidentQueryParams({ severity: 'CRITICAL_PLUS' });
      assert.equal(isValid, false);
      assert.ok(error.includes('Invalid severity filter'));
    });

    it('validates assignedToId as UUID', () => {
      const validUuid = '11111111-2222-3333-4444-555555555555';
      assert.equal(validateIncidentQueryParams({ assignedToId: validUuid }).isValid, true);
      assert.equal(validateIncidentQueryParams({ assignedToId: 'bad-id' }).isValid, false);
    });

    it('enforces search query length', () => {
      assert.equal(validateIncidentQueryParams({ search: 'ransomware' }).isValid, true);
      assert.equal(validateIncidentQueryParams({ search: 'a'.repeat(205) }).isValid, false);
    });

    it('validates date range correctly', () => {
      const start = '2026-01-01T00:00:00Z';
      const end = '2026-01-02T00:00:00Z';
      assert.equal(validateIncidentQueryParams({ startDate: start, endDate: end }).isValid, true);
      assert.equal(validateIncidentQueryParams({ startDate: end, endDate: start }).isValid, false);
      assert.equal(validateIncidentQueryParams({ startDate: 'not-a-date' }).isValid, false);
    });
  });

  describe('validateCreateIncidentPayload', () => {
    it('accepts valid incident payload with all fields', () => {
      const validPayload = {
        title: 'Suspected Ransomware Outbreak',
        description: 'Multiple encrypted hosts detected on subnet 10.0.1.0/24',
        severity: 'CRITICAL',
        status: 'OPEN',
        assignedToId: '11111111-2222-3333-4444-555555555555',
        alertIds: ['aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'],
      };
      const res = validateCreateIncidentPayload(validPayload);
      assert.equal(res.isValid, true);
      assert.equal(res.sanitized.title, validPayload.title);
      assert.equal(res.sanitized.severity, 'CRITICAL');
      assert.equal(res.sanitized.status, 'OPEN');
      assert.equal(res.sanitized.alertIds.length, 1);
    });

    it('applies defaults for optional fields', () => {
      const res = validateCreateIncidentPayload({ title: 'Basic Incident' });
      assert.equal(res.isValid, true);
      assert.equal(res.sanitized.severity, 'MEDIUM');
      assert.equal(res.sanitized.status, 'OPEN');
      assert.equal(res.sanitized.description, null);
      assert.equal(res.sanitized.assignedToId, null);
      assert.deepEqual(res.sanitized.alertIds, []);
    });

    it('rejects missing or empty title', () => {
      assert.equal(validateCreateIncidentPayload({}).isValid, false);
      assert.equal(validateCreateIncidentPayload({ title: '' }).isValid, false);
      assert.equal(validateCreateIncidentPayload({ title: '   ' }).isValid, false);
    });

    it('rejects unsupported fields in body', () => {
      const res = validateCreateIncidentPayload({
        title: 'Valid Title',
        id: 'client-injected-id',
        createdAt: '2020-01-01',
      });
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('Unsupported field'));
    });

    it('rejects invalid alert UUIDs in alertIds', () => {
      const res = validateCreateIncidentPayload({
        title: 'Test',
        alertIds: ['valid-uuid', 'not-a-uuid'],
      });
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('Invalid alert ID'));
    });
  });

  describe('validateUpdateIncidentPayload', () => {
    it('accepts valid partial update', () => {
      const res = validateUpdateIncidentPayload({
        status: 'INVESTIGATING',
        severity: 'HIGH',
      });
      assert.equal(res.isValid, true);
      assert.equal(res.sanitized.status, 'INVESTIGATING');
      assert.equal(res.sanitized.severity, 'HIGH');
    });

    it('accepts clearing assignedToId to null', () => {
      const res = validateUpdateIncidentPayload({ assignedToId: null });
      assert.equal(res.isValid, true);
      assert.equal(res.sanitized.assignedToId, null);
    });

    it('rejects empty update object', () => {
      const res = validateUpdateIncidentPayload({});
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('No update fields provided'));
    });

    it('rejects unsupported fields in update body', () => {
      const res = validateUpdateIncidentPayload({
        title: 'New Title',
        resolvedAt: '2026-01-01',
      });
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('Unsupported or unmodifiable'));
    });
  });

  describe('validateLinkAlertsPayload', () => {
    it('accepts alertIds array', () => {
      const uuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
      const res = validateLinkAlertsPayload({ alertIds: [uuid] });
      assert.equal(res.isValid, true);
      assert.deepEqual(res.alertIds, [uuid]);
    });

    it('accepts single alertId string', () => {
      const uuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
      const res = validateLinkAlertsPayload({ alertId: uuid });
      assert.equal(res.isValid, true);
      assert.deepEqual(res.alertIds, [uuid]);
    });

    it('rejects invalid or empty alertIds', () => {
      assert.equal(validateLinkAlertsPayload({ alertIds: [] }).isValid, false);
      assert.equal(validateLinkAlertsPayload({ alertIds: ['bad'] }).isValid, false);
      assert.equal(validateLinkAlertsPayload({}).isValid, false);
    });
  });

  describe('validateAddNotePayload', () => {
    it('accepts valid note', () => {
      const res = validateAddNotePayload({ note: 'Analyst reviewed firewall drop rules.' });
      assert.equal(res.isValid, true);
      assert.equal(res.note, 'Analyst reviewed firewall drop rules.');
    });

    it('rejects empty or whitespace note', () => {
      assert.equal(validateAddNotePayload({ note: '' }).isValid, false);
      assert.equal(validateAddNotePayload({ note: '   ' }).isValid, false);
      assert.equal(validateAddNotePayload({}).isValid, false);
    });

    it('rejects notes exceeding 2000 characters', () => {
      const res = validateAddNotePayload({ note: 'x'.repeat(2001) });
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('2000 characters'));
    });
  });
});
