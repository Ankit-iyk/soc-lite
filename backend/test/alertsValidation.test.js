// test/alertsValidation.test.js
// Unit tests for Alert Management validation logic (Phase 5 Step 1).
// Uses Node 22 native test runner (node:test).

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidUuid,
  validateAlertId,
  validateAlertQueryParams,
  validateUpdateStatusPayload,
  VALID_ALERT_STATUSES,
  VALID_SEVERITIES,
} from '../src/modules/alerts/alerts.validation.js';

describe('Phase 5 Step 1 — Alert Validation Unit Tests', () => {
  describe('isValidUuid and validateAlertId', () => {
    it('accepts valid UUID strings', () => {
      const valid = 'a1b2c3d4-e5f6-4a1b-8c2d-e3f4a5b6c7d8';
      assert.equal(isValidUuid(valid), true);
      const res = validateAlertId(valid);
      assert.equal(res.isValid, true);
      assert.equal(res.error, undefined);
    });

    it('rejects malformed UUID strings', () => {
      const invalidCases = [
        '',
        'not-a-uuid',
        '12345',
        'a1b2c3d4-e5f6-7a1b-8c2d',
        null,
        undefined,
        123,
        {},
      ];
      for (const val of invalidCases) {
        assert.equal(isValidUuid(val), false);
        const res = validateAlertId(val);
        assert.equal(res.isValid, false);
        assert.ok(res.error.includes('UUID'));
      }
    });
  });

  describe('validateAlertQueryParams', () => {
    it('provides sensible defaults when query is empty', () => {
      const { isValid, sanitized } = validateAlertQueryParams({});
      assert.equal(isValid, true);
      assert.equal(sanitized.page, 1);
      assert.equal(sanitized.limit, 20);
    });

    it('validates and sanitizes valid pagination', () => {
      const { isValid, sanitized } = validateAlertQueryParams({ page: '3', limit: '50' });
      assert.equal(isValid, true);
      assert.equal(sanitized.page, 3);
      assert.equal(sanitized.limit, 50);
    });

    it('rejects invalid page values', () => {
      const invalidPages = ['0', '-1', 'abc', '1.5'];
      for (const p of invalidPages) {
        const { isValid, error } = validateAlertQueryParams({ page: p });
        assert.equal(isValid, false);
        assert.ok(error.includes('page'));
      }
    });

    it('rejects invalid limit values', () => {
      const invalidLimits = ['0', '-5', '101', 'xyz', '20.5'];
      for (const l of invalidLimits) {
        const { isValid, error } = validateAlertQueryParams({ limit: l });
        assert.equal(isValid, false);
        assert.ok(error.includes('limit'));
      }
    });

    it('accepts all valid alert statuses case-insensitively', () => {
      for (const status of VALID_ALERT_STATUSES) {
        const { isValid, sanitized } = validateAlertQueryParams({ status: status.toLowerCase() });
        assert.equal(isValid, true);
        assert.equal(sanitized.status, status);
      }
    });

    it('rejects invalid status filter', () => {
      const { isValid, error } = validateAlertQueryParams({ status: 'RESOLVED' });
      assert.equal(isValid, false);
      assert.ok(error.includes('Invalid status filter'));
    });

    it('accepts all valid severities case-insensitively', () => {
      for (const sev of VALID_SEVERITIES) {
        const { isValid, sanitized } = validateAlertQueryParams({ severity: sev.toLowerCase() });
        assert.equal(isValid, true);
        assert.equal(sanitized.severity, sev);
      }
    });

    it('rejects invalid severity filter', () => {
      const { isValid, error } = validateAlertQueryParams({ severity: 'URGENT' });
      assert.equal(isValid, false);
      assert.ok(error.includes('Invalid severity filter'));
    });

    it('validates ruleId as UUID', () => {
      const validRuleId = '11111111-2222-3333-4444-555555555555';
      const resValid = validateAlertQueryParams({ ruleId: validRuleId });
      assert.equal(resValid.isValid, true);
      assert.equal(resValid.sanitized.ruleId, validRuleId);

      const resInvalid = validateAlertQueryParams({ ruleId: 'not-a-uuid' });
      assert.equal(resInvalid.isValid, false);
      assert.ok(resInvalid.error.includes('ruleId'));
    });

    it('enforces maximum length on search query', () => {
      const validSearch = 'Brute Force attempt';
      const resValid = validateAlertQueryParams({ search: validSearch });
      assert.equal(resValid.isValid, true);
      assert.equal(resValid.sanitized.search, validSearch);

      const tooLong = 'a'.repeat(201);
      const resInvalid = validateAlertQueryParams({ search: tooLong });
      assert.equal(resInvalid.isValid, false);
      assert.ok(resInvalid.error.includes('200 characters'));
    });

    it('validates date ranges correctly', () => {
      const startDate = '2026-01-01T00:00:00.000Z';
      const endDate = '2026-01-02T00:00:00.000Z';
      const resValid = validateAlertQueryParams({ startDate, endDate });
      assert.equal(resValid.isValid, true);
      assert.ok(resValid.sanitized.startDate instanceof Date);
      assert.ok(resValid.sanitized.endDate instanceof Date);

      const resInvalidOrder = validateAlertQueryParams({ startDate: endDate, endDate: startDate });
      assert.equal(resInvalidOrder.isValid, false);
      assert.ok(resInvalidOrder.error.includes('startDate'));

      const resBadDate = validateAlertQueryParams({ startDate: 'not-a-date' });
      assert.equal(resBadDate.isValid, false);
      assert.ok(resBadDate.error.includes('valid parseable date'));
    });
  });

  describe('validateUpdateStatusPayload', () => {
    it('accepts valid ACKNOWLEDGED status', () => {
      const res = validateUpdateStatusPayload({ status: 'ACKNOWLEDGED' });
      assert.equal(res.isValid, true);
      assert.equal(res.status, 'ACKNOWLEDGED');
    });

    it('accepts valid CLOSED status', () => {
      const res = validateUpdateStatusPayload({ status: 'closed' });
      assert.equal(res.isValid, true);
      assert.equal(res.status, 'CLOSED');
    });

    it('rejects OPEN status transition', () => {
      const res = validateUpdateStatusPayload({ status: 'OPEN' });
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('Allowed target statuses'));
    });

    it('rejects arbitrary or unsupported statuses', () => {
      const res = validateUpdateStatusPayload({ status: 'RESOLVED' });
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('Invalid status transition'));
    });

    it('rejects non-object or empty bodies', () => {
      assert.equal(validateUpdateStatusPayload(null).isValid, false);
      assert.equal(validateUpdateStatusPayload([]).isValid, false);
      assert.equal(validateUpdateStatusPayload({}).isValid, false);
    });

    it('rejects forbidden or spoofed fields in request body', () => {
      const res = validateUpdateStatusPayload({
        status: 'ACKNOWLEDGED',
        userId: 'attacker-id',
        acknowledgedBy: 'spoofed-user',
        acknowledgedAt: '2020-01-01',
      });
      assert.equal(res.isValid, false);
      assert.ok(res.error.includes('Unsupported or unmodifiable field(s)'));
    });
  });
});
