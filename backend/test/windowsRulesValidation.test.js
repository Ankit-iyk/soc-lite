import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateRuleConfig } from '../src/modules/rules/rules.validation.js';

describe('WINDOWS_FAILED_LOGON configuration', () => {
  it('accepts a bounded threshold and time window', () => {
    assert.equal(
      validateRuleConfig('WINDOWS_FAILED_LOGON', { threshold: 5 }, { threshold: 5, windowSeconds: 300 }),
      null
    );
  });

  it('rejects thresholds below two attempts', () => {
    assert.match(
      validateRuleConfig('WINDOWS_FAILED_LOGON', { threshold: 1 }, { threshold: 1, windowSeconds: 300 }),
      /threshold must be an integer between 2 and 1000/
    );
  });

  it('rejects unsupported event-type overrides', () => {
    assert.match(
      validateRuleConfig('WINDOWS_FAILED_LOGON', { eventType: 'ssh_login_failed' }, { threshold: 5, windowSeconds: 300 }),
      /Unsupported config key/
    );
  });
});