// backend/src/modules/threat-intelligence/providers/mock.adapter.js
// Mock threat intelligence provider for deterministic testing and local offline demos.

import { BaseThreatProvider } from './base.adapter.js';

export class MockThreatProvider extends BaseThreatProvider {
  constructor() {
    super('MOCK_THREAT_INTEL', ['IP', 'DOMAIN', 'HASH', 'URL'], 'MOCK_API_KEY');
  }

  isConfigured() {
    return true; // Always available for testing and offline development
  }

  async lookup(type, value) {
    const lower = value.toLowerCase();

    // Deterministic verdicts based on string indicators for testing
    let verdict = 'BENIGN';
    let detectionCount = 0;
    let score = 5;

    if (lower.includes('malicious') || lower.includes('evil') || lower.includes('cobalt') || lower === '198.51.100.23') {
      verdict = 'MALICIOUS';
      detectionCount = 42;
      score = 95;
    } else if (lower.includes('scanner') || lower.includes('suspicious') || lower === '203.0.113.88') {
      verdict = 'SUSPICIOUS';
      detectionCount = 12;
      score = 65;
    } else if (lower.includes('rate-limit')) {
      return {
        status: 'RATE_LIMITED',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: 'Mock provider rate limit simulated',
      };
    } else if (lower.includes('error') || lower.includes('timeout')) {
      return {
        status: 'ERROR',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: 'Mock provider simulated network failure',
      };
    }

    return {
      status: 'SUCCESS',
      verdict,
      score,
      detectionCount,
      totalEngines: 70,
      rawSummary: {
        provider: 'Mock Threat Intelligence Lab',
        simulated: true,
        checkedValue: value,
        checkedType: type,
        timestamp: new Date().toISOString(),
      },
      errorMessage: null,
    };
  }
}
