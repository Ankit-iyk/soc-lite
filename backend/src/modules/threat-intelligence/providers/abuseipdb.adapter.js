// backend/src/modules/threat-intelligence/providers/abuseipdb.adapter.js
// Adapter for AbuseIPDB Threat Intelligence API (v2).
// Official docs: https://docs.abuseipdb.com/#check-endpoint

import { BaseThreatProvider } from './base.adapter.js';

export class AbuseIpDbAdapter extends BaseThreatProvider {
  constructor(timeoutMs = 5000) {
    super('ABUSEIPDB', ['IP'], 'ABUSEIPDB_API_KEY', timeoutMs);
  }

  async lookup(type, value) {
    if (!this.supports(type)) {
      return {
        status: 'ERROR',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: `AbuseIPDB only supports IP addresses (received "${type}")`,
      };
    }

    if (!this.isConfigured()) {
      return this.getNotConfiguredResult();
    }

    const apiKey = process.env[this.envKeyName].trim();
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose=true`;

    try {
      const res = await this.fetchWithTimeout(url, {
        method: 'GET',
        headers: {
          Key: apiKey,
          Accept: 'application/json',
          'User-Agent': 'SOC-Lite-ThreatIntel/1.0',
        },
      });

      if (res.status === 429) {
        return {
          status: 'RATE_LIMITED',
          verdict: null,
          score: null,
          detectionCount: null,
          totalEngines: null,
          rawSummary: null,
          errorMessage: 'AbuseIPDB request rate limit exceeded. Please wait before retrying.',
        };
      }

      if (res.status === 401 || res.status === 403) {
        return {
          status: 'ERROR',
          verdict: null,
          score: null,
          detectionCount: null,
          totalEngines: null,
          rawSummary: null,
          errorMessage: 'AbuseIPDB authentication failed. Invalid API key.',
        };
      }

      if (res.status === 404) {
        return {
          status: 'NOT_FOUND',
          verdict: 'UNKNOWN',
          score: 0,
          detectionCount: 0,
          totalEngines: null,
          rawSummary: null,
          errorMessage: 'IP address not found in AbuseIPDB database.',
        };
      }

      if (!res.ok) {
        return {
          status: 'ERROR',
          verdict: null,
          score: null,
          detectionCount: null,
          totalEngines: null,
          rawSummary: null,
          errorMessage: `AbuseIPDB returned HTTP ${res.status}: ${res.statusText}`,
        };
      }

      const body = await res.json();
      return this.normalizeResponse(body);
    } catch (err) {
      const isTimeout = err.name === 'AbortError' || err.code === 20;
      return {
        status: 'ERROR',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: isTimeout ? 'AbuseIPDB request timed out' : `AbuseIPDB network error: ${err.message}`,
      };
    }
  }

  /**
   * Normalizes standard AbuseIPDB API v2 response payload.
   */
  normalizeResponse(body) {
    const data = body?.data;
    if (!data || typeof data !== 'object') {
      return {
        status: 'ERROR',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: 'Invalid response format received from AbuseIPDB',
      };
    }

    const confidenceScore = Number(data.abuseConfidenceScore ?? 0);
    const totalReports = Number(data.totalReports ?? 0);

    let verdict = 'UNKNOWN';
    if (confidenceScore >= 50) {
      verdict = 'MALICIOUS';
    } else if (confidenceScore > 15 || totalReports > 5) {
      verdict = 'SUSPICIOUS';
    } else if (confidenceScore <= 15 && totalReports === 0) {
      verdict = 'BENIGN';
    }

    const rawSummary = {
      ipAddress: data.ipAddress,
      isPublic: data.isPublic,
      ipVersion: data.ipVersion,
      isWhitelisted: data.isWhitelisted,
      abuseConfidenceScore: confidenceScore,
      countryCode: data.countryCode,
      countryName: data.countryName,
      usageType: data.usageType,
      isp: data.isp,
      domain: data.domain,
      totalReports,
      numDistinctUsers: data.numDistinctUsers,
      lastReportedAt: data.lastReportedAt,
    };

    return {
      status: 'SUCCESS',
      verdict,
      score: confidenceScore,
      detectionCount: totalReports,
      totalEngines: null,
      rawSummary,
      errorMessage: null,
    };
  }
}
