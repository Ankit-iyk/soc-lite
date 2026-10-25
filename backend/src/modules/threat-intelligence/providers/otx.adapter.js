// backend/src/modules/threat-intelligence/providers/otx.adapter.js
// Adapter for AlienVault Open Threat Exchange (OTX) API (v1).
// Official docs: https://otx.alienvault.com/api

import { BaseThreatProvider } from './base.adapter.js';

export class AlienVaultOtxAdapter extends BaseThreatProvider {
  constructor(timeoutMs = 5000) {
    super('ALIENVAULT_OTX', ['IP', 'DOMAIN', 'HASH', 'URL'], 'OTX_API_KEY', timeoutMs);
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
        errorMessage: `AlienVault OTX does not support indicator type "${type}"`,
      };
    }

    if (!this.isConfigured()) {
      return this.getNotConfiguredResult();
    }

    const apiKey = process.env[this.envKeyName].trim();
    let section;

    switch (type) {
      case 'IP':
        section = value.includes(':') ? 'IPv6' : 'IPv4';
        break;
      case 'DOMAIN':
        section = 'domain';
        break;
      case 'HASH':
        section = 'file';
        break;
      case 'URL':
        section = 'url';
        break;
      default:
        section = null;
    }

    const url = `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(value)}/general`;

    try {
      const res = await this.fetchWithTimeout(url, {
        method: 'GET',
        headers: {
          'X-OTX-API-KEY': apiKey,
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
          errorMessage: 'AlienVault OTX rate limit exceeded.',
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
          errorMessage: 'AlienVault OTX authentication failed. Please verify OTX_API_KEY.',
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
          errorMessage: 'Indicator not found in AlienVault OTX.',
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
          errorMessage: `AlienVault OTX returned HTTP ${res.status}: ${res.statusText}`,
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
        errorMessage: isTimeout ? 'AlienVault OTX request timed out' : `AlienVault OTX network error: ${err.message}`,
      };
    }
  }

  /**
   * Normalizes standard AlienVault OTX general indicator response.
   */
  normalizeResponse(body) {
    if (!body || typeof body !== 'object') {
      return {
        status: 'ERROR',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: 'Invalid response format received from AlienVault OTX',
      };
    }

    const pulseCount = Number(body.pulse_info?.count ?? 0);
    const reputation = body.reputation !== undefined ? Number(body.reputation) : null;

    let verdict = 'UNKNOWN';
    if (pulseCount >= 3) {
      verdict = 'MALICIOUS';
    } else if (pulseCount > 0) {
      verdict = 'SUSPICIOUS';
    } else if (pulseCount === 0) {
      verdict = 'BENIGN';
    }

    const rawSummary = {
      indicator: body.indicator,
      pulseCount,
      reputation,
      countryName: body.country_name,
      asn: body.asn,
      city: body.city,
      validation: body.validation,
      references: body.pulse_info?.pulses?.slice(0, 5).map((p) => ({
        name: p.name,
        created: p.created,
        author: p.author_name,
      })) || [],
    };

    return {
      status: 'SUCCESS',
      verdict,
      score: pulseCount > 0 ? Math.min(100, pulseCount * 20) : 0,
      detectionCount: pulseCount,
      totalEngines: null,
      rawSummary,
      errorMessage: null,
    };
  }
}
