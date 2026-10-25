// backend/src/modules/threat-intelligence/providers/virustotal.adapter.js
// Adapter for VirusTotal Threat Intelligence API (v3).
// Official docs: https://docs.virustotal.com/reference/overview

import { BaseThreatProvider } from './base.adapter.js';

export class VirusTotalAdapter extends BaseThreatProvider {
  constructor(timeoutMs = 6000) {
    super('VIRUSTOTAL', ['IP', 'DOMAIN', 'HASH', 'URL'], 'VIRUSTOTAL_API_KEY', timeoutMs);
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
        errorMessage: `VirusTotal adapter does not support type "${type}"`,
      };
    }

    if (!this.isConfigured()) {
      return this.getNotConfiguredResult();
    }

    const apiKey = process.env[this.envKeyName].trim();
    let endpoint;

    switch (type) {
      case 'IP':
        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
        break;
      case 'DOMAIN':
        endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
        break;
      case 'HASH':
        endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`;
        break;
      case 'URL': {
        const urlId = Buffer.from(value).toString('base64url');
        endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        break;
      }
      default:
        endpoint = null;
    }

    if (!endpoint) {
      return {
        status: 'ERROR',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: `Unable to construct VirusTotal endpoint for type ${type}`,
      };
    }

    try {
      const res = await this.fetchWithTimeout(endpoint, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey,
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
          errorMessage: 'VirusTotal API rate limit exceeded (standard public API limit is 4 lookups/min).',
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
          errorMessage: 'VirusTotal authentication failed. Please verify VIRUSTOTAL_API_KEY.',
        };
      }

      if (res.status === 404) {
        return {
          status: 'NOT_FOUND',
          verdict: 'UNKNOWN',
          score: null,
          detectionCount: 0,
          totalEngines: null,
          rawSummary: null,
          errorMessage: 'Indicator not found in VirusTotal database.',
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
          errorMessage: `VirusTotal returned HTTP ${res.status}: ${res.statusText}`,
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
        errorMessage: isTimeout ? 'VirusTotal request timed out' : `VirusTotal network error: ${err.message}`,
      };
    }
  }

  /**
   * Normalizes standard VirusTotal API v3 response payload.
   */
  normalizeResponse(body) {
    const data = body?.data;
    const attributes = data?.attributes;
    if (!attributes || typeof attributes !== 'object') {
      return {
        status: 'ERROR',
        verdict: null,
        score: null,
        detectionCount: null,
        totalEngines: null,
        rawSummary: null,
        errorMessage: 'Invalid response format received from VirusTotal',
      };
    }

    const stats = attributes.last_analysis_stats || {};
    const malicious = Number(stats.malicious ?? 0);
    const suspicious = Number(stats.suspicious ?? 0);
    const harmless = Number(stats.harmless ?? 0);
    const undetected = Number(stats.undetected ?? 0);
    const totalEngines = malicious + suspicious + harmless + undetected;

    let verdict = 'UNKNOWN';
    if (malicious >= 3) {
      verdict = 'MALICIOUS';
    } else if (malicious >= 1 || suspicious >= 2) {
      verdict = 'SUSPICIOUS';
    } else if (malicious === 0 && (harmless > 0 || undetected > 0)) {
      verdict = 'BENIGN';
    }

    const score = totalEngines > 0 ? Math.round((malicious / totalEngines) * 100) : 0;

    const rawSummary = {
      reputation: attributes.reputation,
      lastAnalysisDate: attributes.last_analysis_date ? new Date(attributes.last_analysis_date * 1000).toISOString() : null,
      stats: {
        malicious,
        suspicious,
        harmless,
        undetected,
      },
      categories: attributes.categories,
      tags: attributes.tags,
      network: attributes.network,
      asOwner: attributes.as_owner,
      country: attributes.country,
    };

    return {
      status: 'SUCCESS',
      verdict,
      score,
      detectionCount: malicious,
      totalEngines,
      rawSummary,
      errorMessage: null,
    };
  }
}
