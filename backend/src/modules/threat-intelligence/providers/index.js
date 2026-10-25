// backend/src/modules/threat-intelligence/providers/index.js
// Registry and dispatcher for Threat Intelligence provider adapters.

import { AbuseIpDbAdapter } from './abuseipdb.adapter.js';
import { VirusTotalAdapter } from './virustotal.adapter.js';
import { AlienVaultOtxAdapter } from './otx.adapter.js';
import { MockThreatProvider } from './mock.adapter.js';

export const PROVIDERS = {
  ABUSEIPDB: new AbuseIpDbAdapter(),
  VIRUSTOTAL: new VirusTotalAdapter(),
  ALIENVAULT_OTX: new AlienVaultOtxAdapter(),
  MOCK_THREAT_INTEL: new MockThreatProvider(),
};

/**
 * Returns summary list of all registered providers and their configuration status.
 */
export function getAvailableProviders() {
  return Object.values(PROVIDERS).map((p) => ({
    name: p.name,
    supportedTypes: p.supportedTypes,
    envKeyName: p.envKeyName,
    configured: p.isConfigured(),
  }));
}

/**
 * Gets a specific provider by name (case-insensitive).
 */
export function getProvider(name) {
  if (!name || typeof name !== 'string') return null;
  const upper = name.trim().toUpperCase();
  return PROVIDERS[upper] || null;
}

/**
 * Finds the most appropriate provider for an indicator type.
 * Priority order:
 * 1. Explicitly requested provider (if it supports type)
 * 2. Any real configured provider supporting the type (AbuseIPDB for IP, VirusTotal, OTX)
 * 3. In test/development mode: MockThreatProvider
 * 4. Fallback to VirusTotal or AbuseIPDB to return appropriate NOT_CONFIGURED state.
 */
export function resolveProviderForLookup(type, requestedProviderName = null) {
  // If user requested a specific provider
  if (requestedProviderName) {
    const p = getProvider(requestedProviderName);
    if (p) return p;
  }

  // If in test environment or mock explicitly enabled, use Mock provider
  if (process.env.NODE_ENV === 'test' || process.env.THREAT_INTEL_USE_MOCK === 'true') {
    return PROVIDERS.MOCK_THREAT_INTEL;
  }

  // Look for configured real providers in priority order
  if (type === 'IP' && PROVIDERS.ABUSEIPDB.isConfigured()) {
    return PROVIDERS.ABUSEIPDB;
  }
  if (PROVIDERS.VIRUSTOTAL.isConfigured() && PROVIDERS.VIRUSTOTAL.supports(type)) {
    return PROVIDERS.VIRUSTOTAL;
  }
  if (PROVIDERS.ALIENVAULT_OTX.isConfigured() && PROVIDERS.ALIENVAULT_OTX.supports(type)) {
    return PROVIDERS.ALIENVAULT_OTX;
  }

  // If none configured, return standard provider so it reports honest NOT_CONFIGURED
  if (type === 'IP') return PROVIDERS.ABUSEIPDB;
  return PROVIDERS.VIRUSTOTAL;
}
